#[cfg(feature = "z3")]
use crate::common::types::{TaintSource, Waypoint};
#[cfg(feature = "z3")]
use revm::primitives::U256;
#[cfg(feature = "z3")]
use z3::ast::{Ast, BV};
#[cfg(feature = "z3")]
use z3::{Context, SatResult, Solver};

#[cfg(feature = "z3")]
pub struct ConcolicSolver<'a> {
    ctx: &'a Context,
}

#[cfg(feature = "z3")]
impl<'a> ConcolicSolver<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        Self { ctx }
    }

    /// Generates a "hint" (a 32-byte value) that satisfies the alternative
    /// path of a comparison or an arithmetic edge case.
    pub fn solve_hint(&self, waypoint: &Waypoint) -> Option<[u8; 32]> {
        match waypoint {
            Waypoint::Comparison {
                op,
                lhs: _,
                rhs,
                taint_source: Some(taint_source),
                ..
            } => {
                let solver = Solver::new(self.ctx);
                let input_var = self.create_symbolic_var(taint_source)?;
                let rhs_bv = self.u256_to_bv(rhs)?;

                // EVM Opcode Mapping to Z3 BitVector operations
                let constraint = match *op {
                    0x10 => input_var.bvult(&rhs_bv), // LT
                    0x11 => input_var.bvugt(&rhs_bv), // GT
                    0x14 => input_var._eq(&rhs_bv),   // EQ
                    0x12 => input_var.bvslt(&rhs_bv), // SLT
                    0x13 => input_var.bvsgt(&rhs_bv), // SGT
                    _ => return None,
                };

                solver.assert(&constraint);
                self.get_solution(solver, input_var)
            }

            Waypoint::Arithmetic {
                op,
                lhs: _,
                rhs,
                third,
                taint_source: Some(taint_source),
                ..
            } => {
                let solver = Solver::new(self.ctx);
                let input_var = self.create_symbolic_var(taint_source)?;
                let rhs_bv = self.u256_to_bv(rhs)?;
                let zero_bv = self.u256_to_bv(&U256::ZERO)?;
                let max_bv = self.u256_to_bv(&U256::MAX)?;

                let constraint = match *op {
                    0x01 => input_var.bvadd(&rhs_bv).bvugt(&max_bv), // ADD: Overflow
                    0x02 => input_var.bvmul(&rhs_bv).bvugt(&max_bv), // MUL: Overflow
                    0x03 => input_var.bvult(&rhs_bv),                // SUB: Underflow
                    0x04 | 0x05 => input_var.bvurem(&rhs_bv)._ne(&zero_bv), // DIV: Force rounding
                    0x08 | 0x09 => {
                        // ADDMOD / MULMOD
                        if let Some(n) = third {
                            let n_bv = self.u256_to_bv(n)?;
                            let res = if *op == 0x08 {
                                input_var.bvadd(&rhs_bv)
                            } else {
                                input_var.bvmul(&rhs_bv)
                            };
                            res.bvurem(&n_bv)._eq(&zero_bv)
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                };

                solver.assert(&constraint);
                self.get_solution(solver, input_var)
            }
            _ => None,
        }
    }

    fn create_symbolic_var(&self, taint_source: &TaintSource) -> Option<BV<'a>> {
        match taint_source {
            TaintSource::Calldata(offset) => {
                if *offset >= 1024 * 1024 {
                    return None;
                }
                Some(BV::new_const(self.ctx, format!("calldata_{}", offset), 256))
            }
            TaintSource::Storage(tx_idx, offset) => Some(BV::new_const(
                self.ctx,
                format!("tx{}_storage_at_{}", tx_idx, offset),
                256,
            )),
        }
    }

    fn u256_to_bv(&self, val: &U256) -> Option<BV<'a>> {
        let hex_str = format!("0x{:x}", val);
        BV::from_str(self.ctx, 256, &hex_str)
    }

    fn get_solution(&self, solver: Solver<'a>, var: BV<'a>) -> Option<[u8; 32]> {
        if solver.check() == SatResult::Sat {
            let model = solver.get_model()?;
            let solution = model.eval(&var, true)?;

            // Format to 64-char hex string (32 bytes)
            let bit_string = format!("{:x}", solution);
            let stripped = bit_string.trim_start_matches("0x");
            let mut decoded = hex::decode(format!("{:0>64}", stripped)).ok()?;

            if decoded.len() == 32 {
                let mut res = [0u8; 32];
                res.copy_from_slice(&decoded);
                return Some(res);
            }
        }
        None
    }
}
