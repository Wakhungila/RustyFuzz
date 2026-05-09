use crate::common::types::{Waypoint, TaintSource};
use revm::primitives::U256;
use z3::ast::BV;
use z3::{Config, Context, Solver};

/// ConcolicSolver leverages Z3 to solve for input values that satisfy 
/// branching conditions encountered during execution.
pub struct ConcolicSolver<'a> {
    ctx: &'a Context,
}

impl<'a> ConcolicSolver<'a> {
    pub fn new(ctx: &'a Context) -> Self {
        Self { ctx }
    }

    /// Generates a "hint" (a 32-byte value) that would satisfy the alternative 
    /// path of a comparison.
    pub fn solve_hint(&self, waypoint: &Waypoint) -> Option<[u8; 32]> {
        match waypoint {
            Waypoint::Comparison { op, lhs, rhs, taint_source: Some(taint_source), .. } => {
                let solver = Solver::new(self.ctx);
                
                let input_var = self.create_symbolic_var(taint_source)?;
                let rhs_bv = self.u256_to_bv(rhs)?;

                let constraint = match *op {
                    0x10 => input_var.bvult(&rhs_bv), // LT
                    0x11 => input_var.bvugt(&rhs_bv), // GT
                    0x14 => input_var._eq(&rhs_bv),   // EQ
                    0x12 => input_var.bvslt(&rhs_bv), // SLT
                    0x13 => input_var.bvsgt(&rhs_bv), // SGT
                    _ => return None,
                };

                solver.assert(&constraint);
                if solver.check() == z3::SatResult::Sat {
                    let model = solver.get_model()?;
                    let solution = model.eval(&input_var, true)?;
                    return Some(self.bv_to_bytes(solution));
                }
            }
            Waypoint::Arithmetic { op, lhs, rhs, third, taint_source: Some(taint_source), .. } => {
                let solver = Solver::new(self.ctx);
                
                let input_var = self.create_symbolic_var(taint_source)?;
                let rhs_bv = self.u256_to_bv(rhs)?;
                let zero_bv = self.u256_to_bv(&U256::ZERO)?;
                let max_bv = self.u256_to_bv(&U256::MAX)?;

                // Full arithmetic constraint propagation:
                // We solve for potential edge cases (overflow, rounding, etc.)
                let constraint = match *op {
                    0x01 => { // ADD: Solve for overflow
                        input_var.bvadd(&rhs_bv).bvugt(&max_bv)
                    }
                    0x02 => { // MUL: Solve for overflow/wrap-around
                        input_var.bvmul(&rhs_bv).bvugt(&max_bv)
                    }
                    0x03 => { // SUB: Solve for underflow
                        input_var.bvult(&rhs_bv)
                    }
                    0x04 | 0x05 => { // DIV/SDIV: Rounding direction
                        // Find input s.t. the division is not exact (forces rounding)
                        input_var.bvurem(&rhs_bv)._ne(&zero_bv)
                    }
                    0x08 => { // ADDMOD
                        if let Some(n) = third {
                            let n_bv = self.u256_to_bv(n)?;
                            input_var.bvadd(&rhs_bv).bvurem(&n_bv)._eq(&zero_bv)
                        } else { return None; }
                    }
                    0x09 => { // MULMOD
                        if let Some(n) = third {
                            let n_bv = self.u256_to_bv(n)?;
                            input_var.bvmul(&rhs_bv).bvurem(&n_bv)._eq(&zero_bv)
                        } else { return None; }
                    }
                    _ => return None,
                };

                solver.assert(&constraint);
                if solver.check() == z3::SatResult::Sat {
                    let model = solver.get_model()?;
                    let solution = model.eval(&input_var, true)?;
                    return Some(self.bv_to_bytes(solution));
                }
            }
            _ => {}
        }
        None
    }

    fn create_symbolic_var(&self, taint_source: &TaintSource) -> Option<BV<'a>> {
        match taint_source {
            TaintSource::Calldata(offset) => {
                if *offset >= 1024 * 1024 { return None; } // Sanity check
                Some(BV::new_const(self.ctx, format!("calldata_at_{}", offset), 256))
            }
            TaintSource::Storage(tx_idx, original_calldata_offset) => {
                Some(BV::new_const(self.ctx, format!("calldata_tx{}_at_{}", tx_idx, original_calldata_offset), 256))
            }
        }
    }
    fn u256_to_bv(&self, val: &U256) -> Option<BV<'a>> {
        let bytes = val.to_be_bytes::<32>();
        let mut hex = String::from("0x");
        for b in bytes {
            hex.push_str(&format!("{:02x}", b));
        }
        BV::from_str(self.ctx, 256, &hex)
    }

    fn bv_to_bytes(&self, bv: BV<'a>) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let bit_string = format!("{:x}", bv); // Z3 returns hex
        let stripped = bit_string.trim_start_matches("0x");
        if let Ok(decoded) = hex::decode(format!("{:0>64}", stripped)) {
            if decoded.len() == 32 {
                bytes.copy_from_slice(&decoded);
            }
        }
        bytes
    }
}

/// Extends the EvmInput with hints generated by the Concolic engine.
pub struct ConcolicHint {
    pub offset: usize,
    pub value: [u8; 32],
}