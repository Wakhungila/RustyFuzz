use revm::{
    interpreter::Interpreter,
    Database, Inspector, EvmContext,
};
use bitvec::prelude::*;

pub struct CoverageInspector<'a> {
    pub coverage: &'a mut BitSlice<u8, Lsb0>,
}

impl<'a> CoverageInspector<'a> {
    pub fn new(coverage: &'a mut BitSlice<u8, Lsb0>) -> Self {
        Self { coverage }
    }
}

impl<'a, DB: Database> Inspector<DB> for CoverageInspector<'a> {
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<'_, DB>) {
        let pc = interp.program_counter;
        let opcode = interp.current_opcode;
        
        // Calculate a hash of PC and Opcode
        let hash = (pc ^ (opcode as usize)) % self.coverage.len();
        self.coverage.set(hash, true);
    }
}