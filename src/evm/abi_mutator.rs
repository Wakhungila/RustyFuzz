use alloy_dyn_abi::{DynSolType, DynSolValue, JsonAbiExt, DynamicParameters};
use alloy_json_abi::JsonAbi;
use alloy_primitives::{Address, U256, Bytes, FixedBytes};
use libafl_bolts::rands::Rand;
use libafl_bolts::rands::RomuDuoJrRand;
use std::sync::Arc;

/// ABI-aware mutator that understands Solidity function signatures and parameter types.
/// 
/// Unlike byte-level mutation, this mutator:
/// - Parses calldata according to the contract's ABI
/// - Mutates individual parameters based on their semantic types
/// - Generates boundary values appropriate for each type (uint max, address zero, etc.)
/// - Preserves valid ABI encoding to avoid immediate reverts
pub struct AbiAwareMutator {
    abi: Arc<JsonAbi>,
    target_function: Option<[u8; 4]>, // Optional: focus on specific function
}

impl AbiAwareMutator {
    pub fn new(abi: JsonAbi) -> Self {
        Self {
            abi: Arc::new(abi),
            target_function: None,
        }
    }
    
    /// Create a mutator focused on a specific function selector
    pub fn with_function(abi: JsonAbi, function_selector: [u8; 4]) -> Self {
        Self {
            abi: Arc::new(abi),
            target_function: Some(function_selector),
        }
    }
    
    /// Mutate calldata using ABI-aware strategies
    pub fn mutate_calldata(&self, call: &[u8], rand: &mut RomuDuoJrRand) -> Vec<u8> {
        if call.len() < 4 {
            // Not a valid function call, fall back to byte mutation
            return self.byte_mutate(call, rand);
        }
        
        let selector = [call[0], call[1], call[2], call[3]];
        
        // Find the function in the ABI
        let function = self.abi.functions().find(|f| f.selector() == selector);
        
        if let Some(func) = function {
            // Decode the calldata according to the function signature
            let params = func.inputs();
            
            if params.is_empty() {
                // No parameters, just return the selector
                return call.to_vec();
            }
            
            // Attempt to decode the remaining calldata
            let input_data = &call[4..];
            
            match self.decode_and_mutate(params, input_data, rand) {
                Some(mutated_params) => {
                    // Re-encode with mutated values
                    let mut result = selector.to_vec();
                    result.extend_from_slice(&mutated_params.abi_encode_params());
                    result
                }
                None => {
                    // Decoding failed, fall back to byte mutation
                    self.byte_mutate(call, rand)
                }
            }
        } else {
            // Unknown function selector, use byte mutation
            self.byte_mutate(call, rand)
        }
    }
    
    /// Decode parameters, mutate them, and re-encode
    fn decode_and_mutate(
        &self,
        params: &[alloy_json_abi::Param],
        input_data: &[u8],
        rand: &mut RomuDuoJrRand,
    ) -> Option<Vec<DynSolValue>> {
        // Convert ABI params to DynSolType
        let types: Vec<DynSolType> = params
            .iter()
            .map(|p| DynSolType::parse(&p.ty).ok()?)
            .collect();
        
        // Decode the input data
        let tuple_type = DynSolType::Tuple(types.clone());
        let decoded = tuple_type.abi_decode_sequence(input_data).ok()?;
        
        // Extract values from the tuple
        let mut values = if let DynSolValue::Tuple(vals) = decoded {
            vals
        } else {
            return None;
        };
        
        // Choose which parameter(s) to mutate
        if values.is_empty() {
            return Some(values);
        }
        
        let param_idx = (rand.next() as usize) % values.len();
        
        // Mutate the selected parameter based on its type
        values[param_idx] = self.mutate_value(&values[param_idx], &types[param_idx], rand);
        
        Some(values)
    }
    
    /// Mutate a value based on its type with semantic awareness
    fn mutate_value(&self, value: &DynSolValue, ty: &DynSolType, rand: &mut RomuDuoJrRand) -> DynSolValue {
        let mutation_strategy = rand.below(100);
        
        match (ty, value) {
            // Uint mutations: boundary values are critical
            (DynSolType::Uint(size), DynSolValue::Uint(current, _)) => {
                if mutation_strategy < 30 {
                    // Return a boundary value
                    self.generate_uint_boundary(*size, rand)
                } else if mutation_strategy < 70 {
                    // Bit flipping on current value
                    let bits: [u64; 4] = current.as_limbs();
                    let mut mutated_bits = bits;
                    let limb_idx = (rand.next() as usize) % 4;
                    let bit_idx = rand.next() % 64;
                    mutated_bits[limb_idx] ^= (1 << bit_idx);
                    DynSolValue::Uint(U256::from_limbs(mutated_bits), *size)
                } else {
                    // Small increment/decrement
                    let delta = U256::from(rand.below(100) + 1);
                    if rand.below(2) == 0 {
                        DynSolValue::Uint(current.saturating_add(delta), *size)
                    } else {
                        DynSolValue::Uint(current.saturating_sub(delta), *size)
                    }
                }
            }
            
            // Int mutations: watch for sign changes
            (DynSolType::Int(size), DynSolValue::Int(current, _)) => {
                if mutation_strategy < 30 {
                    self.generate_int_boundary(*size, rand)
                } else {
                    // Simple bit mutation
                    let bits: [u64; 4] = current.as_limbs();
                    let mut mutated_bits = bits;
                    let limb_idx = (rand.next() as usize) % 4;
                    mutated_bits[limb_idx] = rand.next();
                    DynSolValue::Int(I256::from_raw(U256::from_limbs(mutated_bits)), *size)
                }
            }
            
            // Address mutations: zero address, max address, known contracts
            (DynSolType::Address, DynSolValue::Address(current)) => {
                if mutation_strategy < 40 {
                    // Zero address (common vulnerability trigger)
                    DynSolValue::Address(Address::ZERO)
                } else if mutation_strategy < 60 {
                    // Max address
                    DynSolValue::Address(Address::repeat_byte(0xff))
                } else if mutation_strategy < 80 {
                    // Flip some bits
                    let mut bytes = current.0;
                    for i in 0..5 {
                        let idx = (rand.next() as usize) % 20;
                        bytes[idx] = rand.next() as u8;
                    }
                    DynSolValue::Address(Address::new(bytes))
                } else {
                    // Keep current (sometimes valid addresses are needed)
                    DynSolValue::Address(*current)
                }
            }
            
            // Bool mutations
            (DynSolType::Bool, DynSolValue::Bool(current)) => {
                // Mostly flip the boolean
                if mutation_strategy < 70 {
                    DynSolValue::Bool(!current)
                } else {
                    DynSolValue::Bool(*current)
                }
            }
            
            // Bytes mutations
            (DynSolType::Bytes, DynSolValue::Bytes(current)) => {
                if current.is_empty() {
                    // Generate some bytes
                    let len = (rand.next() % 256) as usize;
                    let mut new_bytes = vec![0u8; len];
                    for b in &mut new_bytes {
                        *b = rand.next() as u8;
                    }
                    DynSolValue::Bytes(Bytes::from(new_bytes))
                } else if mutation_strategy < 30 {
                    // Empty the bytes
                    DynSolValue::Bytes(Bytes::default())
                } else if mutation_strategy < 60 {
                    // Append boundary patterns
                    let mut new_bytes = current.to_vec();
                    new_bytes.extend_from_slice(&[0x00, 0xff, 0x00, 0xff]);
                    DynSolValue::Bytes(Bytes::from(new_bytes))
                } else {
                    // Byte flip
                    let mut new_bytes = current.to_vec();
                    if !new_bytes.is_empty() {
                        let idx = (rand.next() as usize) % new_bytes.len();
                        new_bytes[idx] = rand.next() as u8;
                    }
                    DynSolValue::Bytes(Bytes::from(new_bytes))
                }
            }
            
            // FixedBytes mutations
            (DynSolType::FixedBytes(size), DynSolValue::FixedBytes(current, _)) => {
                let mut bytes = current.as_slice().to_vec();
                if !bytes.is_empty() {
                    let idx = (rand.next() as usize) % bytes.len();
                    bytes[idx] = rand.next() as u8;
                }
                DynSolValue::FixedBytes(FixedBytes::<32>::from_slice(&bytes), *size)
            }
            
            // String mutations
            (DynSolType::String, DynSolValue::String(current)) => {
                if mutation_strategy < 30 {
                    // Empty string
                    DynSolValue::String(String::new())
                } else if mutation_strategy < 60 {
                    // Inject special characters (potential injection attacks)
                    let mut new_string = current.clone();
                    new_string.push_str("\x00\x01\x02");
                    DynSolValue::String(new_string)
                } else {
                    // Append random chars
                    let mut new_string = current.clone();
                    for _ in 0..10 {
                        new_string.push((rand.next() % 26) as u8 as char);
                    }
                    DynSolValue::String(new_string)
                }
            }
            
            // Array mutations
            (DynSolType::Array(inner_ty), DynSolValue::Array(items)) => {
                if items.is_empty() {
                    // Generate a small array
                    let len = (rand.next() % 5) as usize;
                    let mut new_items = Vec::with_capacity(len);
                    for _ in 0..len {
                        let default = self.default_value_for_type(inner_ty.as_ref(), rand);
                        new_items.push(default);
                    }
                    DynSolValue::Array(new_items)
                } else if mutation_strategy < 30 {
                    // Resize array
                    let new_len = (rand.next() % 10) as usize;
                    let mut new_items = items.clone();
                    new_items.resize_with(new_len, || {
                        self.default_value_for_type(inner_ty.as_ref(), rand)
                    });
                    DynSolValue::Array(new_items)
                } else {
                    // Mutate an element
                    let idx = (rand.next() as usize) % items.len();
                    let mut new_items = items.clone();
                    new_items[idx] = self.mutate_value(&items[idx], inner_ty.as_ref(), rand);
                    DynSolValue::Array(new_items)
                }
            }
            
            // Tuple mutations
            (DynSolType::Tuple(fields), DynSolValue::Tuple(items)) => {
                if items.is_empty() {
                    return DynSolValue::Tuple(vec![]);
                }
                
                // Mutate one field in the tuple
                let idx = (rand.next() as usize) % items.len();
                let mut new_items = items.clone();
                let field_ty = if idx < fields.len() {
                    &fields[idx]
                } else {
                    &fields[0]
                };
                new_items[idx] = self.mutate_value(&items[idx], field_ty, rand);
                DynSolValue::Tuple(new_items)
            }
            
            // Default: return unchanged or simple mutation
            _ => {
                if mutation_strategy < 50 {
                    self.default_value_for_type(ty, rand)
                } else {
                    value.clone()
                }
            }
        }
    }
    
    /// Generate boundary values for uint types
    fn generate_uint_boundary(&self, size: usize, rand: &mut RomuDuoJrRand) -> DynSolValue {
        let boundary_values = [
            U256::ZERO,
            U256::from(1),
            U256::from(2),
            U256::from(127),
            U256::from(128),
            U256::from(255),
            U256::from(256),
            U256::MAX >> (256 - size),
            (U256::MAX >> (256 - size)) - U256::from(1),
            (U256::MAX >> (256 - size)) + U256::from(1),
        ];
        
        let val = boundary_values[(rand.next() as usize) % boundary_values.len()];
        DynSolValue::Uint(val, size)
    }
    
    /// Generate boundary values for int types
    fn generate_int_boundary(&self, size: usize, rand: &mut RomuDuoJrRand) -> DynSolValue {
        let min_val = I256::MIN >> (256 - size);
        let max_val = I256::MAX >> (256 - size);
        
        let boundary_values = [
            I256::ZERO,
            I256::from(-1),
            I256::from(1),
            min_val,
            min_val + I256::from(1),
            max_val,
            max_val - I256::from(1),
        ];
        
        let val = boundary_values[(rand.next() as usize) % boundary_values.len()];
        DynSolValue::Int(val, size)
    }
    
    /// Generate a default value for a given type
    fn default_value_for_type(&self, ty: &DynSolType, rand: &mut RomuDuoJrRand) -> DynSolValue {
        match ty {
            DynSolType::Uint(size) => DynSolValue::Uint(U256::ZERO, *size),
            DynSolType::Int(size) => DynSolValue::Int(I256::ZERO, *size),
            DynSolType::Bool => DynSolValue::Bool(false),
            DynSolType::Address => DynSolValue::Address(Address::ZERO),
            DynSolType::Bytes => DynSolValue::Bytes(Bytes::default()),
            DynSolType::String => DynSolValue::String(String::new()),
            DynSolType::Array(inner) => {
                let len = (rand.next() % 3) as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.default_value_for_type(inner.as_ref(), rand));
                }
                DynSolValue::Array(items)
            }
            DynSolType::Tuple(fields) => {
                let mut items = Vec::with_capacity(fields.len());
                for field in fields {
                    items.push(self.default_value_for_type(field, rand));
                }
                DynSolValue::Tuple(items)
            }
            DynSolType::FixedBytes(size) => {
                DynSolValue::FixedBytes(FixedBytes::<32>::default(), *size)
            }
            _ => DynSolValue::Uint(U256::ZERO, 256),
        }
    }
    
    /// Fallback byte-level mutation when ABI decoding fails
    fn byte_mutate(&self, call: &[u8], rand: &mut RomuDuoJrRand) -> Vec<u8> {
        let mut result = call.to_vec();
        
        if result.is_empty() {
            result.push(rand.next() as u8);
            return result;
        }
        
        let mutation_type = rand.below(100);
        
        match mutation_type {
            0..=60 => {
                // Flip a byte
                let idx = (rand.next() as usize) % result.len();
                result[idx] = rand.next() as u8;
            }
            61..=80 => {
                // Insert a byte
                let idx = (rand.next() as usize) % (result.len() + 1);
                result.insert(idx, rand.next() as u8);
            }
            81..=95 => {
                // Remove a byte
                if result.len() > 1 {
                    let idx = (rand.next() as usize) % result.len();
                    result.remove(idx);
                }
            }
            _ => {
                // Duplicate a byte
                let idx = (rand.next() as usize) % result.len();
                let val = result[idx];
                result.insert(idx + 1, val);
            }
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_abi::Function;
    
    #[test]
    fn test_uint_boundary_generation() {
        let abi = JsonAbi::default();
        let mutator = AbiAwareMutator::new(abi);
        let mut rand = RomuDuoJrRand::with_seed(42);
        
        // Should generate various boundary values
        for _ in 0..10 {
            let val = mutator.generate_uint_boundary(256, &mut rand);
            assert!(matches!(val, DynSolValue::Uint(_, 256)));
        }
    }
}
