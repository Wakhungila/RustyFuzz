use crate::engine::formal_spec::{FormalSpecification, PermissionModelSpec};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAnomaly {
    pub selector: String,
    pub kind: PermissionAnomalyKind,
    pub severity: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionAnomalyKind {
    OverPrivilegedRole,      // role can access too many functions
    MissingRoleCheck,        // function lacks required role check
    InconsistentPermissions, // some funcs check owner, others don't
    UnguardedAdminFunction,  // admin function without proper checks
    RoleCanSelfTransition,   // role can give itself more permissions
    MissingMutualExclusion,  // exclusive roles not enforced
}

#[derive(Debug, Clone, Default)]
pub struct PermissionModelAnalyzer {
    spec: Option<PermissionModelSpec>,
    inferred_permissions: HashMap<String, Vec<String>>, // selector -> required_roles
    inferred_role_functions: HashMap<String, Vec<String>>, // role -> functions
    anomalies: Vec<PermissionAnomaly>,
}

impl PermissionModelAnalyzer {
    pub fn new(spec: Option<&FormalSpecification>) -> Self {
        let perm_spec = spec.and_then(|s| s.permission_model.as_ref().cloned());

        let mut inferred_permissions = HashMap::new();
        let mut inferred_role_functions = HashMap::new();

        if let Some(ref ps) = perm_spec {
            for func_perm in &ps.function_permissions {
                inferred_permissions
                    .insert(func_perm.selector.clone(), func_perm.required_roles.clone());
            }
            for role in &ps.roles {
                inferred_role_functions.insert(role.name.clone(), role.allowed_functions.clone());
            }
        }

        Self {
            spec: perm_spec,
            inferred_permissions,
            inferred_role_functions,
            anomalies: Vec::new(),
        }
    }

    pub fn infer_permission_from_bytecode(
        &mut self,
        selector: &str,
        checks_owner: bool,
        checks_caller: bool,
        checks_msg_sender: bool,
    ) {
        // Heuristic: if function checks msg.sender against constant address, it's owner-only
        if checks_owner || checks_msg_sender {
            self.inferred_permissions
                .entry(selector.to_string())
                .or_insert_with(Vec::new)
                .push("Owner".to_string());
        }

        // If multiple functions check owner, mark inconsistent if not all do
        if checks_caller && !self.inferred_permissions.contains_key(selector) {
            self.inferred_permissions
                .insert(selector.to_string(), vec!["Caller".to_string()]);
        }
    }

    pub fn check_privilege_model(&mut self) -> Vec<PermissionAnomaly> {
        if self.spec.is_none() {
            return Vec::new();
        }

        let spec = self.spec.as_ref().unwrap();

        // Check 1: OverPrivilegedRole - role with too many functions
        for (role, functions) in &self.inferred_role_functions {
            if functions.len() > 15 {
                // Threshold: > 15 functions is suspicious
                self.anomalies.push(PermissionAnomaly {
                    selector: format!("role:{}", role),
                    kind: PermissionAnomalyKind::OverPrivilegedRole,
                    severity: "high".to_string(),
                    evidence: format!("{} role can access {} functions", role, functions.len()),
                });
            }
        }

        // Check 2: InconsistentPermissions - some functions require role, others don't
        let with_perms: HashSet<_> = self.inferred_permissions.keys().cloned().collect();
        let without_perms: HashSet<_> = self
            .inferred_role_functions
            .values()
            .flat_map(|f| f.iter().cloned())
            .filter(|f| !with_perms.contains(f))
            .collect();

        if !without_perms.is_empty() && !with_perms.is_empty() {
            let some_checked: Vec<_> = with_perms.iter().take(3).cloned().collect();
            let some_unchecked: Vec<_> = without_perms.iter().take(3).cloned().collect();
            self.anomalies.push(PermissionAnomaly {
                selector: "permission_model".to_string(),
                kind: PermissionAnomalyKind::InconsistentPermissions,
                severity: "medium".to_string(),
                evidence: format!(
                    "Checked: {:?}, Unchecked: {:?}",
                    some_checked, some_unchecked
                ),
            });
        }

        // Check 3: MissingRoleCheck - sensitive function without permission
        let sensitive_prefixes = ["upgrade", "pause", "unpause", "drain", "setFee", "setOwner"];
        for selector in self.inferred_role_functions.values().flat_map(|v| v.iter()) {
            if sensitive_prefixes
                .iter()
                .any(|prefix| selector.starts_with(prefix))
            {
                if !self.inferred_permissions.contains_key(selector) {
                    self.anomalies.push(PermissionAnomaly {
                        selector: selector.clone(),
                        kind: PermissionAnomalyKind::UnguardedAdminFunction,
                        severity: "critical".to_string(),
                        evidence: format!(
                            "Sensitive function '{}' has no permission checks",
                            selector
                        ),
                    });
                }
            }
        }

        // Check 4: MutualExclusion - exclusive roles not enforced
        for func_perm in &spec.function_permissions {
            if !func_perm.mutually_exclusive_roles.is_empty() {
                // Would need runtime execution to truly check,
                // but we can flag it as a design smell
                self.anomalies.push(PermissionAnomaly {
                    selector: func_perm.selector.clone(),
                    kind: PermissionAnomalyKind::MissingMutualExclusion,
                    severity: "medium".to_string(),
                    evidence: format!(
                        "Roles {:?} should be mutually exclusive",
                        func_perm.mutually_exclusive_roles
                    ),
                });
            }
        }

        self.anomalies.clone()
    }

    pub fn get_anomalies(&self) -> &[PermissionAnomaly] {
        &self.anomalies
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_analyzer_initializes() {
        let analyzer = PermissionModelAnalyzer::new(None);
        assert!(analyzer.get_anomalies().is_empty());
    }

    #[test]
    fn analyzer_tracks_inferred_permissions() {
        let mut analyzer = PermissionModelAnalyzer::new(None);
        analyzer.infer_permission_from_bytecode("deposit", false, false, true);

        let perms = &analyzer.inferred_permissions;
        assert!(perms.contains_key("deposit"));
    }
}
