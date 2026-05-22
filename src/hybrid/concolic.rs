use crate::common::types::Waypoint;
use crate::engine::concolic::ConcolicSolver;

pub fn generate_hints(waypoints: &[Waypoint]) -> Vec<Vec<u8>> {
    ConcolicSolver::new()
        .solve_hints(waypoints.iter().map(|waypoint| (0, waypoint)))
        .into_iter()
        .map(|hint| hint.word.to_vec())
        .collect()
}
