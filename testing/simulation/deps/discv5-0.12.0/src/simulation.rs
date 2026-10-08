//! Virtual-process state for the production discovery implementation.

use crate::{PermitBanList, metrics::InternalMetrics};
use madsim::{
    Config,
    plugin::{self, Simulator},
    rand::GlobalRng,
    task::NodeId,
    time::TimeHandle,
};
use parking_lot::{Mutex, RwLock};
use std::{collections::HashMap, sync::Arc};

#[derive(Default)]
struct NodeState {
    permit_ban: Arc<RwLock<PermitBanList>>,
    metrics: Arc<InternalMetrics>,
}

/// Register with `Runtime::add_simulator` before creating discovery nodes.
/// Native discv5 assumes one process per node; this gives each virtual process
/// its own globals and discards them when that process restarts.
#[derive(Default)]
pub struct SimulationState {
    nodes: Mutex<HashMap<NodeId, NodeState>>,
}

impl Simulator for SimulationState {
    fn new(_: &GlobalRng, _: &TimeHandle, _: &Config) -> Self {
        Self::default()
    }

    fn create_node(&self, id: NodeId) {
        self.nodes.lock().insert(id, NodeState::default());
    }

    fn reset_node(&self, id: NodeId) {
        self.nodes.lock().remove(&id);
    }
}

pub(crate) fn permit_ban_list() -> Arc<RwLock<PermitBanList>> {
    plugin::simulator::<SimulationState>()
        .nodes
        .lock()
        .entry(plugin::node())
        .or_default()
        .permit_ban
        .clone()
}

pub(crate) fn metrics() -> Arc<InternalMetrics> {
    plugin::simulator::<SimulationState>()
        .nodes
        .lock()
        .entry(plugin::node())
        .or_default()
        .metrics
        .clone()
}
