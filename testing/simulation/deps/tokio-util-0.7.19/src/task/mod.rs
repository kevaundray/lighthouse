//! Extra utilities for spawning tasks
//!
//! This module is only available when the `rt` feature is enabled. Note that enabling the
//! `join-map` feature will automatically also enable the `rt` feature.

cfg_rt! {
    #[cfg(not(madsim))]
    mod spawn_pinned;
    #[cfg(not(madsim))]
    pub use spawn_pinned::LocalPoolHandle;

    pub mod task_tracker;
    #[doc(inline)]
    pub use task_tracker::TaskTracker;

    mod abort_on_drop;
    pub use abort_on_drop::{AbortOnDrop, AbortOnDropHandle};

    #[cfg(not(madsim))]
    mod join_queue;
    #[cfg(not(madsim))]
    pub use join_queue::JoinQueue;
}

#[cfg(all(feature = "join-map", not(madsim)))]
mod join_map;
#[cfg(all(feature = "join-map", not(madsim)))]
#[cfg_attr(docsrs, doc(cfg(feature = "join-map")))]
pub use join_map::{JoinMap, JoinMapKeys};
