use beacon_chain::builder::{BeaconChainBuilder, Witness};
use slot_clock::SystemTimeSlotClock;
use store::MemoryStore;
use types::MinimalEthSpec;

type Builder =
    BeaconChainBuilder<Witness<SystemTimeSlotClock, MinimalEthSpec, MemoryStore, MemoryStore>>;

fn main() {
    let _ = Builder::canonical_head;
}
