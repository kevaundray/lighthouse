// Example usage of the new execution proof subnet system
use types::{ExecutionProof, ProofSubnetId, ProofType};

fn main() {
    // Example: Creating different types of execution proofs
    
    // SP1 zkVM proof (subnet 0)
    let sp1_proof_data = vec![1, 2, 3, 4]; // Opaque SP1 proof bytes
    let sp1_proof = ExecutionProof::new(1, sp1_proof_data);
    let sp1_subnet = ProofSubnetId::sp1(); // or ProofSubnetId::for_proof_type(ProofType::SP1Proof)
    println!("SP1 proof on subnet {}: version {}, {} bytes", 
             *sp1_subnet, sp1_proof.version(), sp1_proof.data().len());
    
    // Risc0 zkVM proof (subnet 1)
    let risc0_proof_data = vec![5, 6, 7, 8, 9]; // Opaque Risc0 proof bytes
    let risc0_proof = ExecutionProof::new(2, risc0_proof_data);
    let risc0_subnet = ProofSubnetId::risc0();
    println!("Risc0 proof on subnet {}: version {}, {} bytes", 
             *risc0_subnet, risc0_proof.version(), risc0_proof.data().len());
    
    // Execution witness for stateless execution (subnet 2)
    let witness_data = vec![10, 11, 12, 13, 14, 15]; // Opaque witness bytes (MPT proofs etc.)
    let execution_witness = ExecutionProof::new(1, witness_data);
    let witness_subnet = ProofSubnetId::execution_witness();
    println!("Execution witness on subnet {}: version {}, {} bytes", 
             *witness_subnet, execution_witness.version(), execution_witness.data().len());
    
    // Gossip topic format examples:
    println!("\nGossip topics:");
    println!("SP1 proofs: /eth2/{{fork_digest}}/execution_proof_0/ssz_snappy");
    println!("Risc0 proofs: /eth2/{{fork_digest}}/execution_proof_1/ssz_snappy");
    println!("Execution witnesses: /eth2/{{fork_digest}}/execution_proof_2/ssz_snappy");
    
    // Network usage patterns:
    println!("\nNetwork usage:");
    println!("- L2 sequencers publish SP1 proofs to subnet 0");
    println!("- Alternative zkVM users publish Risc0 proofs to subnet 1");
    println!("- Portal Network/light clients share execution witnesses on subnet 2");
    println!("- Each application handles its own proof format and versioning");
}