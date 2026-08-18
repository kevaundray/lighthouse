//! Provides methods for obtaining validator signatures, including:
//!
//! - Via a local `Keypair`.
//! - Via a remote signer (Web3Signer)
//!
//! The PQ journal and its raw reservation operation are not public APIs:
//!
//! ```compile_fail
//! use pq_signing::journal::XmssUsageJournal;
//! ```

#[cfg(not(feature = "pq-devnet"))]
use bls::{Keypair, PublicKey};
use consensus_signature::IndividualSignature;
#[cfg(feature = "pq-devnet")]
use consensus_signature::pq::PqSigningClaim;
use consensus_signature::{OneTimeUseId, SigningDuty, SigningIdError};
#[cfg(not(feature = "pq-devnet"))]
use eth2_keystore::Keystore;
#[cfg(not(feature = "pq-devnet"))]
use lockfile::Lockfile;
#[cfg(not(feature = "pq-devnet"))]
use parking_lot::Mutex;
#[cfg(feature = "pq-devnet")]
use pq_signing::{PqSigner, PqSigningError};
#[cfg(not(feature = "pq-devnet"))]
use reqwest::{Client, header::ACCEPT};
#[cfg(not(feature = "pq-devnet"))]
use std::path::PathBuf;
#[cfg(not(feature = "pq-devnet"))]
use std::sync::Arc;
use task_executor::{RayonPoolType, TaskExecutor};
use tracing::instrument;
use types::*;
#[cfg(not(feature = "pq-devnet"))]
use url::Url;
#[cfg(not(feature = "pq-devnet"))]
use web3signer::{ForkInfo, MessageType, SigningRequest, SigningResponse};

#[cfg(not(feature = "pq-devnet"))]
pub use web3signer::Web3SignerObject;

#[cfg(not(feature = "pq-devnet"))]
mod web3signer;

#[derive(Debug)]
pub enum Error {
    InconsistentDomains {
        message_type_domain: Domain,
        domain: Domain,
    },
    InconsistentEpochs {
        message_epoch: Epoch,
        context_epoch: Epoch,
    },
    Web3SignerRequestFailed(String),
    Web3SignerJsonParsingFailed(String),
    ShuttingDown,
    TokioJoin(String),
    MergeForkNotSupported,
    GenesisForkVersionRequired,
    PqSigningDutyUnsupported(UnsupportedPqSigningDuty),
    PqSigningId(SigningIdError),
    #[cfg(feature = "pq-devnet")]
    PqSigning(PqSigningError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "pq-devnet")]
            Self::PqSigning(error) => Some(error),
            _ => None,
        }
    }
}

/// A signing request deliberately excluded from the frozen `LeanPqDevnetV1` profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedPqSigningDuty {
    ValidatorRegistration,
    VoluntaryExit,
    ExecutionPayloadEnvelope,
    PayloadAttestation,
    ProposerPreferences,
}

/// Enumerates all messages that can be signed by a validator.
pub enum SignableMessage<'a, E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    RandaoReveal(Slot),
    BeaconBlock(&'a BeaconBlock<E, Payload>),
    AttestationData(&'a AttestationData),
    SignedAggregateAndProof(AggregateAndProofRef<'a, E>),
    SelectionProof(Slot),
    SyncSelectionProof(&'a SyncAggregatorSelectionData),
    SyncCommitteeSignature {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SignedContributionAndProof(&'a ContributionAndProof<E>),
    ValidatorRegistration(&'a ValidatorRegistrationData),
    VoluntaryExit(&'a VoluntaryExit),
    ExecutionPayloadEnvelope(&'a ExecutionPayloadEnvelope<E>),
    PayloadAttestationData(&'a PayloadAttestationData),
    ProposerPreferences(&'a ProposerPreferences),
}

impl<E: EthSpec, Payload: AbstractExecPayload<E>> SignableMessage<'_, E, Payload> {
    #[cfg(feature = "pq-devnet")]
    fn validate_signing_context(&self, context: &SigningContext) -> Result<(), Error> {
        let (expected_domain, expected_epoch) = match self {
            Self::RandaoReveal(slot) => (Domain::Randao, slot.epoch(E::slots_per_epoch())),
            Self::BeaconBlock(block) => (Domain::BeaconProposer, block.epoch()),
            Self::AttestationData(attestation) => {
                (Domain::BeaconAttester, attestation.target.epoch)
            }
            Self::SignedAggregateAndProof(aggregate) => (
                Domain::AggregateAndProof,
                aggregate.aggregate().data().target.epoch,
            ),
            Self::SelectionProof(slot) => {
                (Domain::SelectionProof, slot.epoch(E::slots_per_epoch()))
            }
            Self::SyncSelectionProof(selection) => (
                Domain::SyncCommitteeSelectionProof,
                selection.slot.epoch(E::slots_per_epoch()),
            ),
            Self::SyncCommitteeSignature { slot, .. } => {
                (Domain::SyncCommittee, slot.epoch(E::slots_per_epoch()))
            }
            Self::SignedContributionAndProof(contribution) => (
                Domain::ContributionAndProof,
                contribution.contribution.slot.epoch(E::slots_per_epoch()),
            ),
            Self::ValidatorRegistration(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ValidatorRegistration,
                ));
            }
            Self::VoluntaryExit(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::VoluntaryExit,
                ));
            }
            Self::ExecutionPayloadEnvelope(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ExecutionPayloadEnvelope,
                ));
            }
            Self::PayloadAttestationData(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::PayloadAttestation,
                ));
            }
            Self::ProposerPreferences(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ProposerPreferences,
                ));
            }
        };

        if context.domain != expected_domain {
            return Err(Error::InconsistentDomains {
                message_type_domain: expected_domain,
                domain: context.domain,
            });
        }
        if context.epoch != expected_epoch {
            return Err(Error::InconsistentEpochs {
                message_epoch: expected_epoch,
                context_epoch: context.epoch,
            });
        }
        Ok(())
    }

    /// Returns the `SignedRoot` for the contained message.
    ///
    /// The actual `SignedRoot` trait is not used since it also requires a `TreeHash` impl, which is
    /// not required here.
    pub fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            SignableMessage::RandaoReveal(proposal_slot) => proposal_slot
                .epoch(E::slots_per_epoch())
                .signing_root(domain),
            SignableMessage::BeaconBlock(b) => b.signing_root(domain),
            SignableMessage::AttestationData(a) => a.signing_root(domain),
            SignableMessage::SignedAggregateAndProof(a) => a.signing_root(domain),
            SignableMessage::SelectionProof(slot) => slot.signing_root(domain),
            SignableMessage::SyncSelectionProof(s) => s.signing_root(domain),
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root, ..
            } => beacon_block_root.signing_root(domain),
            SignableMessage::SignedContributionAndProof(c) => c.signing_root(domain),
            SignableMessage::ValidatorRegistration(v) => v.signing_root(domain),
            SignableMessage::VoluntaryExit(exit) => exit.signing_root(domain),
            SignableMessage::ExecutionPayloadEnvelope(e) => e.signing_root(domain),
            SignableMessage::PayloadAttestationData(d) => d.signing_root(domain),
            SignableMessage::ProposerPreferences(p) => p.signing_root(domain),
        }
    }

    /// Extracts the semantic duty and stateful-signature leaf for the V1 PQ profile.
    pub fn lean_pq_devnet_v1_signing_id(&self) -> Result<(Slot, SigningDuty, OneTimeUseId), Error> {
        let (slot, duty) = match self {
            SignableMessage::RandaoReveal(proposal_slot) => {
                (*proposal_slot, SigningDuty::RandaoReveal)
            }
            SignableMessage::BeaconBlock(block) => (block.slot(), SigningDuty::BeaconBlockProposal),
            SignableMessage::AttestationData(attestation) => {
                (attestation.slot, SigningDuty::Attestation)
            }
            SignableMessage::SignedAggregateAndProof(aggregate_and_proof) => (
                aggregate_and_proof.aggregate().data().slot,
                SigningDuty::AggregateAndProof,
            ),
            SignableMessage::SelectionProof(slot) => {
                (*slot, SigningDuty::AttestationSelectionProof)
            }
            SignableMessage::SyncSelectionProof(selection) => (
                selection.slot,
                SigningDuty::sync_selection_proof(selection.subcommittee_index)
                    .map_err(Error::PqSigningId)?,
            ),
            SignableMessage::SyncCommitteeSignature { slot, .. } => {
                (*slot, SigningDuty::SyncCommitteeMessage)
            }
            SignableMessage::SignedContributionAndProof(contribution_and_proof) => (
                contribution_and_proof.contribution.slot,
                SigningDuty::sync_contribution_and_proof(
                    contribution_and_proof.contribution.subcommittee_index,
                )
                .map_err(Error::PqSigningId)?,
            ),
            SignableMessage::ValidatorRegistration(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ValidatorRegistration,
                ));
            }
            SignableMessage::VoluntaryExit(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::VoluntaryExit,
                ));
            }
            SignableMessage::ExecutionPayloadEnvelope(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ExecutionPayloadEnvelope,
                ));
            }
            SignableMessage::PayloadAttestationData(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::PayloadAttestation,
                ));
            }
            SignableMessage::ProposerPreferences(_) => {
                return Err(Error::PqSigningDutyUnsupported(
                    UnsupportedPqSigningDuty::ProposerPreferences,
                ));
            }
        };
        let one_time_use_id =
            OneTimeUseId::for_lean_pq_devnet_v1(slot.as_u64(), duty).map_err(Error::PqSigningId)?;
        Ok((slot, duty, one_time_use_id))
    }
}

/// A method used by a validator to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[cfg_attr(
    feature = "pq-devnet",
    doc = r#"
The bound signer is opaque and cannot be extracted from the public signing method:

```compile_fail
use pq_signing::PqSigner;
use signing_method::SigningMethod;

fn extract(method: SigningMethod) -> PqSigner {
    match method {
        SigningMethod::PqLocal(local) => local.signer,
    }
}
```
"#
)]
pub enum SigningMethod {
    /// The only signing method supported by the frozen PQ devnet profile.
    #[cfg(feature = "pq-devnet")]
    PqLocal(PqLocalSigningMethod),
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    #[cfg(not(feature = "pq-devnet"))]
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore: Keystore,
        voting_keypair: Arc<Keypair>,
    },
    /// A validator that defers to a Web3Signer server for signing.
    ///
    /// See: https://docs.web3signer.consensys.net/en/latest/
    #[cfg(not(feature = "pq-devnet"))]
    Web3Signer {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
}

/// Opaque holder for the authority-bound PQ signer.
#[cfg(feature = "pq-devnet")]
pub struct PqLocalSigningMethod {
    signer: PqSigner,
}

/// The additional information used to construct a signature. Mostly used for protection from replay
/// attacks.
pub struct SigningContext {
    pub domain: Domain,
    pub epoch: Epoch,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

impl SigningContext {
    /// Returns the `Hash256` to be mixed-in with the signature.
    pub fn domain_hash(&self, spec: &ChainSpec) -> Hash256 {
        spec.get_domain(
            self.epoch,
            self.domain,
            &self.fork,
            self.genesis_validators_root,
        )
    }
}

impl SigningMethod {
    /// Binds an authority-owned signer to the semantic signing interface.
    #[cfg(feature = "pq-devnet")]
    pub fn pq_local(signer: PqSigner) -> Self {
        Self::PqLocal(PqLocalSigningMethod { signer })
    }

    /// Return whether this signing method requires local slashing protection.
    pub fn requires_local_slashing_protection(
        &self,
        _enable_web3signer_slashing_protection: bool,
    ) -> bool {
        match self {
            #[cfg(feature = "pq-devnet")]
            SigningMethod::PqLocal(_) => true,
            // Slashing protection is ALWAYS required for local keys. DO NOT TURN THIS OFF.
            #[cfg(not(feature = "pq-devnet"))]
            SigningMethod::LocalKeystore { .. } => true,
            // Slashing protection is only required for remote signer keys when the configuration
            // dictates that it is desired.
            #[cfg(not(feature = "pq-devnet"))]
            SigningMethod::Web3Signer { .. } => _enable_web3signer_slashing_protection,
        }
    }

    /// Return the signature of `signable_message`, with respect to the `signing_context`.
    #[cfg_attr(
        feature = "pq-devnet",
        doc = r#"
PQ callers cannot supply a signing root independently from the semantic message:

```compile_fail
use signing_method::SigningMethod;
use types::{BlindedPayload, MinimalEthSpec};

let _ = SigningMethod::get_signature_from_root::<
    MinimalEthSpec,
    BlindedPayload<MinimalEthSpec>,
>;
```
"#
    )]
    #[instrument(skip_all, level = "debug")]
    pub async fn get_signature<E: EthSpec, Payload: AbstractExecPayload<E>>(
        &self,
        signable_message: SignableMessage<'_, E, Payload>,
        signing_context: SigningContext,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<IndividualSignature, Error> {
        #[cfg(feature = "pq-devnet")]
        signable_message.validate_signing_context(&signing_context)?;

        let domain_hash = signing_context.domain_hash(spec);
        let signing_root = signable_message.signing_root(domain_hash);

        #[cfg(feature = "pq-devnet")]
        {
            let (_, _, one_time_use_id) = signable_message.lean_pq_devnet_v1_signing_id()?;
            let claim = PqSigningClaim::new(signing_root.0, one_time_use_id);
            let signer = match self {
                SigningMethod::PqLocal(local) => local.signer.clone(),
            };
            let signature = executor
                .spawn_blocking_with_rayon_async(RayonPoolType::HighPriority, move || {
                    signer.sign(claim)
                })
                .await
                .map_err(|_| Error::ShuttingDown)?
                .map_err(Error::PqSigning)?;
            Ok(signature)
        }

        #[cfg(not(feature = "pq-devnet"))]
        {
            let fork_info = Some(ForkInfo {
                fork: signing_context.fork,
                genesis_validators_root: signing_context.genesis_validators_root,
            });
            self.get_signature_from_root::<E, Payload>(
                signable_message,
                signing_root,
                executor,
                fork_info,
            )
            .await
        }
    }

    #[cfg(not(feature = "pq-devnet"))]
    pub async fn get_signature_from_root<E: EthSpec, Payload: AbstractExecPayload<E>>(
        &self,
        signable_message: SignableMessage<'_, E, Payload>,
        signing_root: Hash256,
        executor: &TaskExecutor,
        fork_info: Option<ForkInfo>,
    ) -> Result<IndividualSignature, Error> {
        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                let _timer = validator_metrics::start_timer_vec(
                    &validator_metrics::SIGNING_TIMES,
                    &[validator_metrics::LOCAL_KEYSTORE],
                );

                let voting_keypair = voting_keypair.clone();
                // Spawn a blocking task to produce the signature. This avoids blocking the core
                // tokio executor.
                //
                // We are using the Rayon high-priority pool which uses up to 80% of available
                // threads. In future we could consider using 90-100% in the VC, seeing as we have
                // very little other work to do aside from signing.
                let signature = executor
                    .spawn_blocking_with_rayon_async(RayonPoolType::HighPriority, move || {
                        voting_keypair.sk.sign(signing_root)
                    })
                    .await
                    .map_err(|_| Error::ShuttingDown)?;
                Ok(signature)
            }
            SigningMethod::Web3Signer {
                signing_url,
                http_client,
                ..
            } => {
                let _timer = validator_metrics::start_timer_vec(
                    &validator_metrics::SIGNING_TIMES,
                    &[validator_metrics::WEB3SIGNER],
                );

                // Map the message into a Web3Signer type.
                let object = match signable_message {
                    SignableMessage::RandaoReveal(proposal_slot) => {
                        let epoch = proposal_slot.epoch(E::slots_per_epoch());
                        Web3SignerObject::RandaoReveal { epoch }
                    }
                    SignableMessage::BeaconBlock(block) => Web3SignerObject::beacon_block(block)?,
                    SignableMessage::AttestationData(a) => Web3SignerObject::Attestation(a),
                    SignableMessage::SignedAggregateAndProof(a) => {
                        Web3SignerObject::AggregateAndProof(a)
                    }
                    SignableMessage::SelectionProof(slot) => {
                        Web3SignerObject::AggregationSlot { slot }
                    }
                    SignableMessage::SyncSelectionProof(s) => {
                        Web3SignerObject::SyncAggregatorSelectionData(s)
                    }
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root,
                        slot,
                    } => Web3SignerObject::SyncCommitteeMessage {
                        beacon_block_root,
                        slot,
                    },
                    SignableMessage::SignedContributionAndProof(c) => {
                        Web3SignerObject::ContributionAndProof(c)
                    }
                    SignableMessage::ValidatorRegistration(v) => {
                        Web3SignerObject::ValidatorRegistration(v)
                    }
                    SignableMessage::VoluntaryExit(e) => Web3SignerObject::VoluntaryExit(e),
                    SignableMessage::ExecutionPayloadEnvelope(e) => {
                        Web3SignerObject::ExecutionPayloadEnvelope(e)
                    }
                    SignableMessage::PayloadAttestationData(d) => {
                        Web3SignerObject::PayloadAttestationData(d)
                    }
                    SignableMessage::ProposerPreferences(p) => {
                        Web3SignerObject::ProposerPreferences(p)
                    }
                };

                // Determine the Web3Signer message type.
                let message_type = object.message_type();
                if matches!(message_type, MessageType::ValidatorRegistration) && fork_info.is_some()
                {
                    return Err(Error::GenesisForkVersionRequired);
                }

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    object,
                };

                // Request a signature from the Web3Signer instance via HTTP(S).
                let response: SigningResponse = http_client
                    .post(signing_url.clone())
                    .header(ACCEPT, "application/json")
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| Error::Web3SignerJsonParsingFailed(e.to_string()))?;

                Ok(response.signature)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::PublicKeyBytes;
    use consensus_signature::{IndividualSignature, OneTimeUseId, SigningDuty};

    #[cfg(feature = "pq-devnet")]
    use consensus_signature::pq::{PqSigningClaim, verify_raw};
    #[cfg(feature = "pq-devnet")]
    use pq_signing::{PqKeyUnlock, PqKeystore, PqSigningAuthority, provision_usage_journal};
    #[cfg(feature = "pq-devnet")]
    use task_executor::test_utils::TestRuntime;
    #[cfg(feature = "pq-devnet")]
    use tempfile::TempDir;

    fn assert_signing_id<Payload: AbstractExecPayload<MinimalEthSpec>>(
        message: SignableMessage<'_, MinimalEthSpec, Payload>,
        expected_slot: Slot,
        expected_duty: SigningDuty,
    ) {
        let actual = message
            .lean_pq_devnet_v1_signing_id()
            .expect("supported signing ID");
        assert_eq!(
            actual,
            (
                expected_slot,
                expected_duty,
                OneTimeUseId::for_lean_pq_devnet_v1(expected_slot.as_u64(), expected_duty,)
                    .expect("test slot is supported"),
            )
        );
    }

    #[test]
    fn randao_uses_the_containing_proposal_slot() {
        let proposal_slot = Slot::new(95);
        let message =
            SignableMessage::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::RandaoReveal(
                proposal_slot,
            );
        let domain = Hash256::repeat_byte(0x42);

        assert_eq!(
            message
                .lean_pq_devnet_v1_signing_id()
                .expect("supported RANDAO signing ID"),
            (
                proposal_slot,
                SigningDuty::RandaoReveal,
                OneTimeUseId::for_lean_pq_devnet_v1(
                    proposal_slot.as_u64(),
                    SigningDuty::RandaoReveal,
                )
                .expect("test slot is supported"),
            )
        );
        assert_eq!(
            message.signing_root(domain),
            proposal_slot
                .epoch(MinimalEthSpec::slots_per_epoch())
                .signing_root(domain)
        );
    }

    #[test]
    fn enabled_electra_messages_use_their_semantic_object_slots() {
        let slot = Slot::new(1_234);
        let mut spec = ChainSpec::minimal();
        spec.electra_fork_epoch = Some(Epoch::new(0));
        spec.gloas_fork_epoch = None;

        let mut block = BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
        *block.slot_mut() = slot;
        assert_signing_id(
            SignableMessage::BeaconBlock(&block),
            slot,
            SigningDuty::BeaconBlockProposal,
        );

        let attestation_data = AttestationData {
            slot,
            ..AttestationData::default()
        };
        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::AttestationData(&attestation_data),
            slot,
            SigningDuty::Attestation,
        );

        let aggregate = Attestation::<MinimalEthSpec>::empty_for_signing(
            0,
            1,
            slot,
            Hash256::ZERO,
            Checkpoint::default(),
            Checkpoint::default(),
            false,
            &spec,
        )
        .expect("valid Electra test attestation");
        let aggregate_and_proof = AggregateAndProof::from_attestation(
            0,
            aggregate,
            SelectionProof::from(IndividualSignature::empty()),
        );
        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::SignedAggregateAndProof(aggregate_and_proof.to_ref()),
            slot,
            SigningDuty::AggregateAndProof,
        );

        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::SelectionProof(slot),
            slot,
            SigningDuty::AttestationSelectionProof,
        );

        let sync_selection = SyncAggregatorSelectionData {
            slot,
            subcommittee_index: 2,
        };
        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::SyncSelectionProof(&sync_selection),
            slot,
            SigningDuty::sync_selection_proof(2).expect("subcommittee two is supported"),
        );

        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root: Hash256::ZERO,
                slot,
            },
            slot,
            SigningDuty::SyncCommitteeMessage,
        );

        let sync_message = SyncCommitteeMessage {
            slot,
            beacon_block_root: Hash256::ZERO,
            validator_index: 0,
            signature: IndividualSignature::empty(),
        };
        let contribution =
            SyncCommitteeContribution::<MinimalEthSpec>::from_message(&sync_message, 3, 0)
                .expect("valid test contribution");
        let contribution_and_proof = ContributionAndProof {
            aggregator_index: 0,
            contribution,
            selection_proof: IndividualSignature::empty(),
        };
        assert_signing_id::<BlindedPayload<MinimalEthSpec>>(
            SignableMessage::SignedContributionAndProof(&contribution_and_proof),
            slot,
            SigningDuty::sync_contribution_and_proof(3).expect("subcommittee three is supported"),
        );
    }

    #[test]
    fn v1_explicitly_rejects_messages_outside_the_electra_profile() {
        let registration = ValidatorRegistrationData {
            fee_recipient: Address::ZERO,
            gas_limit: 0,
            timestamp: 0,
            pubkey: PublicKeyBytes::empty(),
        };
        let voluntary_exit = VoluntaryExit {
            epoch: Epoch::new(1),
            validator_index: 0,
        };
        let envelope = ExecutionPayloadEnvelope::<MinimalEthSpec>::empty();
        let payload_attestation = PayloadAttestationData {
            beacon_block_root: Hash256::ZERO,
            slot: Slot::new(1),
            payload_present: false,
            blob_data_available: false,
        };
        let preferences = ProposerPreferences::default();

        let cases = [
            (
                SignableMessage::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::ValidatorRegistration(
                    &registration,
                ),
                UnsupportedPqSigningDuty::ValidatorRegistration,
            ),
            (
                SignableMessage::VoluntaryExit(&voluntary_exit),
                UnsupportedPqSigningDuty::VoluntaryExit,
            ),
            (
                SignableMessage::ExecutionPayloadEnvelope(&envelope),
                UnsupportedPqSigningDuty::ExecutionPayloadEnvelope,
            ),
            (
                SignableMessage::PayloadAttestationData(&payload_attestation),
                UnsupportedPqSigningDuty::PayloadAttestation,
            ),
            (
                SignableMessage::ProposerPreferences(&preferences),
                UnsupportedPqSigningDuty::ProposerPreferences,
            ),
        ];

        for (message, duty) in cases {
            assert!(matches!(
                message.lean_pq_devnet_v1_signing_id(),
                Err(Error::PqSigningDutyUnsupported(actual)) if actual == duty
            ));
        }
    }

    #[cfg(feature = "pq-devnet")]
    #[tokio::test(flavor = "multi_thread")]
    async fn pq_signing_method_signs_and_verifies_first_devnet_duties() {
        const PASSWORD: &[u8] = b"correct horse battery staple";
        let temporary_directory = TempDir::new().expect("temporary directory");
        let journal_path = temporary_directory.path().join("xmss_usage.sqlite");
        let keystore = PqKeystore::from_seed([7; 32], 0..=13, PASSWORD).expect("keystore");
        let metadata = keystore.authenticate(PASSWORD).expect("authentication");
        provision_usage_journal(&journal_path, [3; 32], std::slice::from_ref(&metadata))
            .expect("journal provisioning");
        let authority = PqSigningAuthority::open(
            &journal_path,
            [3; 32],
            vec![PqKeyUnlock::new(keystore, PASSWORD).expect("key unlock")],
        )
        .expect("signing authority");
        let public_key = authority.public_keys()[0];
        let signing_method =
            SigningMethod::pq_local(authority.signer(&public_key).expect("bound signer"));
        let test_runtime = TestRuntime::default();
        let spec = ChainSpec::minimal();
        let slot = Slot::new(0);
        let mut block = BeaconBlock::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>::empty(&spec);
        *block.slot_mut() = slot;
        let attestation_data = AttestationData {
            slot,
            ..AttestationData::default()
        };
        let aggregate = Attestation::<MinimalEthSpec>::empty_for_signing(
            0,
            1,
            slot,
            Hash256::ZERO,
            Checkpoint::default(),
            Checkpoint::default(),
            false,
            &spec,
        )
        .expect("valid Electra test attestation");
        let aggregate_and_proof = AggregateAndProof::from_attestation(
            0,
            aggregate,
            SelectionProof::from(IndividualSignature::empty()),
        );

        let wrong_domain = signing_method
            .get_signature::<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>(
                SignableMessage::RandaoReveal(slot),
                SigningContext {
                    domain: Domain::BeaconProposer,
                    epoch: Epoch::new(0),
                    fork: Fork::default(),
                    genesis_validators_root: Hash256::repeat_byte(0x42),
                },
                &spec,
                &test_runtime.task_executor,
            )
            .await;
        assert!(matches!(
            wrong_domain,
            Err(Error::InconsistentDomains { .. })
        ));

        let wrong_epoch = signing_method
            .get_signature(
                SignableMessage::BeaconBlock(&block),
                SigningContext {
                    domain: Domain::BeaconProposer,
                    epoch: Epoch::new(1),
                    fork: Fork::default(),
                    genesis_validators_root: Hash256::repeat_byte(0x42),
                },
                &spec,
                &test_runtime.task_executor,
            )
            .await;
        assert!(matches!(wrong_epoch, Err(Error::InconsistentEpochs { .. })));

        let messages = [
            (SignableMessage::RandaoReveal(slot), Domain::Randao),
            (SignableMessage::BeaconBlock(&block), Domain::BeaconProposer),
            (
                SignableMessage::AttestationData(&attestation_data),
                Domain::BeaconAttester,
            ),
            (
                SignableMessage::SelectionProof(slot),
                Domain::SelectionProof,
            ),
            (
                SignableMessage::SignedAggregateAndProof(aggregate_and_proof.to_ref()),
                Domain::AggregateAndProof,
            ),
        ];

        for (message, domain) in messages {
            let signing_context = SigningContext {
                domain,
                epoch: Epoch::new(0),
                fork: Fork::default(),
                genesis_validators_root: Hash256::repeat_byte(0x42),
            };
            let signing_root = message.signing_root(signing_context.domain_hash(&spec));
            let (_, _, one_time_use_id) = message
                .lean_pq_devnet_v1_signing_id()
                .expect("supported duty");
            let signature = signing_method
                .get_signature(message, signing_context, &spec, &test_runtime.task_executor)
                .await
                .expect("PQ signature");
            let claim = PqSigningClaim::new(signing_root.0, one_time_use_id);
            verify_raw(&signature, &public_key, &claim).expect("valid PQ signature");
        }
    }
}
