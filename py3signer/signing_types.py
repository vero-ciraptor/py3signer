"""Ethereum Remote Signing API request types.

This module implements the Ethereum Remote Signing API specification,
providing typed signing requests with discriminated union support via msgspec.

Reference: https://github.com/ethereum/remote-signing-api
"""

from typing import Any

import msgspec

# Domain type constants per Ethereum consensus spec
DOMAIN_BEACON_PROPOSER = bytes.fromhex("00000000")
DOMAIN_BEACON_ATTESTER = bytes.fromhex("01000000")
DOMAIN_RANDAO = bytes.fromhex("02000000")
DOMAIN_DEPOSIT = bytes.fromhex("03000000")
DOMAIN_VOLUNTARY_EXIT = bytes.fromhex("04000000")
DOMAIN_SELECTION_PROOF = bytes.fromhex("05000000")
DOMAIN_AGGREGATE_AND_PROOF = bytes.fromhex("06000000")
DOMAIN_SYNC_COMMITTEE = bytes.fromhex("07000000")
DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF = bytes.fromhex("08000000")
DOMAIN_CONTRIBUTION_AND_PROOF = bytes.fromhex("09000000")
DOMAIN_APPLICATION_MASK = bytes.fromhex("0a000000")
DOMAIN_BLOB_SIDECAR = bytes.fromhex("0b000000")


class Fork(msgspec.Struct, frozen=True):
    """Fork information for domain computation.

    Attributes:
        previous_version: Previous fork version (4 bytes)
        current_version: Current fork version (4 bytes)
        epoch: Fork epoch

    """

    previous_version: str
    current_version: str
    epoch: str


class ForkInfo(msgspec.Struct, frozen=True):
    """Fork info required for computing the signing domain.

    Attributes:
        fork: The fork details
        genesis_validators_root: The genesis validators root (32 bytes)

    """

    fork: Fork
    genesis_validators_root: str


# Type-specific data structs


class AttestationData(msgspec.Struct, frozen=True):
    """Attestation data for ATTESTATION signing type."""

    slot: str
    index: str
    beacon_block_root: str = msgspec.field(name="beacon_block_root")
    source: dict[str, str]  # {"epoch": str, "root": str}
    target: dict[str, str]  # {"epoch": str, "root": str}


class AggregationSlot(msgspec.Struct, frozen=True):
    """Aggregation slot data for AGGREGATION_SLOT signing type."""

    slot: str


class RandaoReveal(msgspec.Struct, frozen=True):
    """RANDAO reveal data for RANDAO_REVEAL signing type."""

    epoch: str


class VoluntaryExit(msgspec.Struct, frozen=True):
    """Voluntary exit data for VOLUNTARY_EXIT signing type."""

    epoch: str
    validator_index: str = msgspec.field(name="validator_index")


class DepositData(msgspec.Struct, frozen=True):
    """Deposit data for DEPOSIT signing type."""

    pubkey: str
    withdrawal_credentials: str = msgspec.field(name="withdrawal_credentials")
    amount: str
    genesis_fork_version: str = msgspec.field(name="genesis_fork_version")


class SyncCommitteeMessageData(msgspec.Struct, frozen=True):
    """Sync committee message data for SYNC_COMMITTEE_MESSAGE signing type.

    Per Ethereum Remote Signing API spec v1.3.0, SyncCommitteeMessage
    only contains slot and beacon_block_root.
    """

    slot: str
    beacon_block_root: str = msgspec.field(name="beacon_block_root")


class SyncAggregatorSelectionData(msgspec.Struct, frozen=True):
    """Sync aggregator selection data for SYNC_COMMITTEE_SELECTION_PROOF signing type."""

    slot: str
    subcommittee_index: str = msgspec.field(name="subcommittee_index")


class Checkpoint(msgspec.Struct, frozen=True):
    """Checkpoint data structure."""

    epoch: str
    root: str


class BeaconBlockHeader(msgspec.Struct, frozen=True):
    """Beacon block header for block signing."""

    slot: str
    proposer_index: str = msgspec.field(name="proposer_index")
    parent_root: str = msgspec.field(name="parent_root")
    state_root: str = msgspec.field(name="state_root")
    body_root: str = msgspec.field(name="body_root")


class AggregateAndProof(msgspec.Struct, frozen=True):
    """Aggregate and proof data (deprecated)."""

    aggregator_index: str = msgspec.field(name="aggregator_index")
    aggregate: dict[str, Any]  # Attestation
    selection_proof: str = msgspec.field(name="selection_proof")


class ContributionAndProof(msgspec.Struct, frozen=True):
    """Contribution and proof data for SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF signing type."""

    aggregator_index: str = msgspec.field(name="aggregator_index")
    contribution: dict[str, Any]  # SyncCommitteeContribution
    selection_proof: str = msgspec.field(name="selection_proof")


class ValidatorRegistration(msgspec.Struct, frozen=True):
    """Validator registration data for VALIDATOR_REGISTRATION signing type."""

    fee_recipient: str = msgspec.field(name="fee_recipient")
    gas_limit: str = msgspec.field(name="gas_limit")
    timestamp: str
    pubkey: str


class BlobSidecar(msgspec.Struct, frozen=True):
    """Blob sidecar data for BLOB_SIDECAR signing type.

    Per Ethereum Remote Signing API spec v1.3.0, BlobSidecar
    contains the data needed to sign a blob sidecar for Deneb+.
    """

    slot: str
    block_root: str = msgspec.field(name="block_root")
    index: str


# Union of all signing request types
# Each type has a discriminator 'type' field and the base fields


class AggregationSlotSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="AGGREGATION_SLOT",
):
    """Request to sign an aggregation slot."""

    aggregation_slot: AggregationSlot
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class AggregateAndProofSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="AGGREGATE_AND_PROOF",
):
    """Request to sign an aggregate and proof (deprecated)."""

    aggregate_and_proof: AggregateAndProof
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class AggregateAndProofV2SignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="AGGREGATE_AND_PROOF_V2",
):
    """Request to sign a versioned aggregate and proof."""

    aggregate_and_proof: dict[str, Any]  # Versioned aggregate_and_proof
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class AttestationSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="ATTESTATION",
):
    """Request to sign an attestation."""

    attestation: AttestationData
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class BlockSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="BLOCK",
):
    """Request to sign a beacon block (deprecated)."""

    block: dict[str, Any]  # BeaconBlock
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class BlockV2SignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="BLOCK_V2",
):
    """Request to sign a versioned beacon block."""

    beacon_block: dict[str, Any] = msgspec.field(name="beacon_block")  # Versioned block
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class DepositSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="DEPOSIT",
):
    """Request to sign a deposit."""

    deposit: DepositData
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class RandaoRevealSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="RANDAO_REVEAL",
):
    """Request to sign a RANDAO reveal."""

    randao_reveal: RandaoReveal
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class VoluntaryExitSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="VOLUNTARY_EXIT",
):
    """Request to sign a voluntary exit."""

    voluntary_exit: VoluntaryExit
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class SyncCommitteeMessageSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="SYNC_COMMITTEE_MESSAGE",
):
    """Request to sign a sync committee message."""

    sync_committee_message: SyncCommitteeMessageData
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class SyncCommitteeSelectionProofSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="SYNC_COMMITTEE_SELECTION_PROOF",
):
    """Request to sign a sync committee selection proof."""

    sync_aggregator_selection_data: SyncAggregatorSelectionData
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class SyncCommitteeContributionAndProofSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
):
    """Request to sign a sync committee contribution and proof."""

    contribution_and_proof: ContributionAndProof
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class ValidatorRegistrationSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="VALIDATOR_REGISTRATION",
):
    """Request to sign a validator registration."""

    validator_registration: ValidatorRegistration
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


class BlobSidecarSignRequest(
    msgspec.Struct,
    kw_only=True,
    frozen=True,
    tag_field="type",
    tag="BLOB_SIDECAR",
):
    """Request to sign a blob sidecar.

    Used for signing blob sidecars in Deneb and later forks.
    """

    blob_sidecar: BlobSidecar
    fork_info: ForkInfo = msgspec.field(name="fork_info")
    signing_root: str | None = msgspec.field(name="signing_root", default=None)


# The union type for all sign requests
SignRequest = (
    AggregationSlotSignRequest
    | AggregateAndProofSignRequest
    | AggregateAndProofV2SignRequest
    | AttestationSignRequest
    | BlockSignRequest
    | BlockV2SignRequest
    | DepositSignRequest
    | RandaoRevealSignRequest
    | VoluntaryExitSignRequest
    | SyncCommitteeMessageSignRequest
    | SyncCommitteeSelectionProofSignRequest
    | SyncCommitteeContributionAndProofSignRequest
    | ValidatorRegistrationSignRequest
    | BlobSidecarSignRequest
)

# JSON decoder for discriminated sign requests
sign_request_decoder = msgspec.json.Decoder(SignRequest)


def get_domain_for_request(request: SignRequest) -> bytes:
    """Get the domain bytes for a given signing request type.

    This maps the signing type to its corresponding 4-byte domain.
    Domain computation from fork_info is not yet implemented;
    callers must provide signing_root for now.

    Args:
        request: The signing request

    Returns:
        The 4-byte domain for this signing type

    """
    match request:
        case AggregationSlotSignRequest():
            return DOMAIN_SELECTION_PROOF
        case AggregateAndProofSignRequest() | AggregateAndProofV2SignRequest():
            return DOMAIN_AGGREGATE_AND_PROOF
        case AttestationSignRequest():
            return DOMAIN_BEACON_ATTESTER
        case BlockSignRequest() | BlockV2SignRequest():
            return DOMAIN_BEACON_PROPOSER
        case DepositSignRequest():
            return DOMAIN_DEPOSIT
        case RandaoRevealSignRequest():
            return DOMAIN_RANDAO
        case VoluntaryExitSignRequest():
            return DOMAIN_VOLUNTARY_EXIT
        case SyncCommitteeMessageSignRequest():
            return DOMAIN_SYNC_COMMITTEE
        case SyncCommitteeSelectionProofSignRequest():
            return DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF
        case SyncCommitteeContributionAndProofSignRequest():
            return DOMAIN_CONTRIBUTION_AND_PROOF
        case ValidatorRegistrationSignRequest():
            return DOMAIN_APPLICATION_MASK
        case BlobSidecarSignRequest():
            return DOMAIN_BLOB_SIDECAR
        case _:
            raise ValueError(f"Unknown signing request type: {type(request)}")


def validate_signing_root(signing_root: str | None) -> bytes | None:
    """Validate and convert signing root to bytes.

    Args:
        signing_root: Hex-encoded signing root (with or without 0x prefix)

    Returns:
        The 32-byte signing root, or None if input was None

    Raises:
        ValueError: If signing_root is invalid

    """
    if signing_root is None:
        return None

    signing_root_clean = signing_root.replace("0x", "")
    if len(signing_root_clean) != 64:
        raise ValueError("signing_root must be 32 bytes (64 hex characters)")
    try:
        return bytes.fromhex(signing_root_clean)
    except ValueError as e:
        raise ValueError(f"signing_root must be valid hexadecimal: {e}") from e
