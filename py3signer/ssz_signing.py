"""SSZ signing root computation.

This module implements SSZ serialization and signing root computation
for Ethereum Remote Signing API requests.
"""

from typing import Any

from ssz import get_hash_tree_root
from ssz.sedes import (
    Container,
    UInt,
    Vector,
    bytes32,
    uint64,
)

from .signing_types import (
    DOMAIN_AGGREGATE_AND_PROOF,
    DOMAIN_APPLICATION_MASK,
    DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER,
    DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_DEPOSIT,
    DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF,
    DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT,
    SignRequest,
    AggregationSlotSignRequest,
    AggregateAndProofSignRequest,
    AggregateAndProofV2SignRequest,
    AttestationSignRequest,
    BlockSignRequest,
    BlockV2SignRequest,
    DepositSignRequest,
    RandaoRevealSignRequest,
    VoluntaryExitSignRequest,
    SyncCommitteeMessageSignRequest,
    SyncCommitteeSelectionProofSignRequest,
    SyncCommitteeContributionAndProofSignRequest,
    ValidatorRegistrationSignRequest,
)


def _parse_hex_int(hex_str: str) -> int:
    """Parse hex string to int."""
    if isinstance(hex_str, int):
        return hex_str
    return int(hex_str, 16) if hex_str.startswith("0x") else int(hex_str)


def _parse_hex_bytes(hex_str: str, length: int) -> bytes:
    """Parse hex string to bytes of specified length."""
    if isinstance(hex_str, bytes):
        return hex_str
    hex_clean = hex_str.replace("0x", "")
    return bytes.fromhex(hex_clean.zfill(length * 2))[-length:]


def compute_signing_root(sign_request: SignRequest) -> bytes | None:
    """Compute the signing root from a signing request.

    Args:
        sign_request: The signing request containing type-specific data

    Returns:
        The 32-byte signing root, or None if computation is not supported for this type
    """
    try:
        match sign_request:
            case SyncCommitteeMessageSignRequest():
                return _compute_sync_committee_message_root(sign_request)
            case SyncCommitteeSelectionProofSignRequest():
                return _compute_sync_committee_selection_proof_root(sign_request)
            case AttestationSignRequest():
                return _compute_attestation_root(sign_request)
            case RandaoRevealSignRequest():
                return _compute_randao_root(sign_request)
            case VoluntaryExitSignRequest():
                return _compute_voluntary_exit_root(sign_request)
            case BlockV2SignRequest() | BlockSignRequest():
                # Block signing requires complex SSZ - fallback to requiring signingRoot
                return None
            case AggregateAndProofSignRequest() | AggregateAndProofV2SignRequest():
                # Complex nested structures - fallback to requiring signingRoot
                return None
            case SyncCommitteeContributionAndProofSignRequest():
                # Complex nested structures - fallback to requiring signingRoot
                return None
            case DepositSignRequest():
                return _compute_deposit_root(sign_request)
            case ValidatorRegistrationSignRequest():
                return _compute_validator_registration_root(sign_request)
            case AggregationSlotSignRequest():
                return _compute_aggregation_slot_root(sign_request)
            case _:
                return None
    except Exception:
        # If computation fails, return None to fall back to requiring signingRoot
        return None


def _compute_sync_committee_message_root(
    request: SyncCommitteeMessageSignRequest,
) -> bytes:
    """Compute signing root for sync committee message.

    SyncCommitteeMessage = {
        slot: uint64
        beacon_block_root: bytes32
        validator_index: uint64
    }
    """
    # Sync committee message SSZ structure
    class SyncCommitteeMessage(Container):  # type: ignore[misc]
        fields = [
            ("slot", uint64),
            ("beacon_block_root", bytes32),
            ("validator_index", uint64),
        ]

    data = request.sync_committee_message
    message = SyncCommitteeMessage(
        slot=_parse_hex_int(data.slot),
        beacon_block_root=_parse_hex_bytes(data.beacon_block_root, 32),
        validator_index=0,  # Validator index is not in the request, set to 0
    )

    return get_hash_tree_root(message, SyncCommitteeMessage)  # type: ignore[no-any-return]


def _compute_sync_committee_selection_proof_root(
    request: SyncCommitteeSelectionProofSignRequest,
) -> bytes:
    """Compute signing root for sync committee selection proof.

    SyncAggregatorSelectionData = {
        slot: uint64
        subcommittee_index: uint64
    }
    """
    class SyncAggregatorSelectionData(Container):  # type: ignore[misc]
        fields = [
            ("slot", uint64),
            ("subcommittee_index", uint64),
        ]

    data = request.sync_aggregator_selection_data
    selection_data = SyncAggregatorSelectionData(
        slot=_parse_hex_int(data.slot),
        subcommittee_index=_parse_hex_int(data.subcommittee_index),
    )

    return get_hash_tree_root(selection_data, SyncAggregatorSelectionData)  # type: ignore[no-any-return]


def _compute_attestation_root(request: AttestationSignRequest) -> bytes:
    """Compute signing root for attestation.

    AttestationData = {
        slot: uint64
        index: uint64
        beacon_block_root: bytes32
        source: Checkpoint
        target: Checkpoint
    }
    Checkpoint = {
        epoch: uint64
        root: bytes32
    }
    """
    class Checkpoint(Container):  # type: ignore[misc]
        fields = [
            ("epoch", uint64),
            ("root", bytes32),
        ]

    class AttestationData(Container):  # type: ignore[misc]
        fields = [
            ("slot", uint64),
            ("index", uint64),
            ("beacon_block_root", bytes32),
            ("source", Checkpoint),
            ("target", Checkpoint),
        ]

    data = request.attestation
    attestation_data = AttestationData(
        slot=_parse_hex_int(data.slot),
        index=_parse_hex_int(data.index),
        beacon_block_root=_parse_hex_bytes(data.beacon_block_root, 32),
        source=Checkpoint(
            epoch=_parse_hex_int(data.source["epoch"]),
            root=_parse_hex_bytes(data.source["root"], 32),
        ),
        target=Checkpoint(
            epoch=_parse_hex_int(data.target["epoch"]),
            root=_parse_hex_bytes(data.target["root"], 32),
        ),
    )

    return get_hash_tree_root(attestation_data, AttestationData)  # type: ignore[no-any-return]


def _compute_randao_root(request: RandaoRevealSignRequest) -> bytes:
    """Compute signing root for RANDAO reveal.

    The RANDAO reveal is simply the epoch as uint64.
    """
    epoch = _parse_hex_int(request.randao_reveal.epoch)
    # SSZ encode uint64
    return get_hash_tree_root(epoch, uint64)  # type: ignore[no-any-return]


def _compute_voluntary_exit_root(request: VoluntaryExitSignRequest) -> bytes:
    """Compute signing root for voluntary exit.

    VoluntaryExit = {
        epoch: uint64
        validator_index: uint64
    }
    """
    class VoluntaryExit(Container):  # type: ignore[misc]
        fields = [
            ("epoch", uint64),
            ("validator_index", uint64),
        ]

    data = request.voluntary_exit
    exit_data = VoluntaryExit(
        epoch=_parse_hex_int(data.epoch),
        validator_index=_parse_hex_int(data.validator_index),
    )

    return get_hash_tree_root(exit_data, VoluntaryExit)  # type: ignore[no-any-return]


def _compute_deposit_root(request: DepositSignRequest) -> bytes:
    """Compute signing root for deposit.

    DepositMessage = {
        pubkey: bytes48
        withdrawal_credentials: bytes32
        amount: uint64
    }
    """
    class DepositMessage(Container):  # type: ignore[misc]
        fields = [
            ("pubkey", Vector(UInt(8), 48)),
            ("withdrawal_credentials", bytes32),
            ("amount", uint64),
        ]

    data = request.deposit
    # Parse 48-byte BLS pubkey
    pubkey_bytes = _parse_hex_bytes(data.pubkey, 48)

    deposit_msg = DepositMessage(
        pubkey=pubkey_bytes,
        withdrawal_credentials=_parse_hex_bytes(data.withdrawal_credentials, 32),
        amount=_parse_hex_int(data.amount),
    )

    return get_hash_tree_root(deposit_msg, DepositMessage)  # type: ignore[no-any-return]


def _compute_validator_registration_root(request: ValidatorRegistrationSignRequest) -> bytes:
    """Compute signing root for validator registration.

    ValidatorRegistration = {
        fee_recipient: bytes20
        gas_limit: uint64
        timestamp: uint64
        pubkey: bytes48
    }
    """
    class ValidatorRegistration(Container):  # type: ignore[misc]
        fields = [
            ("fee_recipient", Vector(UInt(8), 20)),
            ("gas_limit", uint64),
            ("timestamp", uint64),
            ("pubkey", Vector(UInt(8), 48)),
        ]

    data = request.validator_registration
    reg = ValidatorRegistration(
        fee_recipient=_parse_hex_bytes(data.fee_recipient, 20),
        gas_limit=_parse_hex_int(data.gas_limit),
        timestamp=_parse_hex_int(data.timestamp),
        pubkey=_parse_hex_bytes(data.pubkey, 48),
    )

    return get_hash_tree_root(reg, ValidatorRegistration)  # type: ignore[no-any-return]


def _compute_aggregation_slot_root(request: AggregationSlotSignRequest) -> bytes:
    """Compute signing root for aggregation slot.

    The aggregation slot is simply the slot as uint64.
    """
    slot = _parse_hex_int(request.aggregation_slot.slot)
    return get_hash_tree_root(slot, uint64)  # type: ignore[no-any-return]
