"""Tests for signing_types module."""

from typing import Any

import msgspec
import pytest

from py3signer.signing_types import (
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
    AggregateAndProofSignRequest,
    AggregateAndProofV2SignRequest,
    AggregationSlot,
    AggregationSlotSignRequest,
    AttestationData,
    AttestationSignRequest,
    BlockSignRequest,
    BlockV2SignRequest,
    DepositData,
    DepositSignRequest,
    Fork,
    ForkInfo,
    RandaoReveal,
    RandaoRevealSignRequest,
    SyncAggregatorSelectionData,
    SyncCommitteeContributionAndProofSignRequest,
    SyncCommitteeMessageData,
    SyncCommitteeMessageSignRequest,
    SyncCommitteeSelectionProofSignRequest,
    ValidatorRegistrationSignRequest,
    VoluntaryExit,
    VoluntaryExitSignRequest,
    get_domain_for_request,
    sign_request_decoder,
    validate_signing_root,
)


class TestDomainConstants:
    """Tests for domain constants."""

    def test_domain_lengths(self) -> None:
        """All domains should be 4 bytes."""
        domains = [
            DOMAIN_BEACON_ATTESTER,
            DOMAIN_BEACON_PROPOSER,
            DOMAIN_RANDAO,
            DOMAIN_DEPOSIT,
            DOMAIN_VOLUNTARY_EXIT,
            DOMAIN_AGGREGATE_AND_PROOF,
            DOMAIN_SELECTION_PROOF,
            DOMAIN_SYNC_COMMITTEE,
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            DOMAIN_CONTRIBUTION_AND_PROOF,
            DOMAIN_APPLICATION_MASK,
        ]
        for domain in domains:
            assert len(domain) == 4


class TestForkInfo:
    """Tests for Fork and ForkInfo structs."""

    def test_fork_creation(self) -> None:
        """Test creating a Fork struct."""
        fork = Fork(
            previous_version="0x00000000",
            current_version="0x01000000",
            epoch="100",
        )
        assert fork.previous_version == "0x00000000"
        assert fork.current_version == "0x01000000"
        assert fork.epoch == "100"

    def test_fork_info_creation(self) -> None:
        """Test creating a ForkInfo struct."""
        fork = Fork(
            previous_version="0x00000000",
            current_version="0x00000000",
            epoch="0",
        )
        fork_info = ForkInfo(fork=fork, genesis_validators_root="0x" + "00" * 32)
        assert fork_info.fork == fork
        assert fork_info.genesis_validators_root == "0x" + "00" * 32


class TestSignRequestParsing:
    """Tests for parsing sign requests."""

    def test_parse_attestation_request(self) -> None:
        """Test parsing an ATTESTATION sign request."""
        json_data = b"""{
            "type": "ATTESTATION",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signing_root": "0xabcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "source": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                "target": {"epoch": "1", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"}
            }
        }"""

        request = sign_request_decoder.decode(json_data)
        assert isinstance(request, AttestationSignRequest)
        assert request.attestation.slot == "123"
        assert request.attestation.index == "0"

    def test_parse_randao_request(self) -> None:
        """Test parsing a RANDAO_REVEAL sign request."""
        json_data = b"""{
            "type": "RANDAO_REVEAL",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signing_root": "0xabcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "randao_reveal": {
                "epoch": "100"
            }
        }"""

        request = sign_request_decoder.decode(json_data)
        assert isinstance(request, RandaoRevealSignRequest)
        assert request.randao_reveal.epoch == "100"

    def test_parse_voluntary_exit_request(self) -> None:
        """Test parsing a VOLUNTARY_EXIT sign request."""
        json_data = b"""{
            "type": "VOLUNTARY_EXIT",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signing_root": "0xabcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "voluntary_exit": {
                "epoch": "100",
                "validator_index": "5"
            }
        }"""

        request = sign_request_decoder.decode(json_data)
        assert isinstance(request, VoluntaryExitSignRequest)
        assert request.voluntary_exit.epoch == "100"
        assert request.voluntary_exit.validator_index == "5"

    def test_parse_block_v2_request(self) -> None:
        """Test parsing a BLOCK_V2 sign request."""
        json_data = b"""{
            "type": "BLOCK_V2",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "signing_root": "0xabcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "beacon_block": {
                "version": "phase0",
                "block": {
                    "slot": "100",
                    "proposer_index": "0",
                    "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "body": {}
                }
            }
        }"""

        request = sign_request_decoder.decode(json_data)
        assert isinstance(request, BlockV2SignRequest)
        assert request.beacon_block["version"] == "phase0"

    def test_parse_without_signing_root(self) -> None:
        """Test parsing a request without signing_root (optional field)."""
        json_data = b"""{
            "type": "ATTESTATION",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "source": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                "target": {"epoch": "1", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"}
            }
        }"""

        request = sign_request_decoder.decode(json_data)
        assert isinstance(request, AttestationSignRequest)
        assert request.signing_root is None

    def test_parse_invalid_type(self) -> None:
        """Test parsing a request with invalid type fails."""
        json_data = b"""{
            "type": "INVALID_TYPE",
            "fork_info": {
                "fork": {
                    "previous_version": "0x00000000",
                    "current_version": "0x00000000",
                    "epoch": "0"
                },
                "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
            }
        }"""

        with pytest.raises(msgspec.ValidationError):
            sign_request_decoder.decode(json_data)

    def test_parse_missing_fork_info(self) -> None:
        """Test parsing a request without fork_info fails."""
        json_data = b"""{
            "type": "ATTESTATION",
            "signing_root": "0xabcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "source": {"epoch": "0", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"},
                "target": {"epoch": "1", "root": "0x0000000000000000000000000000000000000000000000000000000000000000"}
            }
        }"""

        with pytest.raises(msgspec.ValidationError):
            sign_request_decoder.decode(json_data)


class TestGetDomainForRequest:
    """Tests for get_domain_for_request function."""

    def test_attestation_domain(self) -> None:
        """ATTESTATION should return DOMAIN_BEACON_ATTESTER."""
        request = AttestationSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            attestation=AttestationData(
                slot="1",
                index="0",
                beacon_block_root="0x0",
                source={"epoch": "0", "root": "0x0"},
                target={"epoch": "0", "root": "0x0"},
            ),
        )
        assert get_domain_for_request(request) == DOMAIN_BEACON_ATTESTER

    def test_randao_domain(self) -> None:
        """RANDAO_REVEAL should return DOMAIN_RANDAO."""
        request = RandaoRevealSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            randao_reveal=RandaoReveal(epoch="100"),
        )
        assert get_domain_for_request(request) == DOMAIN_RANDAO

    def test_voluntary_exit_domain(self) -> None:
        """VOLUNTARY_EXIT should return DOMAIN_VOLUNTARY_EXIT."""
        request = VoluntaryExitSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            voluntary_exit=VoluntaryExit(epoch="100", validator_index="5"),
        )
        assert get_domain_for_request(request) == DOMAIN_VOLUNTARY_EXIT

    def test_block_v2_domain(self) -> None:
        """BLOCK_V2 should return DOMAIN_BEACON_PROPOSER."""
        request = BlockV2SignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            beacon_block={"version": "phase0", "block": {}},
        )
        assert get_domain_for_request(request) == DOMAIN_BEACON_PROPOSER

    def test_deposit_domain(self) -> None:
        """DEPOSIT should return DOMAIN_DEPOSIT."""
        request = DepositSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            deposit=DepositData(
                pubkey="0x0",
                withdrawal_credentials="0x0",
                amount="32000000000",
                genesis_fork_version="0x00000000",
            ),
        )
        assert get_domain_for_request(request) == DOMAIN_DEPOSIT

    def test_aggregation_slot_domain(self) -> None:
        """AGGREGATION_SLOT should return DOMAIN_SELECTION_PROOF."""
        request = AggregationSlotSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            aggregation_slot=AggregationSlot(slot="100"),
        )
        assert get_domain_for_request(request) == DOMAIN_SELECTION_PROOF

    def test_sync_committee_message_domain(self) -> None:
        """SYNC_COMMITTEE_MESSAGE should return DOMAIN_SYNC_COMMITTEE."""
        request = SyncCommitteeMessageSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            sync_committee_message=SyncCommitteeMessageData(
                slot="100",
                beacon_block_root="0x0",
            ),
        )
        assert get_domain_for_request(request) == DOMAIN_SYNC_COMMITTEE

    def test_sync_committee_selection_proof_domain(self) -> None:
        """SYNC_COMMITTEE_SELECTION_PROOF should return DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF."""
        request = SyncCommitteeSelectionProofSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            sync_aggregator_selection_data=SyncAggregatorSelectionData(
                slot="100",
                subcommittee_index="0",
            ),
        )
        assert get_domain_for_request(request) == DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF

    def test_validator_registration_domain(self) -> None:
        """VALIDATOR_REGISTRATION should return DOMAIN_APPLICATION_MASK."""
        from py3signer.signing_types import ValidatorRegistration

        request = ValidatorRegistrationSignRequest(
            fork_info=ForkInfo(
                fork=Fork(previous_version="0x0", current_version="0x0", epoch="0"),
                genesis_validators_root="0x0",
            ),
            signing_root="0x" + "00" * 32,
            validator_registration=ValidatorRegistration(
                fee_recipient="0x0",
                gas_limit="30000000",
                timestamp="1234567890",
                pubkey="0x0",
            ),
        )
        assert get_domain_for_request(request) == DOMAIN_APPLICATION_MASK


class TestValidateSigningRoot:
    """Tests for validate_signing_root function."""

    def test_valid_signing_root_with_prefix(self) -> None:
        """Test validating a signing root with 0x prefix."""
        result = validate_signing_root("0x" + "ab" * 32)
        assert result == b"\xab" * 32

    def test_valid_signing_root_without_prefix(self) -> None:
        """Test validating a signing root without 0x prefix."""
        result = validate_signing_root("ab" * 32)
        assert result == b"\xab" * 32

    def test_none_signing_root(self) -> None:
        """Test validating None returns None."""
        result = validate_signing_root(None)
        assert result is None

    def test_invalid_length(self) -> None:
        """Test validating a signing root with wrong length fails."""
        with pytest.raises(ValueError, match="32 bytes"):
            validate_signing_root("0xabcd")

    def test_invalid_hex(self) -> None:
        """Test validating non-hex signing root fails."""
        with pytest.raises(ValueError, match="valid hexadecimal"):
            validate_signing_root("0x" + "zz" * 32)


class TestAllSigningTypes:
    """Test that all signing type discriminators work."""

    @pytest.mark.parametrize(
        "type_name,expected_class",
        [
            ("AGGREGATION_SLOT", AggregationSlotSignRequest),
            ("AGGREGATE_AND_PROOF", AggregateAndProofSignRequest),
            ("AGGREGATE_AND_PROOF_V2", AggregateAndProofV2SignRequest),
            ("ATTESTATION", AttestationSignRequest),
            ("BLOCK", BlockSignRequest),
            ("BLOCK_V2", BlockV2SignRequest),
            ("DEPOSIT", DepositSignRequest),
            ("RANDAO_REVEAL", RandaoRevealSignRequest),
            ("VOLUNTARY_EXIT", VoluntaryExitSignRequest),
            ("SYNC_COMMITTEE_MESSAGE", SyncCommitteeMessageSignRequest),
            ("SYNC_COMMITTEE_SELECTION_PROOF", SyncCommitteeSelectionProofSignRequest),
            (
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                SyncCommitteeContributionAndProofSignRequest,
            ),
            ("VALIDATOR_REGISTRATION", ValidatorRegistrationSignRequest),
        ],
    )
    def test_all_types_discriminate(self, type_name: str, expected_class: type) -> None:
        """Test that each type discriminator creates the correct class."""
        # Build minimal valid JSON for each type
        base_json: dict[str, Any] = {
            "fork_info": {
                "fork": {
                    "previous_version": "0x0",
                    "current_version": "0x0",
                    "epoch": "0",
                },
                "genesis_validators_root": "0x0",
            },
            "signing_root": "0x" + "00" * 32,
        }

        # Add type-specific required fields
        type_data: dict[str, dict[str, Any]] = {
            "AGGREGATION_SLOT": {"aggregation_slot": {"slot": "1"}},
            "AGGREGATE_AND_PROOF": {
                "aggregate_and_proof": {
                    "aggregator_index": "1",
                    "aggregate": {},
                    "selection_proof": "0x0",
                },
            },
            "AGGREGATE_AND_PROOF_V2": {"aggregate_and_proof": {}},
            "ATTESTATION": {
                "attestation": {
                    "slot": "1",
                    "index": "0",
                    "beacon_block_root": "0x0",
                    "source": {},
                    "target": {},
                },
            },
            "BLOCK": {"block": {}},
            "BLOCK_V2": {"beacon_block": {}},
            "DEPOSIT": {
                "deposit": {
                    "pubkey": "0x0",
                    "withdrawal_credentials": "0x0",
                    "amount": "32000000000",
                    "genesis_fork_version": "0x0",
                },
            },
            "RANDAO_REVEAL": {"randao_reveal": {"epoch": "1"}},
            "VOLUNTARY_EXIT": {
                "voluntary_exit": {"epoch": "1", "validator_index": "0"},
            },
            "SYNC_COMMITTEE_MESSAGE": {
                "sync_committee_message": {
                    "slot": "1",
                    "beacon_block_root": "0x0",
                },
            },
            "SYNC_COMMITTEE_SELECTION_PROOF": {
                "sync_aggregator_selection_data": {
                    "slot": "1",
                    "subcommittee_index": "0",
                },
            },
            "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": {
                "contribution_and_proof": {
                    "aggregator_index": "1",
                    "contribution": {},
                    "selection_proof": "0x0",
                },
            },
            "VALIDATOR_REGISTRATION": {
                "validator_registration": {
                    "fee_recipient": "0x0",
                    "gas_limit": "30000000",
                    "timestamp": "1",
                    "pubkey": "0x0",
                },
            },
        }

        base_json["type"] = type_name
        base_json.update(type_data[type_name])

        json_bytes = msgspec.json.encode(base_json)
        request = sign_request_decoder.decode(json_bytes)

        assert isinstance(request, expected_class)
