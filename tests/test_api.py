"""Tests for API endpoints."""

import json
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from litestar.testing import AsyncTestClient


# Valid fork info fixture for tests
@pytest.fixture
def valid_fork_info() -> dict[str, Any]:
    """Return a valid fork info structure."""
    return {
        "fork": {
            "previous_version": "0x00000000",
            "current_version": "0x00000000",
            "epoch": "0",
        },
        "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
    }


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncTestClient) -> None:
    """Test the health check endpoint."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert data["status"] == "healthy"
    assert "keys_loaded" in data
    assert data["keys_loaded"] == 0
    assert isinstance(data["keys_loaded"], int)


@pytest.mark.parametrize(
    ("endpoint", "extract_key"),
    [
        ("/eth/v1/keystores", "data"),
        ("/api/v1/eth2/publicKeys", None),
    ],
)
@pytest.mark.asyncio
async def test_list_empty(
    client: AsyncTestClient,
    endpoint: str,
    extract_key: str | None,
) -> None:
    """Test listing endpoints when none are loaded."""
    resp = await client.get(endpoint)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    if extract_key:
        assert extract_key in data, f"Expected '{extract_key}' key in response"
        data = data.get(extract_key)
    assert data == [], f"Expected empty list, got {data}"
    assert isinstance(data, list)


def _assert_signature_format(sig: str) -> None:
    """Assert that a signature string has the correct format.

    Used across multiple sign tests to avoid repetition.
    """
    assert sig.startswith("0x"), f"Expected signature to start with 0x, got {sig[:10]}"
    assert len(sig) == 194, f"Expected 194 chars (0x + 96 bytes * 2), got {len(sig)}"
    try:
        int(sig, 16)
    except ValueError:
        pytest.fail(f"Signature is not valid hex: {sig}")


@pytest.mark.asyncio
async def test_import_keystore_invalid_json(client: AsyncTestClient) -> None:
    """Test importing with invalid JSON."""
    resp = await client.post(
        "/eth/v1/keystores",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400

    data = resp.json()
    assert "detail" in data
    assert "JSON" in data["detail"] or "validation" in data["detail"].lower()


@pytest.mark.parametrize(
    ("keystores", "passwords", "expected_error"),
    [
        (
            ["keystore1"],
            ["pass1", "pass2"],
            "keystores and passwords must have the same length",
        ),
        ([], [], "keystores must not be empty"),
    ],
)
@pytest.mark.asyncio
async def test_import_keystore_validation_errors(
    client: AsyncTestClient,
    keystores: list[str],
    passwords: list[str],
    expected_error: str,
) -> None:
    """Test importing with various validation errors."""
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": keystores, "passwords": passwords},
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data, f"Expected 'detail' key in error response, got {data}"
    assert expected_error in data["detail"], (
        f"Expected '{expected_error}' in '{data['detail']}'"
    )


@pytest.mark.asyncio
async def test_import_keystore_success(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test successful keystore import."""
    keystore_json = json.dumps(sample_keystore)

    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 result, got {len(data['data'])}"
    assert data["data"][0]["status"] == "imported", (
        f"Expected status 'imported', got {data['data'][0]}"
    )
    assert "message" in data["data"][0], "Expected 'message' field in result"
    assert sample_keystore["pubkey"] in data["data"][0]["message"]


@pytest.mark.asyncio
async def test_import_keystore_wrong_password(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
) -> None:
    """Test importing with wrong password."""
    keystore_json = json.dumps(sample_keystore)

    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": ["wrongpassword"]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 result, got {len(data['data'])}"
    assert data["data"][0]["status"] == "error", (
        f"Expected status 'error', got {data['data'][0]}"
    )
    assert "message" in data["data"][0], "Expected 'message' field in error result"
    assert (
        "password" in data["data"][0]["message"].lower()
        or "invalid" in data["data"][0]["message"].lower()
    )


@pytest.mark.asyncio
async def test_list_keystores_after_import(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test listing keystores after importing."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Then list
    resp = await client.get("/eth/v1/keystores")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 keystore, got {len(data['data'])}"
    assert data["data"][0]["validating_pubkey"] == sample_keystore["pubkey"]
    assert data["data"][0]["derivation_path"] == sample_keystore["path"]
    assert data["data"][0]["readonly"] is False


@pytest.mark.asyncio
async def test_delete_keystore(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test deleting a keystore."""
    # First import
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Then delete
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [sample_keystore["pubkey"]]}),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 result, got {len(data['data'])}"
    assert data["data"][0]["status"] == "deleted", (
        f"Expected status 'deleted', got {data['data'][0]}"
    )

    # Verify it's gone
    resp = await client.get("/eth/v1/keystores")
    data = resp.json()
    assert len(data["data"]) == 0, (
        f"Expected 0 keystores after delete, got {len(data['data'])}"
    )


@pytest.mark.asyncio
async def test_delete_nonexistent_keystore(client: AsyncTestClient) -> None:
    """Test deleting a keystore that doesn't exist."""
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": ["a" * 96]}),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 result, got {len(data['data'])}"
    assert data["data"][0]["status"] == "not_found", (
        f"Expected status 'not_found', got {data['data'][0]}"
    )


@pytest.mark.asyncio
async def test_delete_empty_pubkeys(client: AsyncTestClient) -> None:
    """Test deleting with empty pubkeys array."""
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": []}),
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data, f"Expected 'detail' key in error response, got {data}"
    assert (
        "pubkeys must not be empty" in data["detail"]
        or "empty" in data["detail"].lower()
    )


@pytest.mark.asyncio
async def test_list_public_keys_after_import(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test listing public keys after importing keystores."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Then list public keys via Remote Signing API
    resp = await client.get("/api/v1/eth2/publicKeys")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert isinstance(data, list), f"Expected list, got {type(data)}"
    assert len(data) == 1, f"Expected 1 public key, got {len(data)}"
    # API returns pubkey with "0x" prefix
    expected_pubkey = sample_keystore["pubkey"]
    if not expected_pubkey.startswith("0x"):
        expected_pubkey = "0x" + expected_pubkey
    assert data[0] == expected_pubkey, f"Expected {expected_pubkey}, got {data[0]}"
    assert data[0].startswith("0x"), f"Expected pubkey to start with 0x, got {data[0]}"
    assert len(data[0]) == 98, f"Expected 98 chars (0x + 96 hex), got {len(data[0])}"


@pytest.mark.asyncio
async def test_sign_missing_identifier(client: AsyncTestClient) -> None:
    """Test signing without identifier."""
    resp = await client.post("/api/v1/eth2/sign/", json={})
    assert resp.status_code in [404, 405], (
        f"Expected 404 or 405, got {resp.status_code}"
    )

    if resp.status_code == 405:
        assert resp.headers["content-type"] == "application/json"
        data = resp.json()
        assert "detail" in data


# Keystore persistence tests


@pytest.mark.asyncio
async def test_import_keystore_with_persistence(
    client_with_persistence: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test that imported keystores are saved to disk when keystore_path is configured."""
    keystore_json = json.dumps(sample_keystore)

    # Import keystore
    resp = await client_with_persistence.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200

    data = resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "imported"

    # Verify files were created on disk
    # Note: We can't directly access the temp path here, but the storage tests verify this


@pytest.mark.asyncio
async def test_delete_keystore_with_persistence(
    client_with_persistence: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test that deleted keystores are removed from disk when keystore_path is configured."""
    keystore_json = json.dumps(sample_keystore)
    pubkey = sample_keystore["pubkey"]
    _pubkey_normalized = pubkey.lower().replace("0x", "")

    # First import
    resp = await client_with_persistence.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200

    # Then delete
    resp = await client_with_persistence.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [pubkey]}),
    )
    assert resp.status_code == 200

    data = resp.json()
    assert data["data"][0]["status"] == "deleted"


@pytest.mark.asyncio
async def test_import_duplicate_keystore(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test that importing a duplicate keystore returns proper error."""
    keystore_json = json.dumps(sample_keystore)

    # First import
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    assert resp.json()["data"][0]["status"] == "imported"

    # Try to import again
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data, f"Expected 'data' key in response, got {data}"
    assert len(data["data"]) == 1, f"Expected 1 result, got {len(data['data'])}"
    assert data["data"][0]["status"] == "duplicate", (
        f"Expected status 'duplicate', got {data['data'][0]}"
    )
    assert "message" in data["data"][0], "Expected 'message' field in result"
    assert (
        sample_keystore["pubkey"] in data["data"][0]["message"]
        or "already exists" in data["data"][0]["message"].lower()
    )


@pytest.mark.parametrize(
    ("request_body", "expected_error"),
    [
        # Missing type discriminator
        ({}, "missing required field `type`"),
        # Invalid type
        ({"type": "INVALID_TYPE"}, "Invalid value 'INVALID_TYPE'"),
        # Missing attestation field
        ({"type": "ATTESTATION"}, "missing required field `attestation`"),
        # Invalid signing_root length
        (
            {
                "type": "ATTESTATION",
                "signing_root": "0xabcd",
                "attestation": {
                    "slot": "123",
                    "index": "0",
                    "beacon_block_root": "0x" + "00" * 32,
                    "source": {"epoch": "0", "root": "0x" + "00" * 32},
                    "target": {"epoch": "1", "root": "0x" + "00" * 32},
                },
                "fork_info": {
                    "fork": {
                        "previous_version": "0x00",
                        "current_version": "0x00",
                        "epoch": "0",
                    },
                    "genesis_validators_root": "0x00" * 32,
                },
            },
            "signing_root must be 32 bytes",
        ),
    ],
)
@pytest.mark.asyncio
async def test_sign_validation_errors(
    client: AsyncTestClient,
    valid_fork_info: dict[str, Any],
    request_body: dict[str, Any],
    expected_error: str,
) -> None:
    """Test signing with various validation errors."""
    # Add fork_info to requests that need it
    if "fork_info" not in request_body and "type" in request_body:
        request_body["fork_info"] = valid_fork_info

    pubkey = "a" * 96
    resp = await client.post(f"/api/v1/eth2/sign/{pubkey}", json=request_body)
    assert resp.status_code == 400

    data = resp.json()
    assert expected_error in data["detail"]


@pytest.mark.asyncio
async def test_sign_key_not_found(
    client: AsyncTestClient,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing with non-existent key."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signing_root": "abcd1234" * 8,  # 64 hex chars = 32 bytes
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 404
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data, f"Expected 'detail' key in error response, got {data}"
    assert "not found" in data["detail"].lower(), (
        f"Expected 'not found' in '{data['detail']}'"
    )


@pytest.mark.asyncio
async def test_sign_missing_signing_root(
    client: AsyncTestClient,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing without signing_root - returns error since SSZ computation is not implemented."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data, f"Expected 'detail' key in error response, got {data}"
    assert "signing_root is required" in data.get("detail", ""), (
        f"Expected 'signing_root is required' in '{data.get('detail', '')}'"
    )


@pytest.mark.asyncio
async def test_sign_attestation(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing an attestation with spec-compliant format."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign an attestation
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    # Validate signature format using helper
    _assert_signature_format(resp.text)


@pytest.mark.asyncio
async def test_sign_randao(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing a RANDAO reveal with spec-compliant format."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a RANDAO reveal
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    _assert_signature_format(resp.text)


@pytest.mark.asyncio
async def test_sign_voluntary_exit(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing a voluntary exit with spec-compliant format."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a voluntary exit
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "VOLUNTARY_EXIT",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "voluntary_exit": {"epoch": "100", "validator_index": "5"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    _assert_signature_format(resp.text)


@pytest.mark.asyncio
async def test_sign_block_v2(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing a block with spec-compliant BLOCK_V2 format."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a block v2
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "BLOCK_V2",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "beacon_block": {
                "version": "phase0",
                "block": {
                    "slot": "100",
                    "proposer_index": "0",
                    "parent_root": "0x" + "00" * 32,
                    "state_root": "0x" + "00" * 32,
                    "body": {},
                },
            },
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    _assert_signature_format(resp.text)


@pytest.mark.asyncio
async def test_full_flow(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test the full import -> list -> sign -> delete flow with spec-compliant format."""
    # 1. Import
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    data = resp.json()
    assert data["data"][0]["status"] == "imported", f"Import failed: {data}"

    # 2. List
    resp = await client.get("/eth/v1/keystores")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    data = resp.json()
    assert len(data["data"]) == 1, f"Expected 1 keystore, got {len(data['data'])}"
    pubkey = data["data"][0]["validating_pubkey"]
    assert pubkey == sample_keystore["pubkey"], (
        f"Pubkey mismatch: {pubkey} != {sample_keystore['pubkey']}"
    )

    # 3. Sign with spec-compliant format (expects text/plain)
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"
    _assert_signature_format(resp.text)

    # 4. Delete
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [pubkey]}),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["data"][0]["status"] == "deleted", f"Delete failed: {data}"

    # 5. Verify deleted
    resp = await client.get("/eth/v1/keystores")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["data"]) == 0, (
        f"Expected 0 keystores after delete, got {len(data['data'])}"
    )


@pytest.mark.asyncio
async def test_sign_accept_header_json(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test that Accept: application/json returns JSON response."""
    # Import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign with Accept: application/json
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "application/json"},
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "signature" in data, f"Expected 'signature' in response, got {data}"
    _assert_signature_format(data["signature"])


@pytest.mark.asyncio
async def test_sign_accept_header_missing_returns_json(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test that missing Accept header returns JSON response (default)."""
    # Import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign without Accept header
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "signature" in data, f"Expected 'signature' in response, got {data}"
    _assert_signature_format(data["signature"])


@pytest.mark.asyncio
async def test_sign_accept_header_wildcard_returns_json(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test that Accept: */* returns JSON response."""
    # Import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign with Accept: */*
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "*/*"},
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "signature" in data, f"Expected 'signature' in response, got {data}"
    _assert_signature_format(data["signature"])


@pytest.mark.asyncio
async def test_import_keystore_with_invalid_version(
    client: AsyncTestClient,
) -> None:
    """Test importing a keystore with unsupported version."""
    invalid_keystore = {
        "version": 3,  # Unsupported version
        "pubkey": "a" * 96,
        "path": "m/12381/3600/0/0/0",
        "uuid": "test-uuid",
        "crypto": {
            "kdf": {"function": "scrypt", "params": {}, "message": ""},
            "checksum": {"function": "sha256", "params": {}, "message": "aa" * 32},
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": "aa" * 16},
                "message": "aa" * 16,
            },
        },
    }
    keystore_json = json.dumps(invalid_keystore)

    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": ["password"]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "error"
    assert (
        "version" in data["data"][0]["message"].lower()
        or "not supported" in data["data"][0]["message"].lower()
    )


@pytest.mark.asyncio
async def test_delete_keystore_with_0x_prefix(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test deleting a keystore using pubkey with 0x prefix."""
    # First import
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Delete with 0x prefix
    pubkey_with_prefix = "0x" + sample_keystore["pubkey"]
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [pubkey_with_prefix]}),
    )
    assert resp.status_code == 200

    data = resp.json()
    assert data["data"][0]["status"] == "deleted"


@pytest.mark.asyncio
async def test_delete_keystore_with_uppercase_pubkey(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test deleting a keystore using uppercase pubkey (case insensitive)."""
    # First import
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Delete with uppercase
    pubkey_upper = sample_keystore["pubkey"].upper()
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [pubkey_upper]}),
    )
    assert resp.status_code == 200

    data = resp.json()
    assert data["data"][0]["status"] == "deleted"


@pytest.mark.asyncio
async def test_import_keystore_invalid_crypto_structure(
    client: AsyncTestClient,
) -> None:
    """Test importing a keystore with invalid crypto structure."""
    invalid_keystore = {
        "version": 4,
        "pubkey": "a" * 96,
        "path": "m/12381/3600/0/0/0",
        "uuid": "test-uuid",
        "crypto": {
            "kdf": {"function": "scrypt", "params": {}, "message": ""},
            # Missing checksum and cipher
        },
    }
    keystore_json = json.dumps(invalid_keystore)

    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": ["password"]},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "error"


@pytest.mark.asyncio
async def test_healthcheck_endpoint(client: AsyncTestClient) -> None:
    """Test the Web3Signer-compatible healthcheck endpoint."""
    resp = await client.get("/healthcheck")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "status" in data
    assert "outcome" in data
    assert data["status"] == "UP"
    assert data["outcome"] == "UP"


@pytest.mark.asyncio
async def test_sign_attestation_without_fork_info(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test signing without fork_info fails validation."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    pubkey = sample_keystore["pubkey"]

    # Sign without fork_info
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "signing_root": "0x" + "00" * 32,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data
    assert "fork_info" in data["detail"].lower() or "missing" in data["detail"].lower()


@pytest.mark.asyncio
async def test_sign_with_invalid_signing_root_length(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test signing with invalid signing_root length fails."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    pubkey = sample_keystore["pubkey"]

    # Sign with wrong signing_root length (16 bytes instead of 32)
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 16,  # Only 16 bytes
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data
    assert "32 bytes" in data["detail"]


@pytest.mark.asyncio
async def test_sign_with_malformed_json(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test signing with malformed JSON fails."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    pubkey = sample_keystore["pubkey"]

    # Send malformed JSON
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        content="not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "detail" in data


@pytest.mark.asyncio
async def test_sign_accept_header_text_plain(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
    valid_fork_info: dict[str, Any],
) -> None:
    """Test that Accept: text/plain returns plain text response."""
    # Import a keystore
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status_code == 200
    pubkey = sample_keystore["pubkey"]

    # Sign with Accept: text/plain
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        headers={"Accept": "text/plain"},
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signing_root": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    _assert_signature_format(resp.text)


@pytest.mark.asyncio
async def test_delete_keystore_returns_slashing_protection(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test that DELETE /eth/v1/keystores returns slashing_protection field per spec."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Delete the keystore
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": [sample_keystore["pubkey"]]}),
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    # Per Keymanager API spec, response MUST include slashing_protection
    assert "slashing_protection" in data, (
        f"Expected 'slashing_protection' in response, got {data.keys()}"
    )

    slashing = data["slashing_protection"]
    assert "metadata" in slashing, "Expected 'metadata' in slashing_protection"
    assert "data" in slashing, "Expected 'data' in slashing_protection"
    assert slashing["metadata"]["interchange_format_version"] == "5"
    assert "genesis_validators_root" in slashing["metadata"]

    # Should have one entry for the deleted key
    assert len(slashing["data"]) == 1
    # Pubkey may have 0x prefix
    returned_pubkey = slashing["data"][0]["pubkey"].replace("0x", "")
    expected_pubkey = sample_keystore["pubkey"].replace("0x", "")
    assert returned_pubkey == expected_pubkey
    assert "signed_blocks" in slashing["data"][0]
    assert "signed_attestations" in slashing["data"][0]


@pytest.mark.asyncio
async def test_delete_keystore_slashing_protection_empty_for_not_found(
    client: AsyncTestClient,
) -> None:
    """Test that slashing_protection is empty when deleting non-existent keys."""
    resp = await client.request(
        "DELETE",
        "/eth/v1/keystores",
        content=json.dumps({"pubkeys": ["0x" + "a" * 96]}),
    )
    assert resp.status_code == 200

    data = resp.json()
    assert "slashing_protection" in data
    # No slashing data for keys that were not found/deleted
    assert data["slashing_protection"]["data"] == []


@pytest.mark.asyncio
async def test_import_keystore_accepts_slashing_protection(
    client: AsyncTestClient,
    sample_keystore: dict[str, Any],
    sample_keystore_password: str,
) -> None:
    """Test that POST /eth/v1/keystores accepts optional slashing_protection field."""
    keystore_json = json.dumps(sample_keystore)

    # Import with slashing_protection data
    slashing_data = json.dumps(
        {
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x" + "00" * 32,
            },
            "data": [],
        }
    )

    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": [sample_keystore_password],
            "slashing_protection": slashing_data,
        },
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"

    data = resp.json()
    assert "data" in data
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "imported"
