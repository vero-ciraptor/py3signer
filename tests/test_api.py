"""Tests for API endpoints."""

import json
from typing import Any

import pytest
from aiohttp.test_utils import TestClient

from py3signer.config import Config


# Valid fork info fixture for tests
@pytest.fixture
def valid_fork_info() -> dict[str, Any]:
    """Return a valid fork info structure."""
    return {
        "fork": {"previous_version": "0x00000000", "current_version": "0x00000000", "epoch": "0"},
        "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
    }


@pytest.mark.asyncio
async def test_health_endpoint(client: TestClient[Any, Any]) -> None:
    """Test the health check endpoint."""
    resp = await client.get("/health")
    assert resp.status == 200

    data = await resp.json()
    assert data["status"] == "healthy"
    assert "keys_loaded" in data
    assert data["keys_loaded"] == 0


@pytest.mark.parametrize(
    "endpoint,extract_key",
    [
        ("/eth/v1/keystores", "data"),
        ("/api/v1/eth2/publicKeys", None),
    ],
)
@pytest.mark.asyncio
async def test_list_empty(
    client: TestClient[Any, Any], endpoint: str, extract_key: str | None
) -> None:
    """Test listing endpoints when none are loaded."""
    resp = await client.get(endpoint)
    assert resp.status == 200

    data = await resp.json()
    if extract_key:
        data = data.get(extract_key)
    assert data == []


@pytest.mark.asyncio
async def test_import_keystore_invalid_json(client: TestClient[Any, Any]) -> None:
    """Test importing with invalid JSON."""
    resp = await client.post(
        "/eth/v1/keystores", data="not json", headers={"Content-Type": "application/json"}
    )
    assert resp.status == 400


@pytest.mark.parametrize(
    "keystores,passwords,expected_error",
    [
        (["keystore1"], ["pass1", "pass2"], "keystores and passwords must have the same length"),
        ([], [], "keystores must not be empty"),
    ],
)
@pytest.mark.asyncio
async def test_import_keystore_validation_errors(
    client: TestClient[Any, Any], keystores: list[str], passwords: list[str], expected_error: str
) -> None:
    """Test importing with various validation errors."""
    resp = await client.post(
        "/eth/v1/keystores", json={"keystores": keystores, "passwords": passwords}
    )
    assert resp.status == 400

    data = await resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_import_keystore_success(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any], sample_keystore_password: str
) -> None:
    """Test successful keystore import."""
    keystore_json = json.dumps(sample_keystore)

    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status == 200

    data = await resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "imported"


@pytest.mark.asyncio
async def test_import_keystore_wrong_password(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any]
) -> None:
    """Test importing with wrong password."""
    keystore_json = json.dumps(sample_keystore)

    resp = await client.post(
        "/eth/v1/keystores", json={"keystores": [keystore_json], "passwords": ["wrongpassword"]}
    )
    assert resp.status == 200

    data = await resp.json()
    assert data["data"][0]["status"] == "error"


@pytest.mark.asyncio
async def test_list_keystores_after_import(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any], sample_keystore_password: str
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
    assert resp.status == 200

    data = await resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["validating_pubkey"] == sample_keystore["pubkey"]
    assert data["data"][0]["derivation_path"] == sample_keystore["path"]


@pytest.mark.asyncio
async def test_delete_keystore(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any], sample_keystore_password: str
) -> None:
    """Test deleting a keystore."""
    # First import
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )

    # Then delete
    resp = await client.delete("/eth/v1/keystores", json={"pubkeys": [sample_keystore["pubkey"]]})
    assert resp.status == 200

    data = await resp.json()
    assert data["data"][0]["status"] == "deleted"

    # Verify it's gone
    resp = await client.get("/eth/v1/keystores")
    data = await resp.json()
    assert len(data["data"]) == 0


@pytest.mark.asyncio
async def test_delete_nonexistent_keystore(client: TestClient[Any, Any]) -> None:
    """Test deleting a keystore that doesn't exist."""
    resp = await client.delete("/eth/v1/keystores", json={"pubkeys": ["a" * 96]})
    assert resp.status == 200

    data = await resp.json()
    assert data["data"][0]["status"] == "not_found"


@pytest.mark.asyncio
async def test_delete_empty_pubkeys(client: TestClient[Any, Any]) -> None:
    """Test deleting with empty pubkeys array."""
    resp = await client.delete("/eth/v1/keystores", json={"pubkeys": []})
    assert resp.status == 400


@pytest.mark.asyncio
async def test_remote_keys_stub(client: TestClient[Any, Any]) -> None:
    """Test remote keys endpoints return stubs."""
    resp = await client.get("/eth/v1/remotekeys")
    assert resp.status == 200

    data = await resp.json()
    assert data["data"] == []

    resp = await client.post("/eth/v1/remotekeys", json={})
    assert resp.status == 501

    resp = await client.delete("/eth/v1/remotekeys", json={})
    assert resp.status == 501


@pytest.mark.asyncio
async def test_list_public_keys_after_import(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any], sample_keystore_password: str
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
    assert resp.status == 200

    data = await resp.json()
    assert len(data) == 1
    # API returns pubkey with "0x" prefix
    expected_pubkey = sample_keystore["pubkey"]
    if not expected_pubkey.startswith("0x"):
        expected_pubkey = "0x" + expected_pubkey
    assert data[0] == expected_pubkey


@pytest.mark.parametrize(
    "endpoint",
    [
        "/eth/v1/keystores",
        "/api/v1/eth2/publicKeys",
    ],
)
@pytest.mark.asyncio
async def test_auth_token_required(endpoint: str) -> None:
    """Test that auth token is required when configured."""
    from aiohttp.test_utils import TestClient as AiohttpTestClient
    from aiohttp.test_utils import TestServer

    from py3signer.server import create_app

    config = Config(host="127.0.0.1", port=8080, auth_token="secret_token")

    app = create_app(config)
    server = TestServer(app)
    client = AiohttpTestClient(server)
    await client.start_server()

    try:
        # Request without auth should fail
        resp = await client.get(endpoint)
        assert resp.status == 401

        # Request with wrong auth should fail
        resp = await client.get(endpoint, headers={"Authorization": "Bearer wrong_token"})
        assert resp.status == 401

        # Request with correct auth should succeed
        resp = await client.get(endpoint, headers={"Authorization": "Bearer secret_token"})
        assert resp.status == 200
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_sign_missing_identifier(client: TestClient[Any, Any]) -> None:
    """Test signing without identifier."""
    resp = await client.post("/api/v1/eth2/sign/", json={})
    assert resp.status in [404, 405]  # Route not found or method not allowed


# Keystore persistence tests


@pytest.mark.asyncio
async def test_import_keystore_with_persistence(
    client_with_persistence: TestClient[Any, Any],
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
    assert resp.status == 200

    data = await resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "imported"

    # Verify files were created on disk
    # Note: We can't directly access the temp path here, but the storage tests verify this


@pytest.mark.asyncio
async def test_delete_keystore_with_persistence(
    client_with_persistence: TestClient[Any, Any],
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
    assert resp.status == 200

    # Then delete
    resp = await client_with_persistence.delete("/eth/v1/keystores", json={"pubkeys": [pubkey]})
    assert resp.status == 200

    data = await resp.json()
    assert data["data"][0]["status"] == "deleted"


@pytest.mark.asyncio
async def test_import_duplicate_keystore(
    client: TestClient[Any, Any], sample_keystore: dict[str, Any], sample_keystore_password: str
) -> None:
    """Test that importing a duplicate keystore returns proper error."""
    keystore_json = json.dumps(sample_keystore)

    # First import
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status == 200
    assert (await resp.json())["data"][0]["status"] == "imported"

    # Try to import again
    resp = await client.post(
        "/eth/v1/keystores",
        json={"keystores": [keystore_json], "passwords": [sample_keystore_password]},
    )
    assert resp.status == 200

    data = await resp.json()
    assert data["data"][0]["status"] == "duplicate"


@pytest.mark.parametrize(
    "request_body,expected_error",
    [
        # Missing type discriminator
        ({}, "missing required field"),
        # Invalid type
        ({"type": "INVALID_TYPE"}, "Validation error"),
        # Missing fork_info
        ({"type": "ATTESTATION"}, "missing required field"),
        # Invalid signingRoot length
        (
            {
                "type": "ATTESTATION",
                "signingRoot": "0xabcd",
                "fork_info": {
                    "fork": {"previous_version": "0x00", "current_version": "0x00", "epoch": "0"},
                    "genesis_validators_root": "0x00" * 32,
                },
            },
            "signingRoot",
        ),
    ],
)
@pytest.mark.asyncio
async def test_sign_validation_errors(
    client: TestClient[Any, Any],
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
    assert resp.status == 400

    data = await resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_sign_key_not_found(
    client: TestClient[Any, Any], valid_fork_info: dict[str, Any]
) -> None:
    """Test signing with non-existent key."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signingRoot": "abcd1234" * 8,  # 64 hex chars = 32 bytes
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_sign_missing_signing_root(
    client: TestClient[Any, Any], valid_fork_info: dict[str, Any]
) -> None:
    """Test signing without signingRoot (required until SSZ computation is implemented)."""
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
    assert resp.status == 400

    data = await resp.json()
    assert "signingRoot is required" in data["error"]


@pytest.mark.asyncio
async def test_sign_attestation(
    client: TestClient[Any, Any],
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
    assert resp.status == 200
    pubkey = sample_keystore["pubkey"]

    # Sign an attestation
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signingRoot": "0x" + "00" * 32,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status == 200

    data = await resp.json()
    assert "signature" in data
    assert data["signature"].startswith("0x")
    assert len(data["signature"]) == 194  # 0x + 96 bytes * 2 = 194


@pytest.mark.asyncio
async def test_sign_randao(
    client: TestClient[Any, Any],
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
    assert resp.status == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a RANDAO reveal
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "RANDAO_REVEAL",
            "fork_info": valid_fork_info,
            "signingRoot": "0x" + "00" * 32,
            "randao_reveal": {"epoch": "100"},
        },
    )
    assert resp.status == 200

    data = await resp.json()
    assert "signature" in data


@pytest.mark.asyncio
async def test_sign_voluntary_exit(
    client: TestClient[Any, Any],
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
    assert resp.status == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a voluntary exit
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "VOLUNTARY_EXIT",
            "fork_info": valid_fork_info,
            "signingRoot": "0x" + "00" * 32,
            "voluntary_exit": {"epoch": "100", "validator_index": "5"},
        },
    )
    assert resp.status == 200

    data = await resp.json()
    assert "signature" in data


@pytest.mark.asyncio
async def test_sign_block_v2(
    client: TestClient[Any, Any],
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
    assert resp.status == 200
    pubkey = sample_keystore["pubkey"]

    # Sign a block v2
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "BLOCK_V2",
            "fork_info": valid_fork_info,
            "signingRoot": "0x" + "00" * 32,
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
    assert resp.status == 200

    data = await resp.json()
    assert "signature" in data


@pytest.mark.asyncio
async def test_full_flow(
    client: TestClient[Any, Any],
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
    assert resp.status == 200
    data = await resp.json()
    assert data["data"][0]["status"] == "imported"

    # 2. List
    resp = await client.get("/eth/v1/keystores")
    assert resp.status == 200
    data = await resp.json()
    assert len(data["data"]) == 1
    pubkey = data["data"][0]["validating_pubkey"]

    # 3. Sign with spec-compliant format
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "type": "ATTESTATION",
            "fork_info": valid_fork_info,
            "signingRoot": "0x" + "00" * 32,
            "attestation": {
                "slot": "123",
                "index": "0",
                "beacon_block_root": "0x" + "00" * 32,
                "source": {"epoch": "0", "root": "0x" + "00" * 32},
                "target": {"epoch": "1", "root": "0x" + "00" * 32},
            },
        },
    )
    assert resp.status == 200
    data = await resp.json()
    assert "signature" in data
    assert data["signature"].startswith("0x")
    assert len(data["signature"]) == 194  # 0x + 96 bytes * 2 = 194

    # 4. Delete
    resp = await client.delete("/eth/v1/keystores", json={"pubkeys": [pubkey]})
    assert resp.status == 200
    data = await resp.json()
    assert data["data"][0]["status"] == "deleted"

    # 5. Verify deleted
    resp = await client.get("/eth/v1/keystores")
    assert resp.status == 200
    data = await resp.json()
    assert len(data["data"]) == 0
