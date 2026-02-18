"""Tests for API endpoints."""

import json
import pytest
from aiohttp import web


@pytest.mark.asyncio
async def test_health_endpoint(client):
    """Test the health check endpoint."""
    resp = await client.get("/health")
    assert resp.status == 200
    
    data = await resp.json()
    assert data["status"] == "healthy"
    assert "keys_loaded" in data
    assert data["keys_loaded"] == 0


@pytest.mark.asyncio
async def test_list_empty_keystores(client):
    """Test listing keystores when none are loaded."""
    resp = await client.get("/eth/v1/keystores")
    assert resp.status == 200
    
    data = await resp.json()
    assert data["data"] == []


@pytest.mark.asyncio
async def test_import_keystore_invalid_json(client):
    """Test importing with invalid JSON."""
    resp = await client.post(
        "/eth/v1/keystores",
        data="not json",
        headers={"Content-Type": "application/json"}
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_import_keystore_mismatched_arrays(client):
    """Test importing with mismatched keystores/passwords."""
    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": ["keystore1"],
            "passwords": ["pass1", "pass2"]
        }
    )
    assert resp.status == 400
    
    data = await resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_import_keystore_empty_arrays(client):
    """Test importing with empty arrays."""
    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [],
            "passwords": []
        }
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_import_keystore_success(client, sample_keystore, sample_keystore_password):
    """Test successful keystore import."""
    keystore_json = json.dumps(sample_keystore)
    
    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": [sample_keystore_password]
        }
    )
    assert resp.status == 200
    
    data = await resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["status"] == "imported"


@pytest.mark.asyncio
async def test_import_keystore_wrong_password(client, sample_keystore):
    """Test importing with wrong password."""
    keystore_json = json.dumps(sample_keystore)
    
    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": ["wrongpassword"]
        }
    )
    assert resp.status == 200
    
    data = await resp.json()
    assert data["data"][0]["status"] == "error"


@pytest.mark.asyncio
async def test_list_keystores_after_import(client, sample_keystore, sample_keystore_password):
    """Test listing keystores after importing."""
    # First import a keystore
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": [sample_keystore_password]
        }
    )
    
    # Then list
    resp = await client.get("/eth/v1/keystores")
    assert resp.status == 200
    
    data = await resp.json()
    assert len(data["data"]) == 1
    assert data["data"][0]["validating_pubkey"] == sample_keystore["pubkey"]
    assert data["data"][0]["derivation_path"] == sample_keystore["path"]


@pytest.mark.asyncio
async def test_delete_keystore(client, sample_keystore, sample_keystore_password):
    """Test deleting a keystore."""
    # First import
    keystore_json = json.dumps(sample_keystore)
    await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": [sample_keystore_password]
        }
    )
    
    # Then delete
    resp = await client.delete(
        "/eth/v1/keystores",
        json={"pubkeys": [sample_keystore["pubkey"]]}
    )
    assert resp.status == 200
    
    data = await resp.json()
    assert data["data"][0]["status"] == "deleted"
    
    # Verify it's gone
    resp = await client.get("/eth/v1/keystores")
    data = await resp.json()
    assert len(data["data"]) == 0


@pytest.mark.asyncio
async def test_delete_nonexistent_keystore(client):
    """Test deleting a keystore that doesn't exist."""
    resp = await client.delete(
        "/eth/v1/keystores",
        json={"pubkeys": ["a" * 96]}
    )
    assert resp.status == 200
    
    data = await resp.json()
    assert data["data"][0]["status"] == "not_found"


@pytest.mark.asyncio
async def test_delete_empty_pubkeys(client):
    """Test deleting with empty pubkeys array."""
    resp = await client.delete(
        "/eth/v1/keystores",
        json={"pubkeys": []}
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_remote_keys_stub(client):
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
async def test_sign_missing_identifier(client):
    """Test signing without identifier."""
    resp = await client.post("/api/v1/eth2/sign/", json={})
    assert resp.status in [404, 405]  # Route not found or method not allowed


@pytest.mark.asyncio
async def test_sign_missing_signing_root(client):
    """Test signing without signingRoot."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={}
    )
    assert resp.status == 400
    
    data = await resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_sign_key_not_found(client):
    """Test signing with non-existent key."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "signingRoot": "abcd1234" * 8,  # 64 hex chars = 32 bytes
            "domainName": "beacon_attester"
        }
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_sign_invalid_hex(client):
    """Test signing with invalid hex."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={"signingRoot": "not_hex", "domain_name": "beacon_attester"}
    )
    assert resp.status == 400
    
    data = await resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_sign_wrong_signing_root_length(client):
    """Test signing with wrong signing root length."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "signingRoot": "abcd1234",  # Too short
            "domain_name": "beacon_attester"
        }
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_sign_no_domain_or_name(client):
    """Test signing without domain or domain_name."""
    pubkey = "a" * 96
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "signingRoot": "abcd1234" * 8
            # No domain or domain_name
        }
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_full_flow(client, sample_keystore, sample_keystore_password):
    """Test the full import -> list -> sign -> delete flow."""
    # 1. Import
    keystore_json = json.dumps(sample_keystore)
    resp = await client.post(
        "/eth/v1/keystores",
        json={
            "keystores": [keystore_json],
            "passwords": [sample_keystore_password]
        }
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
    
    # 3. Sign
    signing_root = "0x" + "00" * 32  # 32 bytes of zeros
    resp = await client.post(
        f"/api/v1/eth2/sign/{pubkey}",
        json={
            "signingRoot": signing_root,
            "domainName": "beacon_attester"
        }
    )
    assert resp.status == 200
    data = await resp.json()
    assert "signature" in data
    assert data["signature"].startswith("0x")
    assert len(data["signature"]) == 194  # 0x + 96 bytes * 2 = 194
    
    # 4. Delete
    resp = await client.delete(
        "/eth/v1/keystores",
        json={"pubkeys": [pubkey]}
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["data"][0]["status"] == "deleted"
    
    # 5. Verify deleted
    resp = await client.get("/eth/v1/keystores")
    assert resp.status == 200
    data = await resp.json()
    assert len(data["data"]) == 0


@pytest.mark.asyncio
async def test_auth_token_required():
    """Test that auth token is required when configured."""
    from py3signer.config import Config
    from py3signer.server import create_app
    from aiohttp.test_utils import TestClient, TestServer
    
    config = Config(
        host="127.0.0.1",
        port=8080,
        auth_token="secret_token"
    )
    
    app = create_app(config)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    
    try:
        # Request without auth should fail
        resp = await client.get("/eth/v1/keystores")
        assert resp.status == 401
        
        # Request with wrong auth should fail
        resp = await client.get(
            "/eth/v1/keystores",
            headers={"Authorization": "Bearer wrong_token"}
        )
        assert resp.status == 401
        
        # Request with correct auth should succeed
        resp = await client.get(
            "/eth/v1/keystores",
            headers={"Authorization": "Bearer secret_token"}
        )
        assert resp.status == 200
    finally:
        await client.close()
