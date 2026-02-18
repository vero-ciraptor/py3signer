"""Test fixtures and utilities."""

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from py3signer.config import Config
from py3signer.server import create_app
from py3signer.storage import KeyStorage


@pytest.fixture
def config() -> Config:
    """Create a test configuration."""
    return Config(
        host="127.0.0.1",
        port=8080,
        log_level="DEBUG"
    )


@pytest.fixture
def storage() -> KeyStorage:
    """Create a fresh key storage."""
    storage = KeyStorage()
    yield storage
    storage.clear()


@pytest_asyncio.fixture
async def client(config: Config):
    """Create a test client."""
    app = create_app(config)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


@pytest.fixture
def sample_keystore() -> dict:
    """Return a sample EIP-2335 keystore for testing."""
    return {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e8462a8d5b1663e21e0"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f5d6237fe8e0bd504c252495c"
                },
                "message": "06ae90d9fe2f6c66c34d5e5afb0e71f2"
            }
        },
        "description": "Test keystore",
        "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
        "path": "m/12381/3600/0/0/0",
        "uuid": "f1b49410-fd1d-41fd-a222-340f74867fa9",
        "version": 4
    }


@pytest.fixture
def sample_keystore_password() -> str:
    """Return the password for the sample keystore."""
    return "testpassword123"
