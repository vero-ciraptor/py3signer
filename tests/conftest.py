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


import json
from pathlib import Path

@pytest.fixture
def sample_keystore() -> dict:
    """Return a sample EIP-2335 keystore for testing.
    
    This is a real, valid keystore that can be decrypted with
    the password from sample_keystore_password fixture.
    Uses scrypt KDF with N=262144.
    """
    # Load the pre-generated scrypt keystore from test data
    keystore_path = Path(__file__).parent / "data" / "test_keystore_scrypt.json"
    with open(keystore_path) as f:
        return json.load(f)


@pytest.fixture
def sample_keystore_password() -> str:
    """Return the password for the sample keystore."""
    return "testpassword123"
