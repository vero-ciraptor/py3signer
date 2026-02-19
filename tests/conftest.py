"""Test fixtures and utilities."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from litestar.testing import AsyncTestClient

from py3signer.config import Config
from py3signer.server import create_app
from py3signer.storage import KeyStorage

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator


@pytest.fixture
def config() -> Config:
    """Create a test configuration."""
    return Config(host="127.0.0.1", port=8080, log_level="DEBUG")


@pytest.fixture
def config_with_data_dir(tmp_path: Path) -> Config:
    """Create a test configuration with a data directory."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return Config(
        host="127.0.0.1",
        port=8080,
        log_level="DEBUG",
        data_dir=data_dir,
    )


@pytest.fixture
def storage() -> Generator[KeyStorage]:
    """Create a fresh key storage."""
    storage = KeyStorage()
    yield storage
    storage.clear()


@pytest.fixture
def storage_with_data_dir(tmp_path: Path) -> Generator[KeyStorage]:
    """Create a key storage with a data directory."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    storage = KeyStorage(data_dir=data_dir)
    yield storage
    storage.clear()


@pytest.fixture
async def client(config: Config) -> AsyncGenerator[AsyncTestClient]:
    """Create a test client."""
    app = create_app(config)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.fixture
async def client_with_persistence(
    config_with_data_dir: Config,
) -> AsyncGenerator[AsyncTestClient]:
    """Create a test client with keystore persistence enabled."""
    app = create_app(config_with_data_dir)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.fixture
def sample_keystore() -> dict[str, Any]:
    """Return a sample EIP-2335 keystore for testing.

    This is a real, valid keystore that can be decrypted with
    the password from sample_keystore_password fixture.
    Uses scrypt KDF with N=262144.
    """
    # Load the pre-generated scrypt keystore from test data
    keystore_path = Path(__file__).parent / "data" / "test_keystore_scrypt.json"
    with keystore_path.open() as f:
        data: dict[str, Any] = json.load(f)
        return data


@pytest.fixture
def sample_keystore_password() -> str:
    """Return the password for the sample keystore."""
    return "testpassword123"
