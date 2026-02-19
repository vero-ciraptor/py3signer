"""Test fixtures and utilities."""

import json
from collections.abc import AsyncGenerator, Generator
from pathlib import Path
from typing import Any

import pytest
from litestar.testing import AsyncTestClient

from py3signer.config import Config
from py3signer.server import create_app
from py3signer.storage import KeyStorage


@pytest.fixture
def config() -> Config:
    """Create a test configuration."""
    return Config(host="127.0.0.1", port=8080, log_level="DEBUG")


@pytest.fixture
def config_with_keystore_path(tmp_path: Path) -> Config:
    """Create a test configuration with a keystore path."""
    keystore_path = tmp_path / "keystores"
    keystore_path.mkdir()
    return Config(host="127.0.0.1", port=8080, log_level="DEBUG", key_store_path=keystore_path)


@pytest.fixture
def storage() -> Generator[KeyStorage, None, None]:
    """Create a fresh key storage."""
    storage = KeyStorage()
    yield storage
    storage.clear()


@pytest.fixture
async def client(config: Config) -> AsyncGenerator[AsyncTestClient, None]:
    """Create a test client."""
    app = create_app(config)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.fixture
async def client_with_persistence(
    config_with_keystore_path: Config,
) -> AsyncGenerator[AsyncTestClient, None]:
    """Create a test client with keystore persistence enabled."""
    app = create_app(config_with_keystore_path)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.fixture
async def client_with_input_only_keystores(
    tmp_path: Path,
) -> AsyncGenerator[AsyncTestClient, None]:
    """Create a test client with input-only keystores configured."""
    keystores_dir = tmp_path / "input_keystores"
    passwords_dir = tmp_path / "input_passwords"
    keystores_dir.mkdir()
    passwords_dir.mkdir()

    # Copy test keystore and create password file
    test_data = Path(__file__).parent / "data"
    keystore_data = json.loads((test_data / "test_keystore_scrypt.json").read_text())

    # Create keystore with unique pubkey
    keystore_data["pubkey"] = (
        "a792e85e01746b22e89c7289aa693c4413db2c83d1209380cc4e98fc132ba49c"
        "301606032f77089d90e2df0539d23037"
    )

    (keystores_dir / "test_keystore.json").write_text(json.dumps(keystore_data))
    (passwords_dir / "test_keystore.txt").write_text("testpassword123")

    config = Config(
        host="127.0.0.1",
        port=8080,
        log_level="DEBUG",
        keystores_path=keystores_dir,
        keystores_passwords_path=passwords_dir,
    )

    app = create_app(config)
    async with AsyncTestClient(app) as client:
        yield client


@pytest.fixture
async def client_with_both_keystore_types(
    tmp_path: Path,
) -> AsyncGenerator[AsyncTestClient, None]:
    """Create a test client with both persistent and input-only keystores."""
    # Persistent keystores
    key_store_dir = tmp_path / "keystore_store"
    key_store_dir.mkdir()

    # Input-only keystores
    keystores_dir = tmp_path / "input_keystores"
    passwords_dir = tmp_path / "input_passwords"
    keystores_dir.mkdir()
    passwords_dir.mkdir()

    test_data = Path(__file__).parent / "data"
    keystore_data = json.loads((test_data / "test_keystore_scrypt.json").read_text())

    # Create persistent keystore
    persistent_data = keystore_data.copy()
    persistent_data["pubkey"] = (
        "b792e85e01746b22e89c7289aa693c4413db2c83d1209380cc4e98fc132ba49c"
        "301606032f77089d90e2df0539d23038"
    )
    (key_store_dir / "persistent_keystore.json").write_text(json.dumps(persistent_data))
    (key_store_dir / "persistent_keystore.txt").write_text("testpassword123")

    # Create input-only keystore
    input_data = keystore_data.copy()
    input_data["pubkey"] = (
        "a792e85e01746b22e89c7289aa693c4413db2c83d1209380cc4e98fc132ba49c"
        "301606032f77089d90e2df0539d23037"
    )
    (keystores_dir / "input_keystore.json").write_text(json.dumps(input_data))
    (passwords_dir / "input_keystore.txt").write_text("testpassword123")

    config = Config(
        host="127.0.0.1",
        port=8080,
        log_level="DEBUG",
        key_store_path=key_store_dir,
        keystores_path=keystores_dir,
        keystores_passwords_path=passwords_dir,
    )

    app = create_app(config)
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
    with open(keystore_path) as f:
        data: dict[str, Any] = json.load(f)
        return data


@pytest.fixture
def sample_keystore_password() -> str:
    """Return the password for the sample keystore."""
    return "testpassword123"
