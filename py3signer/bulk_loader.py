"""Bulk keystore loading from directory."""

import logging
from typing import TYPE_CHECKING

from .keystore import Keystore, KeystoreError

if TYPE_CHECKING:
    from pathlib import Path

    from py3signer_core import PublicKey, SecretKey

    from .storage import KeyStorage

logger = logging.getLogger(__name__)


def scan_keystore_directory(directory: Path) -> dict[str, Path]:
    """Scan directory for keystore files.

    Returns a dict mapping keystore base name to the JSON file path.
    Only includes .json files that have corresponding .txt password files.

    Args:
        directory: Path to directory containing keystore files

    Returns:
        Dict mapping base name to keystore JSON file path

    """
    keystores: dict[str, Path] = {}

    if not directory.exists():
        logger.warning(f"Keystore directory does not exist: {directory}")
        return keystores

    if not directory.is_dir():
        logger.warning(f"Keystore path is not a directory: {directory}")
        return keystores

    # Find all .json files and check for matching .txt files
    for json_file in directory.glob("*.json"):
        base_name = json_file.stem
        password_file = json_file.with_suffix(".txt")

        if password_file.exists():
            keystores[base_name] = json_file
        else:
            logger.warning(
                f"Skipping {json_file.name}: no matching password file {password_file.name}",
            )

    logger.info(f"Found {len(keystores)} keystore(s) with matching password files")
    return keystores


def load_keystore_with_password(
    keystore_path: Path,
    password_path: Path,
) -> tuple[PublicKey, SecretKey, str, str | None, str]:
    """Load a single keystore with its password.

    Args:
        keystore_path: Path to the keystore JSON file
        password_path: Path to the password text file

    Returns:
        Tuple of (public_key, secret_key, path, description, password)

    Raises:
        KeystoreError: If keystore is invalid or password is incorrect

    """
    # Load keystore
    keystore = Keystore.from_file(keystore_path)

    # Read password
    try:
        password = password_path.read_text().strip()
    except Exception as e:
        raise KeystoreError(f"Failed to read password file: {e!r}") from e

    # Decrypt keystore
    secret_key = keystore.decrypt(password)
    pubkey = secret_key.public_key()

    return pubkey, secret_key, keystore.path, keystore.description, password


def load_keystores_from_directory(
    directory: Path,
    storage: KeyStorage,
    import_to_storage: bool = False,
) -> tuple[int, int]:
    """Load all keystores from a directory into storage.

    Each .json keystore file must have a matching .txt file with the same base name
    containing the plaintext password.

    Args:
        directory: Path to directory containing keystore files
        storage: KeyStorage instance to load keys into
        import_to_storage: If True, copy keystore files to storage's keystores dir

    Returns:
        Tuple of (success_count, failure_count)

    """
    keystores = scan_keystore_directory(directory)

    success_count = 0
    failure_count = 0

    for base_name, keystore_path in keystores.items():
        password_path = keystore_path.with_suffix(".txt")

        try:
            pubkey, secret_key, path, description, password = (
                load_keystore_with_password(
                    keystore_path,
                    password_path,
                )
            )
            pubkey_hex = pubkey.to_bytes().hex()

            # Read keystore JSON for persistence
            keystore_json = keystore_path.read_text()

            # Add key to storage (always persistent if data_dir is set)
            storage.add_key(
                pubkey,
                secret_key,
                path,
                description,
                keystore_json=keystore_json,
                password=password,
            )

            # Optionally import (copy) the files to unified storage
            if import_to_storage:
                storage.import_keystore_files(directory, pubkey_hex)

            logger.info(f"Loaded keystore: {base_name}")
            success_count += 1
        except KeystoreError as e:
            logger.error(f"Failed to load keystore {base_name}: {e}")
            failure_count += 1
        except ValueError as e:
            logger.error(f"Failed to add keystore {base_name} to storage: {e}")
            failure_count += 1
        except Exception as e:
            logger.error(f"Unexpected error loading keystore {base_name}: {e}")
            failure_count += 1

    logger.info(
        f"Bulk loading complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count


def import_keystores_from_directory(
    source_dir: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Import keystores from a source directory into unified storage.

    This function loads keystores from a source directory and copies them
    to the unified storage location (data_dir/keystores).

    Args:
        source_dir: Path to directory containing keystore .json and .txt files
        storage: KeyStorage instance to load keys into

    Returns:
        Tuple of (success_count, failure_count)

    Raises:
        ValueError: If source_dir is not a valid directory

    """
    if not source_dir.exists():
        raise ValueError(f"Source directory does not exist: {source_dir}")
    if not source_dir.is_dir():
        raise ValueError(f"Source path is not a directory: {source_dir}")

    # Use the unified loading function with import enabled
    return load_keystores_from_directory(source_dir, storage, import_to_storage=True)


def import_keystores_from_separate_directories(
    keystores_path: Path,
    passwords_path: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Import keystores from separate directories into unified storage.

    Scans the keystores directory for .json files and looks for matching
    .txt password files in the passwords directory (by base name).
    Keys are imported (copied) to the unified storage location.

    Args:
        keystores_path: Path to directory containing keystore .json files
        passwords_path: Path to directory containing password .txt files
        storage: KeyStorage instance to load keys into

    Returns:
        Tuple of (success_count, failure_count)

    Raises:
        ValueError: If either path is not a valid directory

    """
    if not keystores_path.exists():
        raise ValueError(f"Keystores path does not exist: {keystores_path}")
    if not keystores_path.is_dir():
        raise ValueError(f"Keystores path is not a directory: {keystores_path}")
    if not passwords_path.exists():
        raise ValueError(f"Passwords path does not exist: {passwords_path}")
    if not passwords_path.is_dir():
        raise ValueError(f"Passwords path is not a directory: {passwords_path}")

    # Find all .json files in keystores_path
    success_count = 0
    failure_count = 0

    for json_file in keystores_path.glob("*.json"):
        base_name = json_file.stem
        password_file = passwords_path / f"{base_name}.txt"

        if not password_file.exists():
            logger.warning(
                f"Skipping {json_file.name}: no matching password file in {passwords_path}",
            )
            failure_count += 1
            continue

        try:
            pubkey, secret_key, path, description, password = (
                load_keystore_with_password(
                    json_file,
                    password_file,
                )
            )
            pubkey_hex = pubkey.to_bytes().hex()

            # Read keystore JSON for persistence
            keystore_json = json_file.read_text()

            # Add key to storage
            storage.add_key(
                pubkey,
                secret_key,
                path,
                description,
                keystore_json=keystore_json,
                password=password,
            )

            # Import the keystore files to unified storage
            # Try to import from both locations (keystores_path takes precedence)
            result = storage.import_keystore_files(keystores_path, pubkey_hex)
            if result == (None, None):
                # Try passwords_path as fallback (for files named by pubkey)
                storage.import_keystore_files(passwords_path, pubkey_hex)

            logger.info(f"Imported keystore: {base_name}")
            success_count += 1
        except KeystoreError as e:
            logger.error(f"Failed to import keystore {base_name}: {e}")
            failure_count += 1
        except ValueError as e:
            logger.error(f"Failed to add keystore {base_name} to storage: {e}")
            failure_count += 1
        except Exception as e:
            logger.error(f"Unexpected error importing keystore {base_name}: {e}")
            failure_count += 1

    logger.info(
        f"Import complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count
