"""Bulk keystore loading from directory."""

import logging
from pathlib import Path

from py3signer_core import PublicKey, SecretKey

from .keystore import Keystore, KeystoreError
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
) -> tuple[PublicKey, SecretKey, str, str | None]:
    """Load a single keystore with its password.

    Args:
        keystore_path: Path to the keystore JSON file
        password_path: Path to the password text file

    Returns:
        Tuple of (public_key, secret_key, path, description)

    Raises:
        KeystoreError: If keystore is invalid or password is incorrect

    """
    # Load keystore
    keystore = Keystore.from_file(keystore_path)

    # Read password
    try:
        password = password_path.read_text().strip()
    except Exception as e:
        raise KeystoreError(f"Failed to read password file: {e}")

    # Decrypt keystore
    secret_key = keystore.decrypt(password)
    pubkey = secret_key.public_key()

    return pubkey, secret_key, keystore.path, keystore.description


def load_keystores_from_directory(
    directory: Path,
    storage: KeyStorage,
    persistent: bool = True,
) -> tuple[int, int]:
    """Load all keystores from a directory into storage.

    Each .json keystore file must have a matching .txt file with the same base name
    containing the plaintext password.

    Args:
        directory: Path to directory containing keystore files
        storage: KeyStorage instance to load keys into
        persistent: Whether keys should be marked as persistent (default: True)

    Returns:
        Tuple of (success_count, failure_count)

    """
    keystores = scan_keystore_directory(directory)

    success_count = 0
    failure_count = 0

    for base_name, keystore_path in keystores.items():
        password_path = keystore_path.with_suffix(".txt")

        try:
            pubkey, secret_key, path, description = load_keystore_with_password(
                keystore_path,
                password_path,
            )
            storage.add_key(
                pubkey,
                secret_key,
                path,
                description,
                persistent=persistent,
            )
            logger.info(f"Loaded keystore: {base_name} (persistent={persistent})")
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


def load_input_only_keystores(
    keystores_path: Path,
    passwords_path: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Load input-only keystores from separate directories.

    Scans the keystores directory for .json files and looks for matching
    .txt password files in the passwords directory (by base name).

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
            pubkey, secret_key, path, description = load_keystore_with_password(
                json_file,
                password_file,
            )
            # Mark as non-persistent (input-only)
            storage.add_key(pubkey, secret_key, path, description, persistent=False)
            logger.info(f"Loaded input-only keystore: {base_name}")
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
        f"Input-only keystore loading complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count
