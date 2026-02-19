"""Bulk keystore loading from directory."""

import logging
from typing import TYPE_CHECKING

from .keystore import Keystore, KeystoreError
from .models import KeystoreLoadResult

if TYPE_CHECKING:
    from pathlib import Path

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


def scan_keystore_directories(
    keystores_path: Path,
    passwords_path: Path,
) -> dict[str, tuple[Path, Path]]:
    """Scan separate directories for keystore and password files.

    Returns a dict mapping keystore base name to (json_file, password_file) paths.
    Only includes .json files that have corresponding .txt files in passwords_path.

    Args:
        keystores_path: Path to directory containing keystore .json files
        passwords_path: Path to directory containing password .txt files

    Returns:
        Dict mapping base name to (keystore_path, password_path) tuple

    """
    keystores: dict[str, tuple[Path, Path]] = {}

    if not keystores_path.exists():
        logger.warning(f"Keystores directory does not exist: {keystores_path}")
        return keystores

    if not keystores_path.is_dir():
        logger.warning(f"Keystores path is not a directory: {keystores_path}")
        return keystores

    # Find all .json files in keystores_path
    for json_file in keystores_path.glob("*.json"):
        base_name = json_file.stem
        password_file = passwords_path / f"{base_name}.txt"

        if password_file.exists():
            keystores[base_name] = (json_file, password_file)
        else:
            logger.warning(
                f"Skipping {json_file.name}: no matching password file in {passwords_path}",
            )

    logger.info(f"Found {len(keystores)} keystore(s) with matching password files")
    return keystores


def load_keystore_with_password(
    keystore_path: Path,
    password_path: Path,
) -> KeystoreLoadResult:
    """Load a single keystore with its password.

    Args:
        keystore_path: Path to the keystore JSON file
        password_path: Path to the password text file

    Returns:
        KeystoreLoadResult containing all keystore data

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

    return KeystoreLoadResult(
        pubkey=pubkey,
        secret_key=secret_key,
        path=keystore.path,
        description=keystore.description,
        password=password,
    )


def _load_single_keystore(
    base_name: str,
    keystore_path: Path,
    password_path: Path,
    storage: KeyStorage,
    as_external: bool = False,
) -> bool:
    """Load a single keystore into storage.

    Args:
        base_name: Base name of the keystore for logging
        keystore_path: Path to the keystore JSON file
        password_path: Path to the password text file
        storage: KeyStorage instance to load keys into
        as_external: If True, load as external key; otherwise as managed key

    Returns:
        True if successful, False otherwise

    """
    try:
        result = load_keystore_with_password(keystore_path, password_path)

        if as_external:
            storage.add_external_key(
                result.pubkey,
                result.secret_key,
                result.path,
                result.description,
            )
        else:
            # Read keystore JSON for persistence to managed storage
            keystore_json = keystore_path.read_text()

            storage.add_key(
                result.pubkey,
                result.secret_key,
                result.path,
                result.description,
                keystore_json=keystore_json,
                password=result.password,
            )

        logger.info(f"Loaded keystore: {base_name}")
        return True
    except KeystoreError as e:
        logger.error(f"Failed to load keystore {base_name}: {e}")
    except ValueError as e:
        logger.error(f"Failed to add keystore {base_name} to storage: {e}")
    except Exception as e:
        logger.error(f"Unexpected error loading keystore {base_name}: {e}")
    else:
        logger.info(f"Loaded keystore: {base_name}")
        return True
    return False


def load_keystores_from_directory(
    directory: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Load all keystores from a directory into storage.

    Each .json keystore file must have a matching .txt file with the same base name
    containing the plaintext password. Keys are loaded as managed keys.

    Args:
        directory: Path to directory containing keystore files
        storage: KeyStorage instance to load keys into

    Returns:
        Tuple of (success_count, failure_count)

    """
    keystores = scan_keystore_directory(directory)

    success_count = 0
    for base_name, keystore_path in keystores.items():
        password_path = keystore_path.with_suffix(".txt")
        if _load_single_keystore(base_name, keystore_path, password_path, storage):
            success_count += 1

    failure_count = len(keystores) - success_count
    logger.info(
        f"Bulk loading complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count


def load_external_keystores(
    keystores_path: Path,
    passwords_path: Path,
    storage: KeyStorage,
) -> tuple[int, int]:
    """Load external keystores from separate directories.

    Scans the keystores directory for .json files and looks for matching
    .txt password files in the passwords directory (by base name).
    Keys are loaded as EXTERNAL keys - they are NOT copied to managed storage.

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

    keystores = scan_keystore_directories(keystores_path, passwords_path)

    success_count = 0
    for base_name, (json_file, password_file) in keystores.items():
        if _load_single_keystore(
            base_name, json_file, password_file, storage, as_external=True
        ):
            success_count += 1

    failure_count = len(keystores) - success_count
    logger.info(
        f"External keystore loading complete: {success_count} succeeded, {failure_count} failed",
    )
    return success_count, failure_count
