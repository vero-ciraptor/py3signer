"""Path utilities for keystore file operations.

This module provides shared functions for building keystore file paths,
scanning directories, and extracting public keys from filenames.
"""

from pathlib import Path  # noqa: TC003


def get_keystore_filename(pubkey_hex: str) -> str:
    """Get the keystore filename for a given public key.

    Args:
        pubkey_hex: The public key hex string (will be normalized to lowercase)

    Returns:
        The keystore filename (e.g., "aabbccdd.json")

    """
    return f"{pubkey_hex.lower()}.json"


def get_password_filename(pubkey_hex: str) -> str:
    """Get the password filename for a given public key.

    Args:
        pubkey_hex: The public key hex string (will be normalized to lowercase)

    Returns:
        The password filename (e.g., "aabbccdd.txt")

    """
    return f"{pubkey_hex.lower()}.txt"


def get_keystore_paths(
    directory: Path,
    pubkey_hex: str,
) -> tuple[Path, Path]:
    """Get the file paths for a keystore and its password file.

    Args:
        directory: The directory containing the keystore files
        pubkey_hex: The public key hex string

    Returns:
        Tuple of (keystore_path, password_path)

    """
    base_name = pubkey_hex.lower()
    keystore_path = directory / f"{base_name}.json"
    password_path = directory / f"{base_name}.txt"
    return keystore_path, password_path


def get_pubkey_from_filename(filename: str) -> str | None:
    """Extract the public key hex from a keystore or password filename.

    Args:
        filename: The filename to parse (e.g., "aabbccdd.json" or "aabbccdd.txt")

    Returns:
        The public key hex string, or None if filename doesn't match expected pattern

    """
    if not filename:
        return None

    name = filename.lower()
    if name.endswith(".json"):
        return name[:-5]  # Remove .json extension
    if name.endswith(".txt"):
        return name[:-4]  # Remove .txt extension
    return None


def scan_keystore_directory(directory: Path) -> dict[str, Path]:
    """Scan directory for keystore files with matching password files.

    Returns a dict mapping keystore base name to the JSON file path.
    Only includes .json files that have corresponding .txt password files.

    Args:
        directory: Path to directory containing keystore files

    Returns:
        Dict mapping base name to keystore JSON file path

    """
    keystores: dict[str, Path] = {}

    if not directory.exists() or not directory.is_dir():
        return keystores

    # Find all .json files and check for matching .txt files
    for json_file in directory.glob("*.json"):
        base_name = json_file.stem
        password_file = json_file.with_suffix(".txt")

        if password_file.exists():
            keystores[base_name] = json_file

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

    if not keystores_path.exists() or not keystores_path.is_dir():
        return keystores

    # Find all .json files in keystores_path
    for json_file in keystores_path.glob("*.json"):
        base_name = json_file.stem
        password_file = passwords_path / f"{base_name}.txt"

        if password_file.exists():
            keystores[base_name] = (json_file, password_file)

    return keystores
