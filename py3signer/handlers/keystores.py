"""Keymanager API - Local Key Manager endpoints."""

import logging
from typing import Any

from litestar import Controller, delete, get, post
from litestar.status_codes import HTTP_200_OK

from py3signer.keystore import Keystore, KeystoreError
from py3signer.storage import KeyNotFound, KeyStorage

from .base import (
    DeleteKeystoresResponse,
    ImportKeystoresResponse,
    KeystoreDeleteResult,
    KeystoreDeleteStatus,
    KeystoreImportResult,
    KeystoreInfo,
    ListKeystoresResponse,
    clean_pubkey_hex,
    validate_delete_request,
    validate_import_request,
)

logger = logging.getLogger(__name__)


def _import_single_keystore(
    keystore_json: str,
    password: str,
    existing_keys: set[str],
    storage: KeyStorage,
    persistence_enabled: bool,
) -> KeystoreImportResult:
    """Import a single keystore.

    Args:
        keystore_json: The keystore JSON string
        password: The password for the keystore
        existing_keys: Set of existing public key hex strings
        storage: The KeyStorage instance
        persistence_enabled: Whether persistence is enabled

    Returns:
        KeystoreImportResult with status and message

    """
    try:
        keystore = Keystore.from_json(keystore_json)
        secret_key = keystore.decrypt(password)
        pubkey = secret_key.public_key()
        pubkey_hex = pubkey.to_bytes().hex()

        if pubkey_hex in existing_keys:
            return KeystoreImportResult(
                status="duplicate",
                message=f"Keystore already exists for pubkey {keystore.pubkey}",
            )

        # Add key with optional persistence
        _, persisted = storage.add_key(
            pubkey=pubkey,
            secret_key=secret_key,
            path=keystore.path,
            description=keystore.description,
            keystore_json=keystore_json if persistence_enabled else None,
            password=password if persistence_enabled else None,
        )

        if persistence_enabled and not persisted:
            logger.warning(
                f"Failed to persist keystore to disk: {pubkey_hex[:20]}...",
            )

        existing_keys.add(pubkey_hex)
        return KeystoreImportResult(
            status="imported",
            message=f"Successfully imported keystore with pubkey {keystore.pubkey}",
        )

    except KeystoreError as e:
        return KeystoreImportResult(status="error", message=str(e))
    except Exception as e:
        logger.exception("Unexpected error importing keystore")
        return KeystoreImportResult(
            status="error",
            message=f"Internal error: {e}",
        )


def _delete_single_key(
    pubkey_hex: str,
    storage: KeyStorage,
) -> tuple[KeystoreDeleteResult, dict[str, Any] | None]:
    """Delete a single key and return result with optional slashing data.

    Args:
        pubkey_hex: The public key hex string (with or without 0x prefix)
        storage: The KeyStorage instance

    Returns:
        Tuple of (delete result, slashing data entry or None)

    """
    cleaned_pubkey = clean_pubkey_hex(pubkey_hex)

    try:
        storage.remove_key(cleaned_pubkey)
    except KeyNotFound:
        return KeystoreDeleteResult(status=KeystoreDeleteStatus.NOT_FOUND), None
    except Exception as e:
        return (
            KeystoreDeleteResult(status=KeystoreDeleteStatus.ERROR, message=str(e)),
            None,
        )

    # Build slashing protection entry for deleted key
    slashing_entry = {
        "pubkey": f"0x{cleaned_pubkey}",
        "signed_blocks": [],
        "signed_attestations": [],
    }
    return KeystoreDeleteResult(status=KeystoreDeleteStatus.DELETED), slashing_entry


def _build_slashing_protection_response(
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build slashing protection response per EIP-3076.

    Args:
        entries: List of slashing data entries

    Returns:
        EIP-3076 formatted slashing protection data

    """
    return {
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
        },
        "data": entries,
    }


class LocalKeyManagerController(Controller):  # type: ignore[misc]
    """Keymanager API - Local Key Manager endpoints."""

    path = "/eth/v1/keystores"

    @get()  # type: ignore[untyped-decorator]
    async def list_keystores(self, storage: KeyStorage) -> ListKeystoresResponse:
        """GET /eth/v1/keystores - List all imported keys."""
        keys = storage.list_keys()
        keystores = [
            KeystoreInfo(
                validating_pubkey=key_info.pubkey_hex,
                derivation_path=key_info.path,
                readonly=key_info.is_external,  # External keys are readonly
            )
            for key_info in keys
        ]
        return ListKeystoresResponse(data=keystores)

    @post(status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def import_keystores(
        self,
        data: dict[str, Any],
        storage: KeyStorage,
    ) -> ImportKeystoresResponse:
        """POST /eth/v1/keystores - Import keystores.

        Accepts EIP-3076 slashing_protection data (stored but not processed).
        """
        import_request = validate_import_request(data)

        # Log if slashing protection data was provided (we accept but don't process it)
        if import_request.slashing_protection:
            logger.warning(
                "Slashing protection data provided during import (accepted but not processed)",
            )

        existing_keys = {key.pubkey_hex for key in storage.list_keys()}
        persistence_enabled = storage.managed_keystores_dir is not None

        results = [
            _import_single_keystore(
                keystore_json=keystore_json,
                password=password,
                existing_keys=existing_keys,
                storage=storage,
                persistence_enabled=persistence_enabled,
            )
            for keystore_json, password in zip(
                import_request.keystores,
                import_request.passwords,
                strict=True,
            )
        ]

        return ImportKeystoresResponse(data=results)

    @delete(status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def delete_keystores(
        self,
        data: dict[str, Any],
        storage: KeyStorage,
    ) -> DeleteKeystoresResponse:
        """DELETE /eth/v1/keystores - Delete keystores.

        Returns slashing protection data for keys that were active or had data.
        Per the spec, slashing protection data must be retained even after deletion.
        """
        delete_request = validate_delete_request(data)

        results: list[KeystoreDeleteResult] = []
        slashing_entries: list[dict[str, Any]] = []

        for pubkey_hex in delete_request.pubkeys:
            result, slashing_entry = _delete_single_key(pubkey_hex, storage)
            results.append(result)
            if slashing_entry:
                slashing_entries.append(slashing_entry)

        slashing_protection = _build_slashing_protection_response(slashing_entries)

        return DeleteKeystoresResponse(
            data=results,
            slashing_protection=slashing_protection,
        )
