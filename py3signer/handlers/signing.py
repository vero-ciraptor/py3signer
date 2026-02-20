"""Remote Signing API endpoints."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from litestar import Controller, Request, Response, get, post
from litestar.exceptions import HTTPException, NotFoundException, ValidationException
from litestar.status_codes import HTTP_200_OK, HTTP_500_INTERNAL_SERVER_ERROR

from py3signer.signer import Signer, SignerError
from py3signer.signing_types import (
    SignRequest,
    get_domain_for_request,
    sign_request_decoder,
    validate_signing_root,
)

from .base import SignResponse, clean_pubkey_hex

if TYPE_CHECKING:
    from py3signer.storage import KeyStorage

logger = logging.getLogger(__name__)


async def parse_sign_request(request: Request) -> SignRequest:
    """Parse and validate a sign request from the request body.

    Args:
        request: The HTTP request

    Returns:
        Parsed SignRequest

    Raises:
        ValidationException: If parsing fails

    """
    from typing import cast

    try:
        body_bytes = await request.body()
        return cast("SignRequest", sign_request_decoder.decode(body_bytes))
    except Exception as e:
        raise ValidationException(detail=f"Validation error: {e}") from e


class SigningController(Controller):  # type: ignore[misc]
    """Remote Signing API endpoints."""

    path = "/api/v1/eth2"

    @get("/publicKeys")  # type: ignore[untyped-decorator]
    async def list_public_keys(self, storage: KeyStorage) -> list[str]:
        """GET /api/v1/eth2/publicKeys - List available BLS public keys."""
        keys = storage.list_keys()
        return [f"0x{key_info.pubkey_hex}" for key_info in keys]

    @post("/sign/{identifier:str}", status_code=HTTP_200_OK)  # type: ignore[untyped-decorator]
    async def sign(
        self,
        request: Request,
        identifier: str,
        signer: Signer,
    ) -> Response | SignResponse:
        """POST /api/v1/eth2/sign/:identifier - Sign data."""
        pubkey_hex = clean_pubkey_hex(identifier)
        if not pubkey_hex:
            raise ValidationException(detail="Missing identifier")

        # Parse request body
        sign_request = await parse_sign_request(request)

        # Validate signing root
        try:
            message = validate_signing_root(sign_request.signing_root)
        except ValueError as e:
            raise ValidationException(detail=str(e)) from e

        if message is None:
            raise ValidationException(
                detail="signing_root is required - SSZ signing root computation from request data "
                "is not yet implemented. Please provide signing_root in the request.",
            )

        # Get domain for signing
        try:
            domain = get_domain_for_request(sign_request)
        except ValueError as e:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e),
            ) from e

        # Perform signing
        try:
            signature = await asyncio.to_thread(
                signer.sign_data,
                pubkey_hex=pubkey_hex,
                data=message,
                domain=domain,
            )
        except SignerError as e:
            raise NotFoundException(detail=str(e)) from e
        except Exception as e:
            logger.exception("Signing error")
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Signing failed: {e}",
            ) from e

        # Build response
        signature_hex = signature.to_bytes().hex()
        full_signature = f"0x{signature_hex}"

        accept_header = request.headers.get("Accept", "")
        if accept_header == "text/plain":
            return Response(
                content=full_signature,
                status_code=HTTP_200_OK,
                media_type="text/plain",
            )

        return SignResponse(signature=full_signature)
