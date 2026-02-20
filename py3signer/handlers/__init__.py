"""HTTP route handlers for Keymanager API with Litestar.

This package provides controller modules for different API endpoints:
- health: Health check endpoints
- keystores: Keymanager API for keystore management
- signing: Remote Signing API endpoints
"""

from litestar import Router

from .health import HealthController
from .keystores import LocalKeyManagerController
from .signing import SigningController


def get_routers() -> list[Router]:
    """Get all routers for the application."""
    return [
        Router(path="/", route_handlers=[HealthController]),
        Router(path="/", route_handlers=[LocalKeyManagerController]),
        Router(path="/", route_handlers=[SigningController]),
    ]


__all__ = [
    "HealthController",
    "LocalKeyManagerController",
    "SigningController",
    "get_routers",
]
