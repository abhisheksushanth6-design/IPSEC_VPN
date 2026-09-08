"""Layer 01 — IPsec VPN Test Environment.

Provides VirtualBox test environment management, VM discovery, lifecycle control,
network interface verification, and StrongSwan / IPsec status inspection.
"""

from app.layers.layer01_test_environment.service import (
    EnvironmentService,
    get_environment_service,
)
from app.layers.layer01_test_environment.vbox_manager import VBoxManager
from app.layers.layer01_test_environment.network_discovery import NetworkDiscovery
from app.layers.layer01_test_environment.strongswan_checker import StrongSwanChecker

LAYER_NUMBER = 1
LAYER_NAME = "IPsec VPN Test Environment"

__all__ = [
    "LAYER_NUMBER",
    "LAYER_NAME",
    "EnvironmentService",
    "get_environment_service",
    "VBoxManager",
    "NetworkDiscovery",
    "StrongSwanChecker",
]
