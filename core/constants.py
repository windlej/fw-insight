"""Constants for fw-insight."""

import os

MAX_RULES = int(os.environ.get("MAX_RULES", "5000"))

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

VENDOR_IDS = [
    "paloalto",
    "fortinet",
    "unifi_controller",
    "unifi_gateway",
]
