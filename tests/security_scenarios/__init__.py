"""Security scenario test suite — public entry point."""

from .base import REGISTRY, Scenario, ScenarioResult, register
from .expectations import ScenarioCategory, ScenarioExpectation, Verdict
from .helpers import IpAllocator, event, now, time_ladder

# Importing the scenarios module triggers @register on each subclass,
# populating REGISTRY in deterministic alphabetical order.
from . import scenarios as _scenarios  # noqa: F401

__all__ = [
    "IpAllocator",
    "REGISTRY",
    "Scenario",
    "ScenarioCategory",
    "ScenarioExpectation",
    "ScenarioResult",
    "Verdict",
    "event",
    "now",
    "register",
    "time_ladder",
]
