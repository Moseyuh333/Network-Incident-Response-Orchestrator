"""Scenarios package — each module defines one attack pattern.

Importing this package triggers ``@register`` on every Scenario subclass,
populating the global registry used by ``run_all.py``. Modules are imported
alphabetically so the report order matches the file naming convention.
"""

from __future__ import annotations

import importlib
import pkgutil

# Import every sibling module so their @register decorators fire.
for _info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
    importlib.import_module(f"{__name__}.{_info.name}")
