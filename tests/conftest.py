# SPDX-License-Identifier: Apache-2.0
"""Test-wide settings: witnessing is off, so no test sends a checkpoint."""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["CAPSULE_WITNESS"] = "off"
sys.path.insert(0, str(Path(__file__).parent))
