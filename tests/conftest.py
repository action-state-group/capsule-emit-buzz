# SPDX-License-Identifier: Apache-2.0
"""Test-wide settings: any attempt to open a network connection fails the test
that made it."""
from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


class NetworkUsed(AssertionError):
    """A test tried to open a network connection."""


def _no_network(*_args: object, **_kwargs: object) -> None:
    raise NetworkUsed("tests run with no network: a witness call must be opt-in and injected")


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
