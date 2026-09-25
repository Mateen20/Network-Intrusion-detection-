import time

import pytest

import core.packet_capture as packet_capture
from core.packet_capture import PacketCapture, PacketCaptureError, select_interface


INTERFACES = [
    {
        "identifier": r"\Device\NPF_{WIFI}",
        "name": "Wi-Fi",
        "description": "Intel Wi-Fi Adapter",
        "guid": "{WIFI}",
        "ip": "192.168.1.10",
    },
    {
        "identifier": r"\Device\NPF_{ETH}",
        "name": "Ethernet",
        "description": "Ethernet Adapter",
        "guid": "{ETH}",
        "ip": "192.168.1.11",
    },
]


def test_auto_selects_usable_wifi_interface():
    selected = select_interface("auto", INTERFACES)

    assert selected["name"] == "Wi-Fi"
    assert selected["identifier"] == r"\Device\NPF_{WIFI}"


def test_invalid_interface_lists_scapy_options():
    with pytest.raises(PacketCaptureError, match="Available interfaces") as error:
        select_interface("2", INTERFACES)

    assert "Wi-Fi" in str(error.value)
    assert r"\Device\NPF_{WIFI}" in str(error.value)


def test_live_capture_uses_resolved_scapy_identifier(monkeypatch):
    monkeypatch.setattr(packet_capture, "discover_interfaces", lambda: INTERFACES)

    capture = PacketCapture(mode="live", interface="Wi-Fi")
    capture._live_capture = lambda: setattr(capture, "_running", False)
    capture.start()
    capture.stop()

    assert capture.interface == r"\Device\NPF_{WIFI}"
    assert capture.interface_name == "Wi-Fi"


def test_stop_cleanly_joins_live_capture_worker(monkeypatch):
    monkeypatch.setattr(packet_capture, "discover_interfaces", lambda: INTERFACES)

    capture = PacketCapture(mode="live", interface="auto")

    def worker():
        while capture.is_running:
            time.sleep(0.01)

    capture._live_capture = worker
    capture.start()
    capture.stop()

    assert not capture.is_running
    assert capture._thread is None
    assert capture.error is None