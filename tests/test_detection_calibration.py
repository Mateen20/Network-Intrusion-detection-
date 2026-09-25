from types import SimpleNamespace

from alerts.alert_manager import AlertManager
from ml.detector import calibrate_severity


def make_flow():
    return SimpleNamespace(
        src_ip="192.168.1.10",
        src_port=50000,
        dst_ip="192.168.1.1",
        dst_port=443,
        protocol=0,
        duration=0.2,
        src_bytes=100,
        dst_bytes=200,
    )


def make_detection(label, confidence, severity):
    return {
        "label": label,
        "confidence": confidence,
        "severity": severity,
        "anomaly": False,
    }


def test_high_confidence_malicious_prediction_remains_critical():
    assert calibrate_severity("exploit", 0.97) == ("exploit", "CRITICAL")


def test_low_confidence_malicious_prediction_is_uncertain():
    assert calibrate_severity("exploit", 0.42) == ("exploit", "UNCERTAIN")


def test_normal_prediction_is_clean():
    assert calibrate_severity("normal", 0.99) == ("normal", "CLEAN")


def test_alert_manager_creates_uncertain_alert():
    manager = AlertManager()
    alert = manager.add(
        make_flow(),
        make_detection("exploit", 0.42, "UNCERTAIN"),
        {},
    )

    assert alert is not None
    assert alert.severity == "UNCERTAIN"
    assert manager.dashboard_stats()["total_alerts"] == 1


def test_alert_manager_does_not_create_clean_alert():
    manager = AlertManager()
    alert = manager.add(
        make_flow(),
        make_detection("normal", 0.99, "CLEAN"),
        {},
    )

    assert alert is None
    assert manager.dashboard_stats()["total_alerts"] == 0


def test_alert_manager_deduplicates_same_flow_and_class():
    manager = AlertManager()
    flow = make_flow()
    detection = make_detection("exploit", 0.97, "CRITICAL")

    first = manager.add(flow, detection, {})
    duplicate = manager.add(flow, detection, {})

    assert first is not None
    assert duplicate is None
    assert manager.dashboard_stats()["total_alerts"] == 1