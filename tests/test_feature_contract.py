import math

from core.flow_tracker import FLOW_TIMEOUT, FlowTracker
from ml.trainer import FEATURE_NAMES


def test_live_flow_features_match_training_schema():
    tracker = FlowTracker()
    pkt = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.1",
        "src_port": 50000,
        "dst_port": 443,
        "protocol": 0,
        "size": 120,
        "flags": {"SYN": True, "ACK": True, "FIN": False, "RST": False, "URG": False},
        "ts": 0.0,
    }

    tracker.process_packet(pkt)
    assert tracker.active_count() == 1

    # A newly observed flow must remain active until its inactivity timeout.
    tracker._flows[next(iter(tracker._flows))].last_seen -= FLOW_TIMEOUT + 1
    expired = tracker.collect_expired()
    assert expired, "expected the inactive flow to be collected"

    _, features = expired[0]
    assert list(features.keys()) == FEATURE_NAMES
    assert len(features) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in features.values())
    assert all(math.isfinite(value) for value in features.values())

    # Basic sanity: protocol should be one of the training model codes
    assert features["protocol_type"] in (0.0, 1.0, 2.0)
    assert features["port_number"] == 443.0
    assert features["duration"] > 0.0

    # Missing features must not silently become a misleading all-zero vector
    assert any(value != 0.0 for value in [features["src_bytes"], features["dst_bytes"], features["packet_rate"]])


def test_feature_names_are_in_order_and_valid_for_scaler():
    feature_names = FEATURE_NAMES
    assert feature_names[0] == "duration"
    assert feature_names[-1] == "is_well_known_port"
    assert len(feature_names) == 24
    assert len(set(feature_names)) == len(feature_names)
    assert all(name and name.strip() for name in feature_names)

    # ensure the names are the canonical schema expected by the model
    assert feature_names == [
        "duration", "protocol_type", "src_bytes", "dst_bytes",
        "wrong_fragment", "urgent", "count", "srv_count",
        "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_serror_rate",
        "packet_rate", "byte_rate",
        "flag_syn_ratio", "flag_fin_ratio", "flag_rst_ratio",
        "port_number", "is_well_known_port",
    ]
