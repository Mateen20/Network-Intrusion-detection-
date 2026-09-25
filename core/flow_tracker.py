"""
core/flow_tracker.py — Aggregates raw packet events into network flows
and extracts ML-ready features from each completed flow.
"""

import time
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field

FLOW_TIMEOUT = 30.0   # seconds of inactivity before flow is finalised


def _canonical_feature_names() -> list[str]:
    from ml.trainer import FEATURE_NAMES
    return list(FEATURE_NAMES)


@dataclass
class Flow:
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  int      # 0=TCP 1=UDP 2=ICMP

    # Counters updated as packets arrive
    start_time:    float = field(default_factory=time.time)
    last_seen:     float = field(default_factory=time.time)
    pkt_count:     int   = 0
    src_bytes:     int   = 0
    dst_bytes:     int   = 0
    syn_count:     int   = 0
    fin_count:     int   = 0
    rst_count:     int   = 0
    urg_count:     int   = 0
    wrong_frags:   int   = 0
    same_srv:      int   = 0
    diff_srv:      int   = 0

    def update(self, pkt_size: int, is_src: bool, flags: dict):
        self.pkt_count  += 1
        self.last_seen   = time.time()
        if is_src:
            self.src_bytes += pkt_size
        else:
            self.dst_bytes += pkt_size
        self.syn_count  += int(flags.get("SYN", False))
        self.fin_count  += int(flags.get("FIN", False))
        self.rst_count  += int(flags.get("RST", False))
        self.urg_count  += int(flags.get("URG", False))

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > FLOW_TIMEOUT

    def to_features(self, global_stats: dict) -> dict:
        """Convert a flow into the exact named feature vector expected by the trained model."""
        duration  = max(self.duration, 0.001)
        pkt_rate  = self.pkt_count / duration
        byte_rate = (self.src_bytes + self.dst_bytes) / duration
        pkt_cnt   = max(self.pkt_count, 1)

        same_total = max(global_stats.get("same_srv_total", 1), 1)
        diff_total = max(global_stats.get("diff_srv_total", 0), 0)
        same_srv_rate = float(global_stats.get("same_srv_rate", same_total / max(same_total + diff_total, 1)))
        diff_srv_rate = float(global_stats.get("diff_srv_rate", diff_total / max(same_total + diff_total, 1)))

        feature_map = {
            "duration":               float(duration),
            "protocol_type":          float(self.protocol),
            "src_bytes":              float(self.src_bytes),
            "dst_bytes":              float(self.dst_bytes),
            "wrong_fragment":         float(self.wrong_frags),
            "urgent":                 float(self.urg_count),
            "count":                  float(global_stats.get("conn_2s", 1)),
            "srv_count":              float(global_stats.get("srv_2s", 1)),
            "serror_rate":            float(self.syn_count / pkt_cnt),
            "rerror_rate":            float(self.rst_count / pkt_cnt),
            "same_srv_rate":          same_srv_rate,
            "diff_srv_rate":          diff_srv_rate,
            "dst_host_count":         float(global_stats.get("dst_host_count", 1)),
            "dst_host_srv_count":     float(global_stats.get("dst_host_srv_count", 1)),
            "dst_host_same_srv_rate": float(global_stats.get("dst_host_same_srv_rate", 1.0)),
            "dst_host_diff_srv_rate": float(global_stats.get("dst_host_diff_srv_rate", 0.0)),
            "dst_host_serror_rate":   float(global_stats.get("dst_host_serror_rate", 0.0)),
            "packet_rate":            float(pkt_rate),
            "byte_rate":              float(byte_rate),
            "flag_syn_ratio":         float(self.syn_count / pkt_cnt),
            "flag_fin_ratio":         float(self.fin_count / pkt_cnt),
            "flag_rst_ratio":         float(self.rst_count / pkt_cnt),
            "port_number":            float(self.dst_port),
            "is_well_known_port":     float(1.0 if self.dst_port < 1024 else 0.0),
        }

        feature_names = _canonical_feature_names()
        ordered = {name: float(feature_map[name]) for name in feature_names}
        return ordered


class FlowTracker:
    """Tracks all active network flows and emits completed flows."""

    def __init__(self):
        self._flows:  dict[tuple, Flow] = {}
        self._lock = threading.RLock()
        self._history: list[dict]       = []   # recent completed flows
        self._conn_window: list[float]  = []   # timestamps for 2-sec window
        self._dst_host_log: dict        = defaultdict(Counter)
        self._dst_host_stats: dict      = defaultdict(lambda: {"total": 0, "syn": 0})
        self.last_feature_vector: dict | None = None
        self.last_feature_debug: dict | None = None

    # ─── Public API ───────────────────────────────────────────────────────────

    def process_packet(self, pkt_info: dict) -> Flow | None:
        """
        Feed one packet. Returns a completed Flow if one just expired,
        else None.
        """
        with self._lock:
            return self._process_packet(pkt_info)

    def _process_packet(self, pkt_info: dict) -> Flow | None:
        key     = self._flow_key(pkt_info)
        rev_key = self._flow_key(pkt_info, reverse=True)

        now = time.time()
        self._conn_window = [t for t in self._conn_window if now - t < 2.0]
        self._conn_window.append(now)

        # Look up existing flow
        if key in self._flows:
            flow = self._flows[key]
            is_src = True
        elif rev_key in self._flows:
            flow   = self._flows[rev_key]
            key    = rev_key
            is_src = False
        else:
            # New flow
            flow = Flow(
                src_ip   = pkt_info.get("src_ip",   "0.0.0.0"),
                dst_ip   = pkt_info.get("dst_ip",   "0.0.0.0"),
                src_port = pkt_info.get("src_port", 0),
                dst_port = pkt_info.get("dst_port", 0),
                protocol = pkt_info.get("protocol", 0),
            )
            self._flows[key] = flow
            is_src = True

        flow.update(
            pkt_size = pkt_info.get("size", 0),
            is_src   = is_src,
            flags    = pkt_info.get("flags", {}),
        )

        # Track destination host statistics
        dst = pkt_info.get("dst_ip", "")
        self._dst_host_log[dst][pkt_info.get("dst_port", 0)] += 1
        self._dst_host_stats[dst]["total"] += 1
        if pkt_info.get("flags", {}).get("SYN", False):
            self._dst_host_stats[dst]["syn"] += 1

        # Check for expired flows
        return self._expire_flow(key)

    def collect_expired(self) -> list[tuple[Flow, dict]]:
        """Return and remove all expired flows as (flow, features) pairs."""
        with self._lock:
            expired_keys = [k for k, f in list(self._flows.items()) if f.is_expired()]
            results = []
            for key in expired_keys:
                flow = self._flows.pop(key, None)
                if flow is None:
                    continue
                stats = self._global_stats(flow)
                features = flow.to_features(stats)
                self.last_feature_vector = features
                self.last_feature_debug = {"flow": flow.__dict__.copy(), "stats": stats}
                results.append((flow, features))
            return results

    def active_count(self) -> int:
        return len(self._flows)

    def get_last_feature_debug(self) -> dict | None:
        return self.last_feature_debug

    def get_last_feature_vector(self) -> dict | None:
        return self.last_feature_vector

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _expire_flow(self, key: tuple) -> Flow | None:
        flow = self._flows.get(key)
        if flow and flow.is_expired() and flow.pkt_count > 0:
            return self._flows.pop(key)
        return None

    def _global_stats(self, flow: Flow) -> dict:
        dst = flow.dst_ip
        port_counts = self._dst_host_log.get(dst, Counter())
        total_service_hits = sum(port_counts.values())
        same_srv = float(port_counts.get(flow.dst_port, 0))
        diff_srv = max(total_service_hits - same_srv, 0.0)
        same_total = max(same_srv + diff_srv, 1.0)

        host_stats = self._dst_host_stats.get(dst, {"total": 0, "syn": 0})
        total_host = max(host_stats.get("total", 0), 1)
        syn_total = float(host_stats.get("syn", 0))

        return {
            "conn_2s":               len(self._conn_window),
            "srv_2s":                max(len(self._conn_window) // 2, 1),
            "dst_host_count":        len(self._dst_host_log),
            "dst_host_srv_count":    float(len(port_counts) or 1),
            "dst_host_same_srv_rate": same_srv / same_total,
            "dst_host_diff_srv_rate": diff_srv / same_total,
            "dst_host_serror_rate":  syn_total / total_host,
            "same_srv_total":        same_srv,
            "diff_srv_total":        diff_srv,
            "same_srv_rate":         same_srv / same_total,
            "diff_srv_rate":         diff_srv / same_total,
        }

    @staticmethod
    def _flow_key(pkt: dict, reverse: bool = False) -> tuple:
        if reverse:
            return (pkt.get("dst_ip"), pkt.get("src_ip"),
                    pkt.get("dst_port"), pkt.get("src_port"),
                    pkt.get("protocol"))
        return (pkt.get("src_ip"), pkt.get("dst_ip"),
                pkt.get("src_port"), pkt.get("dst_port"),
                pkt.get("protocol"))
