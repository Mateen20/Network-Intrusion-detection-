from pathlib import Path

from reporting.report_generator import NIDSReportGenerator


def test_generate_report_accepts_missing_explanation(tmp_path):
    session_data = {
        "meta": {
            "session_start": "2026-09-25 00:00:00",
            "session_end": "2026-09-25 00:01:00",
            "hostname": "testhost",
            "mode": "Simulation",
        },
        "stats": {
            "total_flows": 1,
            "clean": 0,
            "critical": 1,
            "high": 0,
            "medium": 0,
            "low": 0,
            "threat_pct": 100.0,
            "clean_pct": 0.0,
            "uptime": "00:01:00",
            "model_accuracy": "Trained",
        },
        "alerts": [
            {
                "timestamp": "00:00:01",
                "severity": "CRITICAL",
                "src": "192.168.1.10:50000",
                "dst": "192.168.1.1:443",
                "label": "EXPLOIT",
                "confidence": "51.5%",
                "explanation": None,
            }
        ],
        "top_sources": [{"ip": "192.168.1.10", "count": 1}],
    }

    report = NIDSReportGenerator(session_data, output_dir=str(tmp_path))
    path = report.generate()

    assert Path(path).exists()
    assert path.endswith(".pdf")
