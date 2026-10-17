"""
tests/test_detector.py — Automated unit tests for LogSentinel detection engine.
Run with:  pytest tests/test_detector.py -v
"""

import io
import pytest
import pandas as pd

import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import detector
from detector import (
    validate_log_dataframe,
    load_and_clean,
    detect_brute_force,
    alerts_to_dataframe,
    REQUIRED_COLUMNS,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)


# ─── Helper builders ──────────────────────────────────────────────────────────

def make_df(rows: list[dict]) -> pd.DataFrame:
    """Build a DataFrame from a list of dicts, using clean column names."""
    return pd.DataFrame(rows)


def failed_logins(ip: str, username: str, timestamps: list[str]) -> list[dict]:
    """Convenience: generate a list of failed login event dicts."""
    return [
        {
            "timestamp": ts,
            "ip_address": ip,
            "username": username,
            "event_type": "login",
            "status": "failed",
        }
        for ts in timestamps
    ]


def success_login(ip: str, username: str, ts: str) -> dict:
    return {
        "timestamp": ts,
        "ip_address": ip,
        "username": username,
        "event_type": "login",
        "status": "success",
    }


# ─── validate_log_dataframe ───────────────────────────────────────────────────

class TestValidateLogDataframe:

    def test_valid_dataframe_passes(self):
        df = make_df(failed_logins("1.2.3.4", "alice", ["2024-01-01 08:00:00"]))
        result = validate_log_dataframe(df)
        assert result.ok is True
        assert result.errors == []

    def test_missing_column_fails(self):
        df = make_df([{"timestamp": "2024-01-01", "ip_address": "1.2.3.4",
                       "username": "u", "event_type": "login"}])
        # 'status' column missing
        result = validate_log_dataframe(df)
        assert result.ok is False
        assert any("status" in e for e in result.errors)

    def test_empty_dataframe_fails(self):
        cols = list(REQUIRED_COLUMNS)
        df = pd.DataFrame(columns=cols)
        result = validate_log_dataframe(df)
        assert result.ok is False

    def test_all_null_timestamps_fails(self):
        df = make_df([{"timestamp": None, "ip_address": "1.2.3.4",
                       "username": "u", "event_type": "login", "status": "failed"}])
        result = validate_log_dataframe(df)
        assert result.ok is False

    def test_column_names_case_insensitive(self):
        """Columns with leading/trailing spaces and uppercase should still pass."""
        df = make_df([{
            "Timestamp": "2024-01-01 00:00:00",
            "IP_Address": "1.2.3.4",
            "Username": "u",
            "Event_Type": "login",
            "Status": "failed",
        }])
        # Normalise as validate_log_dataframe does
        df.columns = df.columns.str.lower().str.strip()
        # Now simulate the original mixed-case input
        df2 = make_df([{
            "Timestamp": "2024-01-01 00:00:00",
            "IP_Address": "1.2.3.4",
            "Username": "u",
            "Event_Type": "login",
            "Status": "failed",
        }])
        result = validate_log_dataframe(df2)
        assert result.ok is True


# ─── load_and_clean ───────────────────────────────────────────────────────────

class TestLoadAndClean:

    def test_sorts_by_timestamp(self):
        df = make_df(failed_logins("1.2.3.4", "alice", [
            "2024-01-01 09:00:00",
            "2024-01-01 08:00:00",
            "2024-01-01 10:00:00",
        ]))
        clean = load_and_clean(df)
        times = clean["timestamp"].tolist()
        assert times == sorted(times)

    def test_drops_bad_timestamps(self):
        rows = failed_logins("1.2.3.4", "alice", ["2024-01-01 08:00:00"])
        rows.append({
            "timestamp": "NOT_A_DATE",
            "ip_address": "1.2.3.4",
            "username": "alice",
            "event_type": "login",
            "status": "failed",
        })
        df = make_df(rows)
        clean = load_and_clean(df)
        assert len(clean) == 1
        assert clean.attrs["dropped_bad_timestamps"] == 1

    def test_fills_missing_ip_address(self):
        df = make_df([{
            "timestamp": "2024-01-01 08:00:00",
            "ip_address": None,
            "username": "alice",
            "event_type": "login",
            "status": "failed",
        }])
        clean = load_and_clean(df)
        assert clean["ip_address"].iloc[0] == "unknown"

    def test_normalises_column_names(self):
        df = make_df([{
            "Timestamp": "2024-01-01 08:00:00",
            " IP_Address ": "1.2.3.4",
            "Username": "alice",
            "Event_Type": "login",
            "Status": "failed",
        }])
        clean = load_and_clean(df)
        assert "timestamp" in clean.columns


# ─── detect_brute_force ───────────────────────────────────────────────────────

class TestDetectBruteForce:

    # --- Basic triggering ---

    def test_no_alerts_when_below_threshold(self):
        df = make_df(failed_logins("1.2.3.4", "alice", [
            "2024-01-01 08:00:00",
            "2024-01-01 08:01:00",
            "2024-01-01 08:02:00",
            "2024-01-01 08:03:00",
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts == []

    def test_alert_triggered_at_threshold(self):
        df = make_df(failed_logins("1.2.3.4", "alice", [
            "2024-01-01 08:00:00",
            "2024-01-01 08:01:00",
            "2024-01-01 08:02:00",
            "2024-01-01 08:03:00",
            "2024-01-01 08:04:00",   # 5th → should trigger
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert len(alerts) == 1
        assert alerts[0].ip_address == "1.2.3.4"
        assert alerts[0].failed_count == 5

    def test_no_alert_for_success_logins(self):
        rows = [success_login("1.2.3.4", "alice", f"2024-01-01 08:0{i}:00") for i in range(8)]
        df = make_df(rows)
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts == []

    def test_events_outside_window_do_not_trigger(self):
        """5 failed logins spread over 30 minutes should not trigger a 10-min window."""
        df = make_df(failed_logins("1.2.3.4", "alice", [
            "2024-01-01 08:00:00",
            "2024-01-01 08:07:00",
            "2024-01-01 08:14:00",
            "2024-01-01 08:21:00",
            "2024-01-01 08:28:00",
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts == []

    def test_two_separate_bursts_produce_two_alerts(self):
        """Two distinct bursts from the same IP should produce two separate alerts."""
        burst1 = failed_logins("5.5.5.5", "alice", [
            "2024-01-01 08:00:00",
            "2024-01-01 08:01:00",
            "2024-01-01 08:02:00",
            "2024-01-01 08:03:00",
            "2024-01-01 08:04:00",
        ])
        burst2 = failed_logins("5.5.5.5", "alice", [
            "2024-01-01 09:00:00",
            "2024-01-01 09:01:00",
            "2024-01-01 09:02:00",
            "2024-01-01 09:03:00",
            "2024-01-01 09:04:00",
        ])
        df = make_df(burst1 + burst2)
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert len(alerts) == 2

    def test_different_ips_produce_independent_alerts(self):
        rows = (
            failed_logins("10.0.0.1", "alice", [
                "2024-01-01 08:00:00", "2024-01-01 08:01:00",
                "2024-01-01 08:02:00", "2024-01-01 08:03:00", "2024-01-01 08:04:00",
            ]) +
            failed_logins("10.0.0.2", "bob", [
                "2024-01-01 08:00:00", "2024-01-01 08:01:00",
                "2024-01-01 08:02:00", "2024-01-01 08:03:00", "2024-01-01 08:04:00",
            ])
        )
        df = make_df(rows)
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        ips = {a.ip_address for a in alerts}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    # --- Severity ---

    def test_severity_low_at_threshold(self):
        df = make_df(failed_logins("1.2.3.4", "u", [
            f"2024-01-01 08:0{i}:00" for i in range(5)
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts[0].severity == SEVERITY_LOW

    def test_severity_high_at_double_threshold(self):
        df = make_df(failed_logins("1.2.3.4", "u", [
            f"2024-01-01 08:{i:02d}:00" for i in range(10)
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=60)
        assert alerts[0].severity == SEVERITY_HIGH

    def test_severity_critical_at_4x_threshold(self):
        df = make_df(failed_logins("1.2.3.4", "u", [
            f"2024-01-01 08:{i:02d}:00" for i in range(20)
        ]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=60)
        assert alerts[0].severity == SEVERITY_CRITICAL

    # --- Multi-username ---

    def test_multi_username_note_in_reason(self):
        rows = [
            {"timestamp": f"2024-01-01 08:0{i}:00", "ip_address": "9.9.9.9",
             "username": name, "event_type": "login", "status": "failed"}
            for i, name in enumerate(["alice", "bob", "carol", "dave", "eve"])
        ]
        df = make_df(rows)
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert len(alerts) == 1
        assert "credential stuffing" in alerts[0].reason.lower()

    # --- Edge cases ---

    def test_empty_dataframe_returns_no_alerts(self):
        df = pd.DataFrame(columns=list(REQUIRED_COLUMNS))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts == []

    def test_only_success_events_returns_no_alerts(self):
        rows = [success_login("1.2.3.4", "alice", f"2024-01-01 08:0{i}:00")
                for i in range(8)]
        df = make_df(rows)
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        assert alerts == []

    def test_threshold_1_triggers_on_single_failure(self):
        df = make_df(failed_logins("1.2.3.4", "alice", ["2024-01-01 08:00:00"]))
        clean = load_and_clean(df)
        alerts = detect_brute_force(clean, threshold=1, window_minutes=10)
        assert len(alerts) == 1

    def test_custom_window_respected(self):
        """4 failures in 5 minutes → alert at 5-min window, no alert at 1-min window."""
        df = make_df(failed_logins("1.2.3.4", "alice", [
            "2024-01-01 08:00:00",
            "2024-01-01 08:01:00",
            "2024-01-01 08:02:00",
            "2024-01-01 08:03:00",
        ]))
        clean = load_and_clean(df)
        alerts_5min = detect_brute_force(clean, threshold=4, window_minutes=5)
        alerts_1min = detect_brute_force(clean, threshold=4, window_minutes=1)
        assert len(alerts_5min) == 1
        assert len(alerts_1min) == 0


# ─── alerts_to_dataframe ──────────────────────────────────────────────────────

class TestAlertsToDataframe:

    def test_empty_alerts_returns_empty_dataframe(self):
        df = alerts_to_dataframe([])
        assert len(df) == 0
        assert "ip_address" in df.columns

    def test_columns_present(self):
        rows = failed_logins("1.2.3.4", "alice", [
            f"2024-01-01 08:0{i}:00" for i in range(5)
        ])
        clean = load_and_clean(make_df(rows))
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        df = alerts_to_dataframe(alerts)
        expected = {
            "first_seen", "last_seen", "ip_address", "usernames",
            "failed_count", "window_minutes", "severity", "reason",
        }
        assert expected.issubset(set(df.columns))

    def test_alert_data_matches_source(self):
        rows = failed_logins("7.7.7.7", "testuser", [
            f"2024-01-01 08:0{i}:00" for i in range(5)
        ])
        clean = load_and_clean(make_df(rows))
        alerts = detect_brute_force(clean, threshold=5, window_minutes=10)
        df = alerts_to_dataframe(alerts)
        assert df.iloc[0]["ip_address"] == "7.7.7.7"
        assert df.iloc[0]["failed_count"] == 5
