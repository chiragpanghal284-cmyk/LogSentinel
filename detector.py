"""
detector.py — LogSentinel Detection Engine
============================================
Responsible for all detection logic, completely separated from the UI layer.

DISCLAIMER: This tool uses transparent, rule-based heuristics for educational
purposes only. A flagged IP does not automatically prove an attack — it
indicates activity that warrants further investigation by a human analyst.
"""

from __future__ import annotations

import pandas as pd
from dataclasses import dataclass, field
from typing import Optional

# ─── Required columns in every uploaded log file ─────────────────────────────
REQUIRED_COLUMNS = {"timestamp", "ip_address", "username", "event_type", "status"}

# ─── Severity levels (expandable) ────────────────────────────────────────────
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


@dataclass
class ValidationResult:
    """Carries the outcome of CSV validation."""
    ok: bool
    errors: list[str] = field(default_factory=list)


@dataclass
class Alert:
    """A single suspicious-activity alert."""
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    ip_address: str
    usernames: str          # comma-separated distinct usernames attempted
    failed_count: int
    window_minutes: int
    severity: str
    reason: str


def validate_log_dataframe(df: pd.DataFrame) -> ValidationResult:
    """
    Check that the uploaded DataFrame has the required columns and at least one
    parseable timestamp. Returns a ValidationResult with human-readable errors.
    """
    errors: list[str] = []

    missing = REQUIRED_COLUMNS - set(df.columns.str.lower().str.strip())
    if missing:
        errors.append(f"Missing required column(s): {', '.join(sorted(missing))}")
        return ValidationResult(ok=False, errors=errors)

    # Normalise column names in-place
    df.columns = df.columns.str.lower().str.strip()

    if df.empty:
        errors.append("The uploaded file contains no data rows.")
        return ValidationResult(ok=False, errors=errors)

    # Try parsing timestamps on a small sample to catch obvious issues early
    sample = df["timestamp"].dropna().head(5)
    if sample.empty:
        errors.append("The 'timestamp' column contains no usable values.")
        return ValidationResult(ok=False, errors=errors)

    try:
        pd.to_datetime(sample)
    except Exception as exc:
        errors.append(f"Could not parse 'timestamp' column: {exc}")
        return ValidationResult(ok=False, errors=errors)

    return ValidationResult(ok=True)


def load_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalise column names, parse timestamps, drop rows with unparseable
    timestamps, and fill missing optional fields with safe defaults.
    Returns a clean copy of the DataFrame sorted by timestamp.
    """
    df = df.copy()
    df.columns = df.columns.str.lower().str.strip()

    # Parse timestamps; coerce bad values to NaT
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    bad_ts = df["timestamp"].isna().sum()
    df = df.dropna(subset=["timestamp"])

    # Fill missing string fields safely
    df["ip_address"] = df["ip_address"].fillna("unknown").astype(str).str.strip()
    df["username"] = df["username"].fillna("unknown").astype(str).str.strip()
    df["event_type"] = df["event_type"].fillna("unknown").astype(str).str.strip().str.lower()
    df["status"] = df["status"].fillna("unknown").astype(str).str.strip().str.lower()

    df = df.sort_values("timestamp").reset_index(drop=True)
    df.attrs["dropped_bad_timestamps"] = int(bad_ts)
    return df


def _assign_severity(failed_count: int, threshold: int) -> str:
    """Map a failed-attempt count to a severity level."""
    ratio = failed_count / threshold
    if ratio >= 4:
        return SEVERITY_CRITICAL
    if ratio >= 2:
        return SEVERITY_HIGH
    if ratio >= 1.5:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def detect_brute_force(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """
    Detect brute-force / credential-stuffing patterns by looking for IP addresses
    that accumulate ≥ *threshold* failed authentication events inside any rolling
    *window_minutes*-minute window.

    Detection rule (transparent):
      1. Filter rows where event_type is 'login' (or 'authentication') AND
         status is 'failed' (or 'failure').
      2. Group by ip_address.
      3. For each group, slide a time window of *window_minutes* minutes across
         the ordered timestamps.  Count events inside the window.
      4. When the count first reaches *threshold*, record an alert and advance
         the window start past the last counted event to avoid double-alerting
         on the same burst.

    Returns a list of Alert objects (one per suspicious burst per IP).
    """
    alerts: list[Alert] = []

    # Filter to relevant failed login events
    failed_mask = (
        df["event_type"].isin({"login", "authentication", "auth"})
        & df["status"].isin({"failed", "failure", "fail"})
    )
    failed_df = df[failed_mask].copy()

    if failed_df.empty:
        return alerts

    for ip, group in failed_df.groupby("ip_address"):
        times = group["timestamp"].reset_index(drop=True)
        usernames_series = group["username"].reset_index(drop=True)
        n = len(times)
        window_td = pd.Timedelta(minutes=window_minutes)

        i = 0
        while i < n:
            window_start = times[i]
            window_end = window_start + window_td

            # Collect indices that fall inside this window
            in_window = times[(times >= window_start) & (times <= window_end)]

            if len(in_window) >= threshold:
                last_idx = in_window.index[-1]
                distinct_users = usernames_series.iloc[i : last_idx + 1].unique()
                count = len(in_window)

                severity = _assign_severity(count, threshold)
                multi_user_note = (
                    " Attempts span multiple usernames (possible credential stuffing)."
                    if len(distinct_users) > 1
                    else ""
                )

                alert = Alert(
                    first_seen=times[i],
                    last_seen=times[last_idx],
                    ip_address=str(ip),
                    usernames=", ".join(str(u) for u in distinct_users),
                    failed_count=count,
                    window_minutes=window_minutes,
                    severity=severity,
                    reason=(
                        f"{count} failed login attempt(s) from this IP within a "
                        f"{window_minutes}-minute window (threshold: {threshold}).{multi_user_note}"
                    ),
                )
                alerts.append(alert)
                # Advance past the last counted event to avoid re-alerting same burst
                i = last_idx + 1
            else:
                i += 1

    return alerts


def alerts_to_dataframe(alerts: list[Alert]) -> pd.DataFrame:
    """Convert a list of Alert objects to a tidy DataFrame for display / export."""
    if not alerts:
        return pd.DataFrame(columns=[
            "first_seen", "last_seen", "ip_address", "usernames",
            "failed_count", "window_minutes", "severity", "reason",
        ])
    rows = [
        {
            "first_seen": a.first_seen,
            "last_seen": a.last_seen,
            "ip_address": a.ip_address,
            "usernames": a.usernames,
            "failed_count": a.failed_count,
            "window_minutes": a.window_minutes,
            "severity": a.severity,
            "reason": a.reason,
        }
        for a in alerts
    ]
    return pd.DataFrame(rows)
