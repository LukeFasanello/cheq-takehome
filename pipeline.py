"""
CHEQ Automated Threat Mitigation Pipeline
------------------------------------------
Fetches raw traffic logs, detects malicious sessions using rule-based logic,
simulates firewall blocking, calculates saved ad spend, and outputs structured
JSON files for the dashboard.

Designed to run unattended (e.g. via cron: `0 * * * * python pipeline.py`).
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import pandas as pd
import requests

import re
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DATA_URL = "https://cheq.free.nf/sample-traffic-data.csv"
RESULTS_FILE = "results.json"
BLOCKED_IPS_FILE = "blocked_ips.json"
SUMMARY_FILE = "summary.json"

CPC = 5.00  # cost-per-click in USD
BOT_THRESHOLD = 80
SUSPICIOUS_THRESHOLD = 40
VELOCITY_WINDOW_SECONDS = 60
VELOCITY_MAX_VIEWS = 10
BLOCKLISTED_COUNTRIES = {"China", "Russia"}
BOT_UA_KEYWORDS = ["bot", "crawl", "spider", "scraper", "wget", "curl", "python-requests"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def solve_js_challenge(html: str) -> str:
    """Extract AES params from the challenge page and decrypt the cookie value."""
    a = bytes.fromhex(re.search(r'toNumbers\("([a-f0-9]+)"\),b=', html).group(1))
    b = bytes.fromhex(re.search(r'toNumbers\("([a-f0-9]+)"\),c=', html).group(1))
    c = bytes.fromhex(re.search(r'toNumbers\("([a-f0-9]+)"\);document', html).group(1))

    cipher = AES.new(a, AES.MODE_CBC, iv=b)
    decrypted = cipher.decrypt(c)
    return decrypted.hex()

# ---------------------------------------------------------------------------
# Step 1: Fetch Data
# ---------------------------------------------------------------------------

def fetch_data(url: str) -> pd.DataFrame:
    log.info(f"Fetching traffic data from {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    session = requests.Session()

    # First request — may return JS challenge
    response = session.get(url, headers=headers, timeout=15)
    
    if "slowAES" in response.text:
        log.info("JS challenge detected, solving...")
        cookie_value = solve_js_challenge(response.text)
        session.cookies.set("__test", cookie_value)
        # Follow the redirect with ?i=1 and the cookie set
        response = session.get(url + "?i=1", headers=headers, timeout=15)

    response.raise_for_status()
    from io import StringIO
    df = pd.read_csv(StringIO(response.text))
    log.info(f"Loaded {len(df)} sessions")
    return df


# ---------------------------------------------------------------------------
# Step 2: Detection Rules
# ---------------------------------------------------------------------------

def check_velocity(df: pd.DataFrame) -> pd.Series:
    """
    Flag sessions where the same IP has > 10 page views within any 60-second window.
    Returns a boolean Series (True = flagged).
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values(["ip_address", "timestamp"])

    flagged = pd.Series(False, index=df.index)

    for ip, group in df.groupby("ip_address"):
        times = group["timestamp"].dropna().tolist()
        if len(times) <= VELOCITY_MAX_VIEWS:
            continue
        # Sliding window: for each event, count how many events fall within 60s
        for i, t in enumerate(times):
            window_end = t + timedelta(seconds=VELOCITY_WINDOW_SECONDS)
            count = sum(1 for other_t in times if t <= other_t <= window_end)
            if count > VELOCITY_MAX_VIEWS:
                flagged.loc[group.index[i]] = True

    return flagged


def check_impossible_behavior(df: pd.DataFrame) -> pd.Series:
    """Flag sessions with 0 time on page but form_submitted = true."""
    time_zero = pd.to_numeric(df["time_on_page"], errors="coerce").fillna(0) == 0
    form_submitted = df["form_submitted"].astype(str).str.lower().isin(["true", "1", "yes"])
    return time_zero & form_submitted


def check_bot_user_agent(df: pd.DataFrame) -> pd.Series:
    """Flag sessions with bot-like or empty user agent strings."""
    ua = df["user_agent"].fillna("").str.lower()
    is_empty = ua.str.strip() == ""
    has_keyword = ua.apply(lambda s: any(kw in s for kw in BOT_UA_KEYWORDS))
    return is_empty | has_keyword


def check_geofencing(df: pd.DataFrame) -> pd.Series:
    """Flag sessions from blocklisted countries."""
    return df["country"].isin(BLOCKLISTED_COUNTRIES)


def calculate_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run all detection rules and compute a risk_score (0-100) and verdict per session.

    Scoring weights:
        Velocity check         -> +40 pts
        Impossible behavior    -> +35 pts
        Bot user agent         -> +30 pts
        Geofencing             -> +25 pts

    Scores are capped at 100. Multiple flags stack.

    Verdicts:
        0  - 40  -> Valid
        41 - 80  -> Suspicious
        81 - 100 -> Bot
    """
    df = df.copy()

    log.info("Running detection rules...")

    velocity_flag      = check_velocity(df)
    impossible_flag    = check_impossible_behavior(df)
    bot_ua_flag        = check_bot_user_agent(df)
    geo_flag           = check_geofencing(df)

    df["flag_velocity"]   = velocity_flag
    df["flag_impossible"] = impossible_flag
    df["flag_bot_ua"]     = bot_ua_flag
    df["flag_geo"]        = geo_flag

    df["risk_score"] = (
        velocity_flag.astype(int)   * 40 +
        impossible_flag.astype(int) * 35 +
        bot_ua_flag.astype(int)     * 30 +
        geo_flag.astype(int)        * 25
    ).clip(upper=100)

    def assign_verdict(score):
        if score > BOT_THRESHOLD:
            return "Bot"
        elif score > SUSPICIOUS_THRESHOLD:
            return "Suspicious"
        return "Valid"

    df["verdict"] = df["risk_score"].apply(assign_verdict)

    log.info(
        f"Detection complete — "
        f"Valid: {(df['verdict'] == 'Valid').sum()}, "
        f"Suspicious: {(df['verdict'] == 'Suspicious').sum()}, "
        f"Bot: {(df['verdict'] == 'Bot').sum()}"
    )

    return df


# ---------------------------------------------------------------------------
# Step 3: Remediation
# ---------------------------------------------------------------------------

def run_remediation(df: pd.DataFrame) -> dict:
    """
    For confirmed bots (risk_score > 80):
      - Write their IPs to blocked_ips.json
      - Calculate total saved ad spend
    Returns a summary dict.
    """
    bots = df[df["verdict"] == "Bot"].copy()
    clicks = pd.to_numeric(bots["clicks"], errors="coerce").fillna(0)
    saved_spend = round(float(clicks.sum() * CPC), 2)
    blocked_ips = sorted(bots["ip_address"].dropna().unique().tolist())

    blocked_payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "blocked_ips": blocked_ips,
    }

    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(blocked_payload, f, indent=2)

    log.info(f"Blocked {len(blocked_ips)} IPs -> {BLOCKED_IPS_FILE}")
    log.info(f"Estimated saved spend: ${saved_spend:,.2f}")

    return {
        "blocked_ips": blocked_ips,
        "saved_spend": saved_spend,
    }


# ---------------------------------------------------------------------------
# Step 4: Write Outputs
# ---------------------------------------------------------------------------

def write_results(df: pd.DataFrame):
    """Write enriched session data to results.json."""
    records = df.to_dict(orient="records")
    # Convert any non-serializable types
    for r in records:
        for k, v in r.items():
            if pd.isna(v) if not isinstance(v, (list, dict)) else False:
                r[k] = None
            elif hasattr(v, "item"):       # numpy scalar
                r[k] = v.item()
            elif hasattr(v, "isoformat"):  # datetime
                r[k] = v.isoformat()

    with open(RESULTS_FILE, "w") as f:
        json.dump(records, f, indent=2)

    log.info(f"Results written -> {RESULTS_FILE}")


def write_summary(df: pd.DataFrame, remediation: dict):
    """Write pre-aggregated KPIs to summary.json for the dashboard."""
    total_sessions      = len(df)
    total_valid         = int((df["verdict"] == "Valid").sum())
    total_suspicious    = int((df["verdict"] == "Suspicious").sum())
    total_bots          = int((df["verdict"] == "Bot").sum())
    blocked_ip_count    = len(remediation["blocked_ips"])
    saved_spend         = remediation["saved_spend"]

    # Fake form fills blocked = impossible behavior sessions that are also Bots
    fake_form_fills = int(
        (df["flag_impossible"] & (df["verdict"] == "Bot")).sum()
    )

    # Recent threats for the dashboard table (last 10 bot sessions)
    bot_sessions = (
        df[df["verdict"] == "Bot"]
        .sort_values("timestamp", ascending=False)
        .head(10)[["timestamp", "ip_address", "country", "user_agent", "risk_score", "verdict"]]
    )
    # Safely convert to records
    recent_threats = []
    for _, row in bot_sessions.iterrows():
        recent_threats.append({
            "timestamp":  str(row["timestamp"]),
            "ip_address": str(row["ip_address"]),
            "country":    str(row["country"]),
            "user_agent": str(row["user_agent"]),
            "risk_score": int(row["risk_score"]),
            "verdict":    str(row["verdict"]),
        })

    summary = {
        "generated_at":        datetime.now(timezone.utc).isoformat(),
        "total_sessions":      total_sessions,
        "total_valid":         total_valid,
        "total_suspicious":    total_suspicious,
        "total_bots":          total_bots,
        "blocked_ip_count":    blocked_ip_count,
        "saved_spend":         saved_spend,
        "fake_form_fills":     fake_form_fills,
        "recent_threats":      recent_threats,
    }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    log.info(f"Summary written -> {SUMMARY_FILE}")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def run():
    log.info("=== CHEQ Threat Mitigation Pipeline Starting ===")

    df = fetch_data(DATA_URL)
    df = calculate_risk_scores(df)
    remediation = run_remediation(df)
    write_results(df)
    write_summary(df, remediation)

    log.info("=== Pipeline Complete ===")


if __name__ == "__main__":
    run()
