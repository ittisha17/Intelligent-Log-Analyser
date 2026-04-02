# threat_intel.py
# Threat Intelligence Enrichment Layer
# Adds AbuseIPDB reputation scoring + GeoIP country/city lookup to detected threats.
#
# Dependencies:
#   pip install requests geoip2
#
# Setup:
#   1. Get a free AbuseIPDB API key → https://www.abuseipdb.com/register
#   2. Download free GeoLite2-City.mmdb from MaxMind → https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
#      Place the .mmdb file in your project root (same folder as app.py)
#   3. Add to your .env:
#      ABUSEIPDB_API_KEY=your_key_here

import os
import time
import threading
from functools import lru_cache

import requests

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────

ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
GEOIP_DB_PATH   = os.getenv("GEOIP_DB_PATH", "GeoLite2-City.mmdb")

# IPs to never query (saves API quota)
PRIVATE_RANGES = [
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "0.", "::1", "localhost",
]

# Simple in-process cache so the same IP is only looked up once per session.
# Key: ip string  →  Value: enriched dict
_reputation_cache: dict = {}
_cache_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    """Return True if the IP is RFC-1918 / loopback — skip external lookups."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_RANGES)


def _empty_intel(ip: str, reason: str = "") -> dict:
    """Return a safe default intel dict when enrichment is unavailable."""
    return {
        "ip":            ip,
        "abuse_score":   0,
        "abuse_reports": 0,
        "country_code":  "N/A",
        "country_name":  "Unknown",
        "city":          "Unknown",
        "isp":           "Unknown",
        "domain":        "Unknown",
        "is_tor":        False,
        "threat_label":  "Unknown",
        "note":          reason,
    }

# ── GeoIP ─────────────────────────────────────────────────────────────────────

def _geoip_lookup(ip: str) -> dict:
    """
    Look up country + city from the local MaxMind GeoLite2 database.
    Returns a partial dict merged into the final result.
    Falls back gracefully if the DB file is missing.
    """
    if not GEOIP_AVAILABLE:
        return {"country_code": "N/A", "country_name": "No geoip2 library",
                "city": "N/A"}

    if not os.path.exists(GEOIP_DB_PATH):
        return {"country_code": "N/A", "country_name": "GeoIP DB not found",
                "city": "N/A"}

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            return {
                "country_code": response.country.iso_code or "N/A",
                "country_name": response.country.name or "Unknown",
                "city":         response.city.name or "Unknown",
            }
    except geoip2.errors.AddressNotFoundError:
        return {"country_code": "N/A", "country_name": "Not in DB", "city": "N/A"}
    except Exception as e:
        return {"country_code": "N/A", "country_name": f"GeoIP error: {e}", "city": "N/A"}

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def _abuseipdb_lookup(ip: str) -> dict:
    """
    Query AbuseIPDB for the reputation score of a single IP.
    Returns a partial dict merged into the final result.

    Free tier: 1,000 checks/day.
    We request reports from the last 90 days for the richest signal.
    """
    if not ABUSEIPDB_KEY:
        return {
            "abuse_score":   0,
            "abuse_reports": 0,
            "isp":           "No API key set",
            "domain":        "N/A",
            "is_tor":        False,
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_score":   data.get("abuseConfidenceScore", 0),
            "abuse_reports": data.get("totalReports", 0),
            "isp":           data.get("isp", "Unknown"),
            "domain":        data.get("domain", "Unknown"),
            "is_tor":        data.get("isTor", False),
        }
    except requests.exceptions.Timeout:
        return {"abuse_score": 0, "abuse_reports": 0,
                "isp": "Timeout", "domain": "N/A", "is_tor": False}
    except requests.exceptions.RequestException as e:
        return {"abuse_score": 0, "abuse_reports": 0,
                "isp": f"Error: {e}", "domain": "N/A", "is_tor": False}

# ── Threat label ──────────────────────────────────────────────────────────────

def _threat_label(abuse_score: int, is_tor: bool) -> str:
    """
    Convert a numeric AbuseIPDB score into a human-readable threat label.
    These map directly to what a SOC analyst would call them.
    """
    if is_tor:
        return "TOR Exit Node"
    if abuse_score >= 80:
        return "Known Malicious"
    if abuse_score >= 50:
        return "Highly Suspicious"
    if abuse_score >= 20:
        return "Suspicious"
    if abuse_score >= 1:
        return "Low Risk"
    return "Clean"

# ── Public API ────────────────────────────────────────────────────────────────

def enrich_ip(ip: str) -> dict:
    """
    Main enrichment function. Returns a unified intel dict for a single IP.

    Checks the in-process cache first so each IP is only queried once
    per Streamlit session (survives reruns, resets on restart).

    Usage:
        intel = enrich_ip("1.2.3.4")
        print(intel["country_name"], intel["abuse_score"], intel["threat_label"])
    """
    ip = ip.strip()

    # 1. Cache hit
    with _cache_lock:
        if ip in _reputation_cache:
            return _reputation_cache[ip]

    # 2. Skip private / loopback addresses
    if _is_private(ip):
        result = _empty_intel(ip, reason="Private/loopback address")
        with _cache_lock:
            _reputation_cache[ip] = result
        return result

    # 3. Run GeoIP (local, fast) and AbuseIPDB (remote) in parallel
    geo_result  = {}
    abuse_result = {}

    def _geo():
        nonlocal geo_result
        geo_result = _geoip_lookup(ip)

    def _abuse():
        nonlocal abuse_result
        abuse_result = _abuseipdb_lookup(ip)

    t1 = threading.Thread(target=_geo,   daemon=True)
    t2 = threading.Thread(target=_abuse, daemon=True)
    t1.start(); t2.start()
    t1.join();  t2.join()

    # 4. Merge into a single intel dict
    abuse_score = abuse_result.get("abuse_score", 0)
    is_tor      = abuse_result.get("is_tor", False)

    result = {
        "ip":            ip,
        "abuse_score":   abuse_score,
        "abuse_reports": abuse_result.get("abuse_reports", 0),
        "country_code":  geo_result.get("country_code", "N/A"),
        "country_name":  geo_result.get("country_name", "Unknown"),
        "city":          geo_result.get("city", "Unknown"),
        "isp":           abuse_result.get("isp", "Unknown"),
        "domain":        abuse_result.get("domain", "Unknown"),
        "is_tor":        is_tor,
        "threat_label":  _threat_label(abuse_score, is_tor),
        "note":          "",
    }

    # 5. Store in cache
    with _cache_lock:
        _reputation_cache[ip] = result

    return result


def enrich_threats(threats: list[dict]) -> list[dict]:
    """
    Enrich a list of threat dicts (output of detect_threats + calculate_risk)
    with intel data. Adds intel fields directly onto each threat dict.

    This is what you call in app.py:
        threats = enrich_threats(threats)

    Uses a thread pool so N unique IPs are looked up concurrently.
    """
    if not threats:
        return threats

    # Deduplicate IPs so we don't fire duplicate requests for the same IP
    unique_ips = list({t["ip"] for t in threats if "ip" in t})

    # Enrich all unique IPs concurrently (max 10 threads to respect rate limits)
    results: dict = {}
    lock = threading.Lock()

    def _worker(ip):
        intel = enrich_ip(ip)
        with lock:
            results[ip] = intel

    threads = []
    for ip in unique_ips:
        t = threading.Thread(target=_worker, args=(ip,), daemon=True)
        threads.append(t)
        t.start()
        # Stagger slightly to avoid hammering AbuseIPDB
        time.sleep(0.05)

    for t in threads:
        t.join(timeout=10)  # Don't block UI forever if an IP times out

    # Merge intel into each threat
    for threat in threats:
        ip    = threat.get("ip", "")
        intel = results.get(ip, _empty_intel(ip, "No result"))
        threat.update({
            "country":       f"{intel['country_name']} ({intel['country_code']})",
            "city":          intel["city"],
            "isp":           intel["isp"],
            "abuse_score":   intel["abuse_score"],
            "threat_label":  intel["threat_label"],
            "is_tor":        intel["is_tor"],
        })

    return threats


def clear_cache():
    """Clear the in-process IP reputation cache. Useful for testing."""
    with _cache_lock:
        _reputation_cache.clear()