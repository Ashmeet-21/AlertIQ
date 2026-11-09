import ipaddress
import logging
from functools import lru_cache
import httpx

logger = logging.getLogger(__name__)

# Static asset registry — extend with real CMDB data as needed
ASSET_REGISTRY: dict[str, dict] = {
    "10.0.0.1":          {"asset_name": "core-router-01",        "asset_type": "network_device",  "criticality": "critical"},
    "10.0.0.2":          {"asset_name": "firewall-01",           "asset_type": "security_device", "criticality": "critical"},
    "192.168.1.1":       {"asset_name": "office-gateway",        "asset_type": "network_device",  "criticality": "high"},
    "dc01":              {"asset_name": "domain-controller-01",  "asset_type": "server",          "criticality": "critical"},
    "dc01.corp.local":   {"asset_name": "domain-controller-01",  "asset_type": "server",          "criticality": "critical"},
    "fileserver01":      {"asset_name": "file-server-01",        "asset_type": "server",          "criticality": "high"},
}

_UNKNOWN_ASSET = {"asset_name": "unknown", "asset_type": "unknown", "criticality": "unknown"}
_GEO_FALLBACK  = {"country": "unknown", "org": "unknown", "is_proxy": False, "is_hosting": False}


def _is_internal(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False


@lru_cache(maxsize=1024)   # ip-api.com free tier allows 45 requests/min: don't re-ask for the same IP
def _geo_lookup_cached(ip_str: str) -> tuple:
    geo = _geo_lookup_uncached(ip_str)
    if geo == _GEO_FALLBACK:
        raise LookupError   # don't cache failures
    return tuple(geo.items())


def _geo_lookup(ip_str: str) -> dict:
    try:
        return dict(_geo_lookup_cached(ip_str))
    except LookupError:
        return dict(_GEO_FALLBACK)


def _geo_lookup_uncached(ip_str: str) -> dict:
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip_str}",
            params={"fields": "country,org,isp,proxy,hosting"},
            timeout=2.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "country":    data.get("country", "unknown"),
                "org":        data.get("org", "unknown"),
                "is_proxy":   bool(data.get("proxy", False)),
                "is_hosting": bool(data.get("hosting", False)),
            }
    except Exception as exc:
        logger.warning(f"[enricher] geo lookup failed for {ip_str}: {exc}")
    return dict(_GEO_FALLBACK)


def get_ip_reputation(ip_str: str) -> dict:
    if not ip_str:
        return {"is_internal": False, **_GEO_FALLBACK}
    if _is_internal(ip_str):
        return {"is_internal": True, "country": "internal", "org": "internal", "is_proxy": False, "is_hosting": False}
    geo = _geo_lookup(ip_str)
    return {"is_internal": False, **geo}


def get_asset_info(*keys: str) -> dict:
    for key in keys:
        if key and key in ASSET_REGISTRY:
            return ASSET_REGISTRY[key]
    return dict(_UNKNOWN_ASSET)


def enrich(normalized: dict) -> dict:
    source_ip = normalized.get("source.ip", "")
    dest_ip   = normalized.get("destination.ip", "")
    hostname  = normalized.get("host.name", "")

    rep   = get_ip_reputation(source_ip)
    # The asset at risk is the target (host / destination), not the attacker's IP
    asset = get_asset_info(hostname, dest_ip, source_ip)

    return {
        "enrichment.source_ip.is_internal": rep["is_internal"],
        "enrichment.source_ip.country":     rep["country"],
        "enrichment.source_ip.org":         rep["org"],
        "enrichment.source_ip.is_proxy":    rep["is_proxy"],
        "enrichment.source_ip.is_hosting":  rep["is_hosting"],
        "enrichment.asset.name":            asset["asset_name"],
        "enrichment.asset.type":            asset["asset_type"],
        "enrichment.asset.criticality":     asset["criticality"],
    }
