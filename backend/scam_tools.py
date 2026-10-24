"""PishGuard MCP tool server.

Exposes read-only lookup tools that an AI model (or any MCP client) can call
to verify facts about a website instead of guessing from wording alone.
"""

import re
import socket
from datetime import datetime, timezone

import whois
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pishguard-tools")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")


def _clean(domain: str) -> str:
    """Accept only valid-looking domain names (input comes from scammers)."""
    d = domain.strip().lower()
    if not DOMAIN_RE.match(d):
        raise ValueError("Invalid domain name")
    return d


def _internet_ok() -> bool:
    """Quick check that this computer can resolve a well-known domain.

    Prevents a false 'this website does not exist' when the real problem
    is that the user's own internet connection is down.
    """
    try:
        socket.gethostbyname("example.com")
        return True
    except Exception:
        return False


@mcp.tool()
def domain_age(domain: str) -> dict:
    """Return how old a domain is, from WHOIS registration data."""
    d = _clean(domain)
    try:
        created = whois.whois(d).creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return {"domain": d, "found": False}
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - created).days
        return {
            "domain": d,
            "found": True,
            "created": created.date().isoformat(),
            "age_days": days,
        }
    except Exception as exc:
        return {"domain": d, "found": False, "error": type(exc).__name__}


@mcp.tool()
def resolve_ip(domain: str) -> dict:
    """Return the IP address a domain points to."""
    d = _clean(domain)
    try:
        return {"domain": d, "ip": socket.gethostbyname(d)}
    except socket.gaierror:
        if not _internet_ok():
            return {"domain": d, "ip": None, "error": "no_network"}
        return {"domain": d, "ip": None, "error": "gaierror"}
    except Exception as exc:
        return {"domain": d, "ip": None, "error": type(exc).__name__}


if __name__ == "__main__":
    mcp.run()
