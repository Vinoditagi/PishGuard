import asyncio
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS_PATH = str(Path(__file__).resolve().parent / "scam_tools.py")
URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
MAX_DOMAINS = 3
TIMEOUT_SECONDS = 25


def extract_domains(message="", url=""):
    candidates = []
    if url:
        candidates.append(url)
    candidates += URL_RE.findall(message or "")

    domains = []
    for c in candidates:
        if not c.lower().startswith("http"):
            c = "http://" + c
        host = urlparse(c).hostname
        if host:
            host = host.lower().rstrip(".")
            if host not in domains:
                domains.append(host)
    return domains[:MAX_DOMAINS]


async def _call(session, tool, domain):
    try:
        result = await session.call_tool(tool, {"domain": domain})
        if result.isError:
            return {"error": "tool_error"}
        return json.loads(result.content[0].text)
    except Exception as exc:
        return {"error": type(exc).__name__}


async def _gather(domains):
    params = StdioServerParameters(command=sys.executable, args=[TOOLS_PATH])
    evidence = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for d in domains:
                evidence.append({
                    "domain": d,
                    "age": await _call(session, "domain_age", d),
                    "ip": await _call(session, "resolve_ip", d),
                })
    return evidence


def gather_evidence(message="", url=""):
    domains = extract_domains(message, url)
    if not domains:
        return []
    try:
        return asyncio.run(
            asyncio.wait_for(_gather(domains), timeout=TIMEOUT_SECONDS)
        )
    except Exception as exc:
        print(f"MCP evidence failed: {type(exc).__name__}: {exc}")
        return []
