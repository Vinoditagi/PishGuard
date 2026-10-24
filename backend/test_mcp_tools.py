
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


SERVER_FILE = Path(__file__).resolve().with_name("scam_tools.py")


async def main():
    if not SERVER_FILE.is_file():
        raise FileNotFoundError(f"MCP server file not found: {SERVER_FILE}")

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_FILE)],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.list_tools()
            tool_names = [tool.name for tool in result.tools]
            print("Tools found:", tool_names)

            required_tools = {"domain_age", "resolve_ip"}
            missing_tools = required_tools - set(tool_names)
            if missing_tools:
                raise RuntimeError(f"Missing MCP tools: {sorted(missing_tools)}")

            result = await session.call_tool(
                "domain_age", {"domain": "google.com"}
            )
            print("domain_age:", result.content)

            result = await session.call_tool(
                "resolve_ip", {"domain": "google.com"}
            )
            print("resolve_ip:", result.content)

            print("MCP tool integration test passed.")


if __name__ == "__main__":
    asyncio.run(main())
