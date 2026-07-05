"""MyFitnessPal MCP Server - deployable remote MCP connector for MyFitnessPal.

Tool implementations ported from AdamWalt/myfitnesspal-mcp-python (MIT);
OAuth/transport skeleton mirrors garmin-mcp-service.
"""

__version__ = "1.2.0"

from myfitnesspal_mcp.server import main, mcp

__all__ = ["main", "mcp", "__version__"]
