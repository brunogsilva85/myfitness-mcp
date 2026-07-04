FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency installation
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Install the package and dependencies (non-editable for Docker)
RUN uv pip install --system .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --uid 1000 mcpuser

# Mount point for a (read-only) Firefox profile containing a logged-in
# myfitnesspal.com session; see MFP_FIREFOX_PROFILE_DIR in the README.
RUN mkdir -p /profile && chown mcpuser:mcpuser /profile

# Copy and set up entrypoint script
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

USER mcpuser

# Expose MCP HTTP port
EXPOSE 8000

# Configure for HTTP transport
ENV MCP_TRANSPORT=streamable-http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MFP_FIREFOX_PROFILE_DIR=/profile

# Health check - verify the port is accepting connections
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(5); r=s.connect_ex(('localhost',8000)); s.close(); sys.exit(0 if r==0 else 1)"

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "-m", "myfitnesspal_mcp.server"]
