@echo off
REM Group B: supergateway wrapping filesystem server (stdio -> SSE)
REM Bifrost connects to http://localhost:8000/sse

set DATA_DIR=C:\Users\Anna\PycharmProjects\mcp-tap\experiment\data

npx supergateway --port 8000 --stdio "mcp-server-filesystem %DATA_DIR%"
