@echo off
REM Group B: supergateway wrapping filesystem server (stdio -> SSE)
REM Bifrost connects to http://localhost:8000/sse

set DATA_DIR=C:\Users\Anna\PycharmProjects\mcp-tap\experiment\data

REM Use npx -y to invoke the package directly. Avoids the global .cmd shim
REM that supergateway's child-process spawn can't resolve correctly on
REM Windows when it has both a path-with-spaces and an argument.
npx supergateway --port 8000 --stdio "npx -y @modelcontextprotocol/server-filesystem %DATA_DIR%"
