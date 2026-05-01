@echo off
REM Wrapper: mcp-tap wrapping filesystem server for Group C
REM scenario_runner uses this as its --server command
C:\Users\Anna\AppData\Local\Programs\Python\Python311\python.exe C:\Users\Anna\PycharmProjects\mcp-tap\mcp_tap.py --server "mcp-server-filesystem C:\Users\Anna\PycharmProjects\mcp-tap\experiment\data" --log %1 --server-id filesystem --sensitivity redact
