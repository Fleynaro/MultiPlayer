"""Local HTTP bridge for running GTA Python scripts from external agents."""

from __future__ import annotations

import io
import json
import runpy
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import gta

HOST = "127.0.0.1"
PORT = 8765
SCRIPTS_DIRECTORY = Path(__file__).resolve().parent
RUN_LOCK = threading.Lock()


def _resolve_script(raw_path: str) -> Path:
    """Resolve a requested script and keep it inside the configured scripts directory."""
    requested = Path(raw_path)
    candidate = (
        SCRIPTS_DIRECTORY / requested if not requested.is_absolute() else requested
    ).resolve(strict=True)
    if candidate == Path(__file__).resolve():
        raise ValueError("agent_server.py cannot execute itself")
    if candidate.parent != SCRIPTS_DIRECTORY or candidate.suffix.lower() != ".py":
        raise ValueError(
            "path must identify a .py file directly inside the scripts directory"
        )
    return candidate


def _run_script(raw_path: str) -> dict[str, object]:
    """Execute one script and return everything it wrote to stdout and stderr."""

    class Tee:
        def __init__(self, *streams):
            self.streams = streams

        def write(self, data):
            for stream in self.streams:
                stream.write(data)
            return len(data)

        def flush(self):
            for stream in self.streams:
                stream.flush()

    script = _resolve_script(raw_path)
    stdout = io.StringIO()
    stderr = io.StringIO()
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    with (
        RUN_LOCK,
        redirect_stdout(Tee(stdout, original_stdout)),
        redirect_stderr(Tee(stderr, original_stderr)),
    ):
        try:
            runpy.run_path(str(script), run_name="__main__")
        except Exception as error:
            return {
                "ok": False,
                "path": str(script),
                "stdout": stdout.getvalue(),
                "stderr": stderr.getvalue(),
                "error": f"{type(error).__name__}: {error}",
            }
    return {
        "ok": True,
        "path": str(script),
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
        "error": None,
    }


class AgentRequestHandler(BaseHTTPRequestHandler):
    """Handle the small query-string based API exposed to local agents."""

    server_version = "GtaAgentServer/1.0"

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler.
        request = urlsplit(self.path)
        if request.path != "/run":
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"ok": False, "error": "endpoint must be POST /run"},
            )
            return

        parameters = parse_qs(request.query, keep_blank_values=True)
        paths = parameters.get("path", [])
        if len(paths) != 1 or not paths[0]:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "error": "POST /run requires exactly one non-empty path query parameter",
                },
            )
            return

        try:
            result = _run_script(paths[0])
        except (OSError, ValueError) as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)})
            return
        status = HTTPStatus.OK if result["ok"] else HTTPStatus.INTERNAL_SERVER_ERROR
        self._send_json(status, result)

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print("[agent-server] " + (format % args))


def main() -> None:
    """Run the HTTP server until the embedded runtime requests a stop."""
    server = ThreadingHTTPServer((HOST, PORT), AgentRequestHandler)
    server_thread = threading.Thread(
        target=server.serve_forever, name="GtaAgentHttpServer", daemon=True
    )
    server_thread.start()
    print(f"Agent HTTP server listening on http://{HOST}:{PORT}")
    try:
        while not gta.stop_requested():
            threading.Event().wait(0.1)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join()
        print("Agent HTTP server stopped")


if __name__ == "__main__":
    main()
