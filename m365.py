#!/usr/bin/env python3
"""
m365_copilot_mcp.py — single-file MCP server that answers questions via the
M365 Copilot web app, driven by Playwright against the system's installed
Microsoft Edge (channel="msedge" — no separate browser binary download).

Hand-rolled JSON-RPC 2.0 over stdio (newline-delimited messages), no MCP SDK.
Selectors confirmed live against the M365 Copilot web chat on 2026-08-02; if
Microsoft changes the markup, update SELECTORS below.

Setup (once per machine):
    pip install playwright

Usage:
    python m365_copilot_mcp.py login   # one-time (or after session expiry): opens
                                        # a visible Edge window, sign in + MFA by hand.
                                        # Auto-detects success and saves the session —
                                        # no keypress needed, just watch the window.
    python m365_copilot_mcp.py serve   # runs the MCP server on stdio (default if no arg)

Register in VS Code's mcp.json (user-level, so it's available in every
workspace — do NOT add "cwd": "${workspaceFolder}" here: that variable only
resolves when a folder is open, and breaks server startup in empty windows.
Tool calls should pass ABSOLUTE file_paths instead, which work regardless):
    {
      "servers": {
        "m365-copilot": {
          "command": "python",
          "args": ["C:\\full\\path\\to\\m365_copilot_mcp.py", "serve"]
        }
      }
    }

The login session is stored in a folder next to this script (or wherever
M365_COPILOT_PROFILE_DIR points), so copying just this one .py file to another
machine gets you the code — you still need to run `login` once there too, since
the session itself can't travel with the file.
"""

import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

PROFILE_DIR = os.environ.get(
    "M365_COPILOT_PROFILE_DIR",
    str(Path(__file__).resolve().parent / ".m365-copilot-profile"),
)
COPILOT_URL = os.environ.get("COPILOT_URL", "https://m365.cloud.microsoft/chat/?auth=2")

# Chunk size for splitting large file contents across multiple chat turns —
# M365 Copilot's input isn't guaranteed to handle arbitrarily large pastes
# reliably in one go.
MAX_CHUNK_CHARS = int(os.environ.get("M365_COPILOT_MAX_CHUNK_CHARS", "12000"))

# Confirmed against the live, authenticated page. Fallbacks kept after the
# confirmed entry in case Microsoft changes the markup again.
SELECTORS = {
    "input": [
        '[role="textbox"][contenteditable="true"]',
        'textarea[placeholder*="Copilot" i]',
        'textarea[aria-label*="Ask" i]',
    ],
    "message_groups": [
        '[data-testid="m365-chat-llm-web-ui-chat-message"]',
        '[data-testid*="message" i]',
    ],
    "answer": [
        '[data-testid="markdown-reply"]',
        '[data-testid="lastChatMessage"]',
    ],
}


def log(*args):
    print("[m365-copilot-mcp]", *args, file=sys.stderr, flush=True)


def locate_visible(page, selectors, timeout_ms=15000):
    deadline = time.time() + timeout_ms / 1000
    last_err = None
    for sel in selectors:
        remaining_ms = max(500, (deadline - time.time()) * 1000)
        loc = page.locator(sel).first
        try:
            loc.wait_for(state="visible", timeout=remaining_ms)
            return loc
        except Exception as e:
            last_err = e
    raise RuntimeError(f"No selector matched (tried: {selectors}): {last_err}")


def locate_group_with_matches(page, selectors, timeout_ms=15000):
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        for sel in selectors:
            loc = page.locator(sel)
            if loc.count() > 0:
                return loc
        time.sleep(0.3)
    raise RuntimeError(f"No message-group selector matched (tried: {selectors})")


def wait_for_stable_text(locator, poll_s=1.5, stable_rounds=2, timeout_s=90):
    deadline = time.time() + timeout_s
    last = None
    stable_count = 0
    while time.time() < deadline:
        try:
            text = (locator.inner_text() or "").strip()
        except Exception:
            text = ""
        if text and text == last:
            stable_count += 1
            if stable_count >= stable_rounds:
                return text
        else:
            stable_count = 0
        last = text
        time.sleep(poll_s)
    raise RuntimeError("Timed out waiting for the Copilot response to finish streaming.")


def split_into_chunks(text, max_chars):
    if len(text) <= max_chars:
        return [text]
    return [text[i : i + max_chars] for i in range(0, len(text), max_chars)]


class Copilot:
    """Owns one persistent Edge context + page for the process lifetime, so
    consecutive ask() calls continue the same Copilot conversation thread."""

    def __init__(self, headless=True):
        self._pw = sync_playwright().start()
        self.context = self._pw.chromium.launch_persistent_context(
            PROFILE_DIR,
            channel="msedge",
            headless=headless,
            viewport={"width": 1280, "height": 900},
        )
        self.page = self.context.pages[0] if self.context.pages else self.context.new_page()

    def close(self):
        try:
            self.context.close()
        finally:
            self._pw.stop()

    def _ensure_on_copilot(self):
        parsed = urlparse(COPILOT_URL)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not self.page.url.startswith(origin):
            self.page.goto(COPILOT_URL, wait_until="domcontentloaded")

    def _send_turn(self, text: str) -> str:
        """One chat turn: type, submit, wait for a new message and its answer
        to stabilize. Low-level building block for ask()/ask_chunked()."""
        page = self.page
        try:
            messages = locate_group_with_matches(page, SELECTORS["message_groups"], 20000)
            before_count = messages.count()
        except Exception:
            before_count = 0

        input_box = locate_visible(page, SELECTORS["input"])
        input_box.click()
        try:
            input_box.fill(text)
        except Exception:
            input_box.press_sequentially(text, delay=10)
        input_box.press("Enter")

        messages_after = locate_group_with_matches(page, SELECTORS["message_groups"], 20000)
        deadline = time.time() + 20
        while messages_after.count() <= before_count and time.time() < deadline:
            time.sleep(0.3)

        answers = locate_group_with_matches(page, SELECTORS["answer"], 20000)
        return wait_for_stable_text(answers.last)

    def ask(self, question: str) -> str:
        return self.ask_chunked(question, [])

    def ask_chunked(self, question: str, files: list) -> str:
        """files: list of {"path": str, "content": str}. Small enough content
        goes in one turn; large content is split across multiple turns, with
        `question` appended only to the final turn so Copilot only produces
        its real answer once all context has arrived."""
        self._ensure_on_copilot()

        if not files:
            return self._send_turn(question)

        context_text = "\n\n".join(
            f"File: {f['path']}\n```\n{f['content']}\n```" for f in files
        )
        chunks = split_into_chunks(context_text, MAX_CHUNK_CHARS)

        last_answer = None
        for i, chunk in enumerate(chunks):
            is_last = i == len(chunks) - 1
            header = (
                ""
                if len(chunks) == 1
                else f"[Context part {i + 1}/{len(chunks)} — more is coming, do not answer yet unless this is the final part]\n\n"
            )
            footer = f"\n\n---\n{question}" if is_last else ""
            last_answer = self._send_turn(f"{header}{chunk}{footer}")
        return last_answer


def run_login():
    log("Opening a visible Edge window. Sign in and complete MFA there — this auto-detects completion, no keypress needed.")
    copilot = Copilot(headless=False)
    copilot.page.goto(COPILOT_URL)

    deadline = time.time() + 8 * 60  # generous: password + MFA + any conditional-access steps
    logged_in = False
    while time.time() < deadline:
        for sel in SELECTORS["input"]:
            try:
                if copilot.page.locator(sel).first.is_visible():
                    logged_in = True
                    break
            except Exception:
                pass
        if logged_in:
            break
        time.sleep(2)

    copilot.close()
    if not logged_in:
        raise RuntimeError("Timed out waiting for sign-in (chat input never appeared). Run `login` again.")
    log(f"Signed in — session saved to {PROFILE_DIR}")


def read_files(file_paths):
    files = []
    for p in file_paths:
        path_obj = Path(p)
        if not path_obj.is_absolute():
            path_obj = Path.cwd() / path_obj
        try:
            content = path_obj.read_text(encoding="utf-8")
            files.append({"path": p, "content": content})
        except Exception as e:
            files.append({"path": p, "content": f"[Could not read this file: {e}]"})
    return files


# ---- hand-rolled MCP JSON-RPC over stdio (no SDK) ----

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "m365-copilot-mcp", "version": "1.0.0"}
TOOLS = [
    {
        "name": "ask_m365_copilot",
        "description": (
            "Sends a question to Microsoft 365 Copilot (the logged-in M365 web chat) and returns its answer. "
            "This tool has NO access to the caller's files unless you pass `file_paths` — prefer that over "
            "pasting code into `question` yourself. Pass ABSOLUTE paths of any files the question is about in "
            "`file_paths`; this tool runs as a separate process and its working directory is not guaranteed to "
            "be the workspace root, so relative paths may fail to resolve — always use the file's full "
            "absolute path (which you already have from reading/listing it). The tool reads the files itself "
            "and sends their real contents to M365 Copilot, automatically splitting large files across "
            "multiple chat turns if needed. Do not send task-type labels or vague workspace descriptions "
            "instead of actual paths/content — M365 Copilot cannot resolve them."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The question to ask M365 Copilot about the given file(s), or standalone if no files are relevant.",
                },
                "file_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "ABSOLUTE paths of files to send as context (e.g. C:\\project\\src\\file.py, not "
                        "src\\file.py). The tool reads these itself — do not paste their contents into `question`."
                    ),
                },
            },
            "required": ["question"],
        },
    }
]


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def send_result(id_, result):
    send({"jsonrpc": "2.0", "id": id_, "result": result})


def send_error(id_, code, message):
    send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


def run_server():
    log("started, waiting for MCP client on stdio")
    state = {"copilot": None}

    def get_copilot():
        # If the underlying browser dies for any reason (crashed, closed, killed
        # by a second process fighting over the same profile dir), a stale
        # reference here would fail forever — so drop it on "close" and let the
        # next call relaunch instead of every future call failing permanently.
        if state["copilot"] is None:
            copilot = Copilot(headless=True)
            copilot.context.on("close", lambda: state.update(copilot=None))
            state["copilot"] = copilot
        return state["copilot"]

    def ask_with_retry(question, files):
        # A page/context can die mid-operation (crash, external process
        # stealing the profile lock, etc.), leaving in-flight Playwright calls
        # throwing obscure internal errors. Retry exactly once against a
        # freshly launched context before surfacing the error to the caller.
        try:
            return get_copilot().ask_chunked(question, files)
        except Exception:
            state["copilot"] = None
            return get_copilot().ask_chunked(question, files)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log("failed to parse line as JSON:", e)
            continue

        id_ = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        # Notifications (no "id") never get a response, per JSON-RPC.
        if id_ is None:
            log("notification:", method)
            continue

        try:
            if method == "initialize":
                send_result(id_, {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                })
            elif method == "tools/list":
                send_result(id_, {"tools": TOOLS})
            elif method == "tools/call":
                name = params.get("name")
                args = params.get("arguments") or {}
                if name != "ask_m365_copilot":
                    send_error(id_, -32602, f"Unknown tool: {name}")
                    continue
                question = args.get("question")
                if not isinstance(question, str) or not question.strip():
                    send_error(id_, -32602, "Missing required string argument: question")
                    continue
                file_paths = args.get("file_paths") or []
                try:
                    log("asking:", question, f"(with {len(file_paths)} file(s))" if file_paths else "")
                    files = read_files(file_paths) if file_paths else []
                    answer = ask_with_retry(question, files)
                    send_result(id_, {"content": [{"type": "text", "text": answer}], "isError": False})
                except Exception as e:
                    log("tool error:", e)
                    send_result(id_, {
                        "content": [{"type": "text", "text": f"Error asking M365 Copilot: {e}"}],
                        "isError": True,
                    })
            elif method == "ping":
                send_result(id_, {})
            else:
                send_error(id_, -32601, f"Method not found: {method}")
        except Exception as e:
            log("unhandled error:", e)
            send_error(id_, -32603, str(e))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "login":
        run_login()
    elif cmd == "serve":
        run_server()
    else:
        print(f"Unknown command: {cmd!r}. Use 'login' or 'serve'.", file=sys.stderr)
        sys.exit(1)





########################

cd "/c/Users/vivek mani/m365-copilot-mcp" && python -m py_compile m365_copilot_mcp.py && rm -rf __pycache__ && echo "OK — ready" && wc -l m365_copilot_mcp.py

Copy just this one .py file (push to git, or however you move it — it's fully self-contained, no other files needed).
pip install playwright (small library only — it drives the office laptop's already-installed Edge via channel="msedge", no separate browser download).
python m365_copilot_mcp.py login — visible Edge window opens, sign in with the office M365 account, complete MFA. Auto-detected, no keypress needed. Session saves to .m365-copilot-profile/ next to the script.
Add to that machine's VS Code user-level mcp.json (don't add "cwd" — it breaks startup in windows with no folder open):

"m365-copilot": {
  "command": "python",
  "args": ["C:\\path\\to\\m365_copilot_mcp.py", "serve"]
}
