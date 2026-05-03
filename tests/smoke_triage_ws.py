"""
Smoke test: connect to /ws, fire a triage run, print every triage_progress
and triage_complete event the server broadcasts. Used to verify the
WebSocket fan-out wired in handlers_triage.go.

Run with the server already up (vanguard.exe --port 18423).
"""

import json
import sys
import threading
import urllib.request

try:
    from websockets.sync.client import connect
except ImportError:
    sys.stderr.write("pip install websockets first\n")
    sys.exit(1)

PORT = 18423
WS_URL = f"ws://127.0.0.1:{PORT}/ws"
RUN_URL = f"http://127.0.0.1:{PORT}/api/triage/run"


def fire_triage():
    body = json.dumps({"type": "sysinfo"}).encode()
    req = urllib.request.Request(
        RUN_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as resp:
        print("HTTP", resp.status, resp.read().decode())


def main():
    with connect(WS_URL) as ws:
        # Give the WS handshake a moment, then trigger a run.
        threading.Timer(0.3, fire_triage).start()
        events = 0
        while True:
            try:
                msg = ws.recv(timeout=60)
            except TimeoutError:
                print("[timeout — no message in 60s]")
                break
            obj = json.loads(msg)
            kind = obj.get("type")
            data = obj.get("data") or {}
            if kind == "triage_progress":
                print(f"  progress  {data.get('step'):30s} status={data.get('status'):8s} "
                      f"dur={data.get('duration', 0)}s files={data.get('files', 0)}")
            elif kind == "triage_complete":
                print(f"  complete  files={data.get('total_files')} "
                      f"bytes={data.get('total_bytes')} dur={data.get('duration')}s")
                break
            else:
                print("  other:", kind, data)
            events += 1
            if events > 200:
                break


if __name__ == "__main__":
    main()
