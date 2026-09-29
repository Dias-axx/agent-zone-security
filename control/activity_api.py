"""Local read-only HTTP API + dashboard over the audit log (control/audit.py).

Renders real recorded activity from a JSONLFileSink path (an AuditLog(path)'s
.path, or wherever your deployment points JSONLFileSink) — it invents
nothing, and returns an empty list/table when the log is empty or missing.

Deliberately stdlib-only (http.server), matching control/policy_engine.py's
and detection/normalise.py's zero-dependency stance, so nothing here needs a
pip install to run. The dashboard's HTML/CSS/JS is embedded below rather than
loaded from a CDN, for the same reason this repo avoids third-party script
dependencies elsewhere (see README's security posture) — no supply-chain
surface, no network access needed beyond the browser talking to this process.

Security scope: no authentication, and binds to 127.0.0.1 by default. This is
a local visibility tool for an operator who already has access to the audit
log file, not a hardened multi-tenant service — do not bind it to 0.0.0.0 or
expose it beyond localhost without putting a real authenticating reverse
proxy in front of it.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from control.activity_reader import filter_records, read_records, summarize_by_agent

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Agent Activity</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; }
  h1 { font-size: 1.25rem; margin-bottom: 0.25rem; }
  .sub { opacity: 0.7; font-size: 0.85rem; margin-bottom: 1.5rem; }
  section { margin-bottom: 2rem; }
  table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid rgba(128,128,128,0.3); }
  th { position: sticky; top: 0; background: Canvas; }
  .filters { display: flex; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .filters input, .filters select { padding: 0.3rem 0.5rem; }
  .allow { color: #2e7d32; }
  .deny { color: #c62828; }
  .confirm { color: #ef6c00; }
  .empty { opacity: 0.6; font-style: italic; }
</style>
</head>
<body>
<h1>Agent Activity</h1>
<div class="sub" id="status">loading…</div>

<section>
  <h2>By agent</h2>
  <table id="agents-table">
    <thead><tr>
      <th>agent_id</th><th>role</th><th>events</th><th>allow</th><th>deny</th>
      <th>confirm</th><th>last seen</th><th>last activity</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</section>

<section>
  <h2>Recent events</h2>
  <div class="filters">
    <input id="f-agent" placeholder="agent_id">
    <select id="f-decision">
      <option value="">any decision</option>
      <option value="allow">allow</option>
      <option value="deny">deny</option>
      <option value="confirm">confirm</option>
    </select>
    <input id="f-kind" placeholder="kind (zone, egress, tool, ...)">
  </div>
  <table id="events-table">
    <thead><tr><th>timestamp</th><th>agent_id</th><th>role</th><th>kind</th><th>target</th><th>decision</th><th>rule_id</th><th>reason</th></tr></thead>
    <tbody></tbody>
  </table>
</section>

<script>
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + ": " + res.status);
  return res.json();
}

function renderAgents(rows) {
  const tbody = document.querySelector("#agents-table tbody");
  tbody.innerHTML = "";
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">no activity recorded yet</td></tr>';
    return;
  }
  for (const r of rows) {
    const d = r.decisions || {};
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.agent_id}</td><td>${r.role || ""}</td>
      <td>${r.total_events}</td>
      <td class="allow">${d.allow || 0}</td>
      <td class="deny">${d.deny || 0}</td>
      <td class="confirm">${d.confirm || 0}</td>
      <td>${r.last_seen || ""}</td>
      <td>${r.last_kind || ""} → ${r.last_target || ""}
        (<span class="${r.last_decision}">${r.last_decision || ""}</span>)</td>`;
    tbody.appendChild(tr);
  }
}

function renderEvents(rows) {
  const tbody = document.querySelector("#events-table tbody");
  tbody.innerHTML = "";
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty">no matching events</td></tr>';
    return;
  }
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.timestamp || ""}</td><td>${r.agent_id || ""}</td><td>${r.role || ""}</td>
      <td>${r.kind || ""}</td><td>${r.target || ""}</td><td class="${r.decision}">${r.decision || ""}</td>
      <td>${r.rule_id || ""}</td><td>${r.reason || ""}</td>`;
    tbody.appendChild(tr);
  }
}

async function refresh() {
  try {
    const params = new URLSearchParams();
    const agent = document.getElementById("f-agent").value.trim();
    const decision = document.getElementById("f-decision").value;
    const kind = document.getElementById("f-kind").value.trim();
    if (agent) params.set("agent_id", agent);
    if (decision) params.set("decision", decision);
    if (kind) params.set("kind", kind);

    const [agents, events] = await Promise.all([
      fetchJSON("/api/agents"),
      fetchJSON("/api/activity?" + params.toString()),
    ]);
    renderAgents(agents);
    renderEvents(events);
    document.getElementById("status").textContent =
      "updated " + new Date().toLocaleTimeString() + " — " + events.length +
      " event(s) shown, refreshes every 5s";
  } catch (e) {
    document.getElementById("status").textContent = "error loading activity: " + e;
  }
}

for (const id of ["f-agent", "f-decision", "f-kind"]) {
  document.getElementById(id).addEventListener("input", refresh);
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


def make_handler(audit_log_path: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            pass  # quiet by default; local dev-time tool, no access-log requirement

        def _send_json(self, payload: object, status: int = 200) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if parsed.path == "/":
                self._send_html(DASHBOARD_HTML)
                return

            if parsed.path == "/api/activity":
                records = read_records(audit_log_path)
                filtered = filter_records(
                    records,
                    agent_id=query.get("agent_id"),
                    decision=query.get("decision"),
                    kind=query.get("kind"),
                    since=query.get("since"),
                )
                filtered.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
                try:
                    limit = int(query.get("limit", "200"))
                except ValueError:
                    limit = 200
                self._send_json(filtered[:limit])
                return

            if parsed.path == "/api/agents":
                self._send_json(summarize_by_agent(read_records(audit_log_path)))
                return

            self._send_json({"error": "not found"}, status=404)

    return Handler


def run(audit_log_path: Path, host: str = "127.0.0.1", port: int = 8090) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(audit_log_path))
    print(f"Serving agent activity dashboard on http://{host}:{port} (audit log: {audit_log_path})")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--audit-log",
        type=Path,
        required=True,
        help="Path to the JSONL audit log (an AuditLog(path)'s .path, i.e. JSONLFileSink's file)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    run(args.audit_log, args.host, args.port)


if __name__ == "__main__":
    main()
