import json
import logging
import os
import threading

from flask import Flask, render_template_string, send_file
from flask_sock import Sock

from agents.remediator_agent import RemediatorAgent

logger = logging.getLogger(__name__)

DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))

app = Flask(__name__)
sock = Sock(app)

_ws_clients: list = []
_engine_ref = None
_audit_thread = None

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VBoxAuditor — Attack Surface Enumeration</title>
<style>
:root {
  --bg-primary: #07070f;
  --bg-secondary: #0c0c1a;
  --bg-card: #111128;
  --bg-card-hover: #18183a;
  --border: #1e1e3a;
  --text: #d0d0e0;
  --text-dim: #606080;
  --accent-cyan: #00bcd4;
  --accent-orange: #ff6f3c;
  --accent-green: #00e676;
  --accent-gold: #ffd740;
  --accent-red: #ff1744;
  --accent-purple: #b388ff;
  --shadow: 0 4px 24px rgba(0,0,0,.4);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg-primary);color:var(--text);height:100vh;display:flex;flex-direction:column;overflow:hidden;font-size:14px}

/* Header */
header{background:linear-gradient(135deg,#0c0c1e 0%,#0a0a18 100%);border-bottom:1px solid var(--border);padding:0 24px;display:flex;justify-content:space-between;align-items:center;flex-shrink:0;height:60px}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--accent-cyan),var(--accent-purple));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:#fff}
.logo-text{font-size:18px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--accent-cyan),var(--accent-purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.logo-text span{color:#fff;background:none;-webkit-text-fill-color:initial}
.header-right{display:flex;align-items:center;gap:16px}
.status-badge{display:flex;align-items:center;gap:8px;padding:6px 14px;border-radius:20px;background:var(--bg-card);border:1px solid var(--border);font-size:12px;font-weight:500}
.status-dot{width:8px;height:8px;border-radius:50%;transition:.3s}
.status-dot.ready{background:var(--text-dim)}
.status-dot.running{background:var(--accent-green);box-shadow:0 0 8px var(--accent-green);animation:pulse 1s infinite}
.status-dot.done{background:var(--accent-cyan)}
.status-dot.error{background:var(--accent-red)}
@keyframes pulse{0%{opacity:.4}50%{opacity:1}100%{opacity:.4}}
.btn-exec{background:linear-gradient(135deg,var(--accent-green),#00c853);color:#000;border:none;padding:8px 24px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;transition:.25s;font-family:inherit;letter-spacing:.3px}
.btn-exec:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,230,118,.3)}
.btn-exec:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn-exec.running{background:linear-gradient(135deg,var(--accent-red),#d50000);color:#fff}

/* Main layout */
#main{display:flex;flex:1;overflow:hidden}

/* Log panel */
#log-panel{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--bg-primary)}
#log-header{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border);flex-shrink:0}
#log-header h3{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--text-dim)}
#phase-indicator{display:flex;gap:6px;margin-left:auto}
.phase{font-size:10px;padding:3px 10px;border-radius:12px;background:var(--bg-card);border:1px solid var(--border);color:var(--text-dim);transition:.3s}
.phase.active{background:var(--accent-cyan);border-color:var(--accent-cyan);color:#000;font-weight:600}
.phase.done{background:var(--accent-green);border-color:var(--accent-green);color:#000;font-weight:600}
#log-stream{flex:1;overflow-y:auto;padding:8px 16px}

/* Log entries */
.entry{margin-bottom:4px;padding:8px 12px;border-radius:6px;font-size:13px;line-height:1.5;opacity:0;transform:translateY(6px);transition:opacity .2s ease,transform .2s ease}
.entry.visible{opacity:1;transform:translateY(0)}
.entry.thinking{background:rgba(255,215,64,.04);border-left:2px solid var(--accent-gold)}
.entry.command{background:rgba(0,188,212,.04);border-left:2px solid var(--accent-cyan)}
.entry.output{background:rgba(96,96,128,.04);border-left:2px solid var(--text-dim)}
.entry.result{background:rgba(0,230,118,.04);border-left:2px solid var(--accent-green)}
.entry.error{background:rgba(255,23,68,.04);border-left:2px solid var(--accent-red)}
.entry.finding{background:rgba(0,230,118,.03);border-left:2px solid var(--accent-green);padding:10px 12px}
.entry.summary_detail{background:rgba(179,136,255,.04);border-left:2px solid var(--accent-purple);padding:10px 12px}
.entry-summary{font-size:13px;line-height:1.7}
.entry-summary .sum-header{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--accent-purple);margin-bottom:6px}
.entry-summary .sum-total{font-size:14px;margin-bottom:4px}
.entry-summary .sum-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim);margin-right:4px}
.entry-summary .sum-sevs{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:4px}
.entry-summary .sum-stat{font-size:12px;font-weight:600;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,.04)}
.entry-summary .sum-stat.critical{color:var(--accent-red)}
.entry-summary .sum-stat.high{color:var(--accent-orange)}
.entry-summary .sum-stat.medium{color:var(--accent-gold)}
.entry-summary .sum-stat.low{color:var(--accent-cyan)}
.entry-summary .sum-stat.info{color:var(--text-dim)}
.entry-summary .sum-risk{display:inline-block;font-size:12px;font-weight:700;padding:3px 10px;border-radius:4px;margin:4px 0}
.entry-summary .sum-risk.critical{background:rgba(255,23,68,.15);color:var(--accent-red)}
.entry-summary .sum-risk.high{background:rgba(255,111,60,.15);color:var(--accent-orange)}
.entry-summary .sum-risk.medium{background:rgba(255,215,64,.15);color:var(--accent-gold)}
.entry-summary .sum-risk.low{background:rgba(0,188,212,.15);color:var(--accent-cyan)}
.entry-summary .sum-vectors{margin:4px 0}
.entry-summary .sum-vectors ul{margin:2px 0 0 16px;padding:0}
.entry-summary .sum-vectors li{font-size:12px;color:var(--accent-orange);margin-bottom:2px}
.entry-summary .sum-component{font-size:12px;color:var(--text);margin-top:4px}
.entry-finding{font-size:13px;line-height:1.6}
.entry-finding .finding-hdr{display:flex;align-items:center;gap:8px;margin-bottom:2px}
.entry-finding .finding-hdr strong{font-size:14px;color:var(--text)}
.entry-finding .finding-meta{font-size:11px;color:var(--text-dim);margin-bottom:6px}
.entry-finding .finding-desc{font-size:12px;color:var(--text);margin-bottom:6px;line-height:1.5}
.entry-finding .finding-label{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--accent-green);display:inline-block;margin-top:4px;margin-bottom:2px}
.entry-finding .finding-remediation{font-size:12px;color:var(--accent-green);line-height:1.6;white-space:pre-line;margin-bottom:4px}
.entry-finding .finding-attack{font-size:12px;color:var(--accent-orange);font-style:italic;line-height:1.5}
.finding-body-actions{margin-top:10px;padding-top:8px;border-top:1px solid var(--border);display:flex;gap:6px}
.finding-exec-btn{margin-left:0!important}
.agent-badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.agent-badge.enumerator{background:rgba(255,111,60,.15);color:var(--accent-orange)}
.agent-badge.analyzer{background:rgba(0,188,212,.15);color:var(--accent-cyan)}
.agent-badge.reporter{background:rgba(0,230,118,.15);color:var(--accent-green)}
.agent-badge.remediator{background:rgba(255,215,64,.15);color:var(--accent-gold)}
.agent-badge.system{background:rgba(179,136,255,.15);color:var(--accent-purple)}
.agent-icon{font-size:12px}
.entry-time{font-size:10px;color:var(--text-dim);margin-left:6px}
.entry-msg{margin-top:3px;color:var(--text);white-space:pre-wrap;word-break:break-word}
.entry-msg .highlight{color:var(--accent-green)}
.entry-msg .warn{color:var(--accent-orange)}
.entry-msg .danger{color:var(--accent-red)}
.entry-msg .info{color:var(--accent-cyan)}
.entry-msg code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px;font-size:12px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold)}
.cmd-output{margin-top:4px;padding:4px 8px;background:rgba(0,0,0,.2);border-radius:4px;font-size:12px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--text-dim);white-space:pre-wrap;word-break:break-word;line-height:1.4}

/* Empty state */
#empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text-dim);text-align:center;padding:40px}
#empty-state .hero-icon{width:80px;height:80px;background:linear-gradient(135deg,rgba(0,188,212,.1),rgba(179,136,255,.1));border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:36px;margin-bottom:20px;border:1px solid rgba(255,255,255,.06)}
#empty-state h2{color:var(--text);font-size:20px;font-weight:600;margin-bottom:8px}
#empty-state p{color:var(--text-dim);font-size:14px;max-width:400px;line-height:1.6}

/* Sidebar */
#sidebar{width:400px;background:var(--bg-secondary);border-left:1px solid var(--border);overflow-y:auto;flex-shrink:0;padding:16px}
.sidebar-section{margin-bottom:20px}
.section-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--text-dim);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border)}

/* Summary grid */
.summary-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.summary-card{background:var(--bg-card);border-radius:8px;padding:12px;text-align:center;border:1px solid transparent;transition:.2s}
.summary-card:hover{border-color:var(--border)}
.summary-card .label{font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px}
.summary-card .val{font-size:24px;font-weight:700;margin-top:2px;transition:.3s}
.summary-card .val.critical{color:var(--accent-red)}
.summary-card .val.high{color:var(--accent-orange)}
.summary-card .val.medium{color:var(--accent-gold)}
.summary-card .val.low{color:var(--accent-cyan)}
.summary-card .val.info{color:var(--text-dim)}

/* Findings cards */
.findings-list{display:flex;flex-direction:column;gap:6px}
.finding-card{background:var(--bg-card);border-radius:8px;overflow:hidden;border:1px solid var(--border);transition:.2s;cursor:pointer}
.finding-card:hover{background:var(--bg-card-hover)}
.finding-card.critical{border-left:3px solid var(--accent-red)}
.finding-card.high{border-left:3px solid var(--accent-orange)}
.finding-card.medium{border-left:3px solid var(--accent-gold)}
.finding-card.low{border-left:3px solid var(--accent-cyan)}
.finding-card.info{border-left:3px solid var(--text-dim)}
.finding-header{display:flex;align-items:center;gap:8px;padding:10px 12px}
.finding-header:hover{background:rgba(255,255,255,.02)}
.remediation-btn{font-size:8px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;padding:3px 8px;border-radius:4px;border:none;background:rgba(0,230,118,.14);color:var(--accent-green);cursor:pointer;white-space:nowrap;margin-left:auto;font-family:inherit;transition:.2s;line-height:normal}
.remediation-btn:hover:not(:disabled){background:rgba(0,230,118,.25);transform:translateY(-1px)}
.remediation-btn:disabled{cursor:not-allowed;opacity:.7}
.remediation-btn.running{background:rgba(255,215,64,.14);color:var(--accent-gold);animation:pulse 1s infinite}
.remediation-btn.done{background:rgba(0,230,118,.2);color:var(--accent-green);cursor:default}
.remediation-btn.failed{background:rgba(255,23,68,.14);color:var(--accent-red);cursor:default}
.remediation-list{display:flex;flex-direction:column;gap:4px}
.remediation-item{display:flex;align-items:center;gap:8px;background:var(--bg-card);border-radius:6px;padding:8px 10px;border:1px solid var(--border);font-size:11px}
.remediation-item .r-icon{font-size:12px}
.remediation-item .r-title{flex:1;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.remediation-item .r-status{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;white-space:nowrap}
.remediation-item .r-status.success{color:var(--accent-green)}
.remediation-item .r-status.failed{color:var(--accent-red)}
.sev-badge{font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;padding:2px 6px;border-radius:3px}
.sev-badge.critical{background:rgba(255,23,68,.15);color:var(--accent-red)}
.sev-badge.high{background:rgba(255,111,60,.15);color:var(--accent-orange)}
.sev-badge.medium{background:rgba(255,215,64,.15);color:var(--accent-gold)}
.sev-badge.low{background:rgba(0,188,212,.15);color:var(--accent-cyan)}
.sev-badge.info{background:rgba(96,96,128,.15);color:var(--text-dim)}
.finding-title{flex:1;font-size:12px;font-weight:500;color:var(--text)}
.cvss-tag{font-size:10px;color:var(--text-dim);background:rgba(255,255,255,.04);padding:2px 6px;border-radius:3px}
.expand-icon{color:var(--text-dim);font-size:10px;transition:.3s}
.finding-card.expanded .expand-icon{transform:rotate(180deg)}
.finding-body{max-height:0;overflow:hidden;transition:.3s ease}
.finding-card.expanded .finding-body{max-height:600px}
.finding-body-inner{padding:0 12px 12px;border-top:1px solid var(--border)}
.finding-body-inner .desc{font-size:12px;color:var(--text);line-height:1.6;margin-top:8px}
.finding-body-inner .section-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-dim);margin-top:10px;margin-bottom:4px}
.finding-body-inner .remediation{font-size:12px;color:var(--accent-green);line-height:1.5;white-space:pre-wrap}
.finding-body-inner .attack-scenario{font-size:12px;color:var(--accent-orange);line-height:1.5;font-style:italic}
.finding-body-inner .refs{font-size:11px;color:var(--accent-cyan)}
.finding-body-inner .refs a{color:var(--accent-cyan);text-decoration:none}
.finding-body-inner .refs a:hover{text-decoration:underline}

/* Download area */
.download-area{margin-top:16px}
.download-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--text-dim);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.download-banner{background:linear-gradient(135deg,rgba(0,230,118,.06),rgba(0,188,212,.06));border:1px solid rgba(0,230,118,.2);border-radius:10px;padding:16px;text-align:center}
.download-banner .check{color:var(--accent-green);font-size:24px;margin-bottom:4px}
.download-banner p{font-size:12px;color:var(--accent-green);font-weight:600;margin-bottom:10px}
.download-buttons{display:flex;gap:6px;flex-wrap:wrap;justify-content:center}
.dl-btn{display:inline-flex;align-items:center;gap:5px;background:rgba(0,230,118,.1);color:var(--accent-green);border:1px solid rgba(0,230,118,.25);border-radius:6px;padding:7px 14px;font-size:11px;font-weight:500;cursor:pointer;text-decoration:none;font-family:inherit;transition:.2s}
.dl-btn:hover{background:rgba(0,230,118,.2);transform:translateY(-1px)}
.dl-btn.pdf{background:rgba(255,23,68,.1);color:var(--accent-red);border-color:rgba(255,23,68,.25)}
.dl-btn.pdf:hover{background:rgba(255,23,68,.2)}
.dl-btn.html{background:rgba(0,188,212,.1);color:var(--accent-cyan);border-color:rgba(0,188,212,.25)}
.dl-btn.html:hover{background:rgba(0,188,212,.2)}

/* Executive summary area */
.exec-area{background:var(--bg-card);border-radius:8px;padding:14px;margin-bottom:20px;border:1px solid var(--border)}
.exec-area .exec-text{font-size:12px;color:var(--text);line-height:1.7}
.risk-tag{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;margin-top:8px}
.risk-tag.critical{background:rgba(255,23,68,.15);color:var(--accent-red)}
.risk-tag.high{background:rgba(255,111,60,.15);color:var(--accent-orange)}
.risk-tag.medium{background:rgba(255,215,64,.15);color:var(--accent-gold)}
.risk-tag.low{background:rgba(0,188,212,.15);color:var(--accent-cyan)}

/* Attack vectors */
.vector-list{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.vector-tag{padding:3px 8px;border-radius:4px;font-size:10px;background:rgba(255,111,60,.08);border:1px solid rgba(255,111,60,.15);color:var(--accent-orange)}

/* Scrollbar */
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">V</div>
    <div class="logo-text">VBox<span>Auditor</span></div>
  </div>
  <div class="header-right">
    <div class="status-badge">
      <span class="status-dot ready" id="statusDot"></span>
      <span id="statusText">Ready</span>
    </div>
    <button class="btn-exec" id="execBtn" onclick="startAudit()">▲ Execute Audit</button>
  </div>
</header>

<div id="main">
  <!-- Log Panel -->
  <div id="log-panel">
    <div id="log-header">
      <h3>Agent Activity Log</h3>
      <div id="phase-indicator">
        <span class="phase" id="phase-enum">01 Enumerate</span>
        <span class="phase" id="phase-analyze">02 Analyze</span>
        <span class="phase" id="phase-report">03 Report</span>
      </div>
    </div>
    <div id="log-stream">
      <div id="empty-state">
        <div class="hero-icon">▣</div>
        <h2>Ready to scan attack surface</h2>
        <p>Click <strong>Execute Audit</strong> to deploy autonomous agents that will enumerate, analyze, and report on VirtualBox security misconfigurations from an attacker's perspective.</p>
      </div>
    </div>
  </div>

  <!-- Sidebar -->
  <div id="sidebar">
    <!-- Executive Summary -->
    <div id="execSection" style="display:none">
      <div class="sidebar-section">
        <div class="section-title">Executive Summary</div>
        <div class="exec-area">
          <div class="exec-text" id="execText"></div>
          <div id="riskTag"></div>
          <div style="margin-top:10px">
            <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--text-dim);margin-bottom:4px">Attack Vectors</div>
            <div class="vector-list" id="vectorList"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Summary -->
    <div class="sidebar-section">
      <div class="section-title">Findings Summary</div>
      <div class="summary-grid" id="summaryGrid">
        <div class="summary-card"><div class="label">Total</div><div class="val" id="s-total">0</div></div>
        <div class="summary-card"><div class="label">Critical</div><div class="val critical" id="s-critical">0</div></div>
        <div class="summary-card"><div class="label">High</div><div class="val high" id="s-high">0</div></div>
        <div class="summary-card"><div class="label">Medium</div><div class="val medium" id="s-medium">0</div></div>
        <div class="summary-card"><div class="label">Low</div><div class="val low" id="s-low">0</div></div>
        <div class="summary-card"><div class="label">Info</div><div class="val info" id="s-info">0</div></div>
      </div>
    </div>

    <!-- Findings -->
    <div class="sidebar-section">
      <div class="section-title">Findings &amp; Remediation <span style="font-weight:400;color:var(--text-dim);font-size:8px;letter-spacing:0;text-transform:none">(click to expand)</span></div>
      <div class="findings-list" id="findingsList"></div>
    </div>

    <!-- Download -->
    <div id="downloadArea" style="display:none">
      <div class="download-area">
        <div class="download-title">Download Reports</div>
        <div class="download-banner">
          <div class="check">✓</div>
          <p>Audit Complete — Reports Ready</p>
          <div class="download-buttons">
            <a class="dl-btn pdf" id="dlPdf" href="#">⬇ PDF Report</a>
            <a class="dl-btn html" id="dlHtml" href="#">⬇ HTML Report</a>
            <a class="dl-btn" id="dlJson" href="#">⬇ JSON Report</a>
          </div>
        </div>
      </div>
    </div>

    <!-- Remediation History -->
    <div id="remediationSection" class="sidebar-section" style="display:none">
      <div class="section-title">Remediation Activity</div>
      <div id="remediationList"></div>
    </div>
  </div>
</div>

<script>
// Agent display config
const AGENTS = {
  enumerator: { label: "Enumerator", icon: "🔍", cls: "enumerator" },
  analyzer:   { label: "Analyzer",   icon: "🧠", cls: "analyzer" },
  reporter:   { label: "Reporter",   icon: "📊", cls: "reporter" },
  remediator: { label: "Remediator", icon: "🔧", cls: "remediator" },
  system:     { label: "System",     icon: "⚙️", cls: "system" },
};

// Event queue for slow streaming
const eventQueue = [];
let processing = false;
const STREAM_DELAY = 250; // ms between entries

const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
const ws = new WebSocket(wsProto + "//" + location.host + "/ws");
const logStream = document.getElementById("log-stream");
const emptyState = document.getElementById("empty-state");
const execBtn = document.getElementById("execBtn");
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const downloadArea = document.getElementById("downloadArea");
const execSection = document.getElementById("execSection");

let currentPhase = null;

ws.onopen = () => console.log("VBoxAuditor WS connected");

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  eventQueue.push(msg);
  if (!processing) processNext();
};

function processNext() {
  if (eventQueue.length === 0) { processing = false; return; }
  processing = true;
  const msg = eventQueue.shift();

  if (msg.type === "status") { updateStatus(msg.data); }
  else if (msg.type === "summary") { updateSummary(msg.data); }
  else if (msg.type === "findings") { renderFindings(msg.data); }
  else if (msg.type === "complete") { onComplete(msg.data); }
  else if (msg.type === "executive") { renderExecutive(msg.data); }
  else if (msg.type === "error") { addEntry(msg.agent, "error", msg.data); }
  else if (msg.type === "remediation_complete") { onRemediationComplete(msg.data); }
  else { addEntry(msg.agent, msg.type, msg.data); }

  setTimeout(processNext, STREAM_DELAY);
}

function addEntry(agent, type, data) {
  emptyState && emptyState.remove();
  const info = AGENTS[agent] || { label: agent, icon: "●", cls: agent };

  // Phase tracking
  if (agent === "enumerator" && type === "result") setPhase("enum", "done");
  else if (agent === "enumerator" && type === "thinking" && data.message && data.message.includes("Initializing")) setPhase("enum", "active");
  else if (agent === "analyzer" && type === "thinking" && data.message && data.message.includes("Preparing")) setPhase("analyze", "active");
  else if (agent === "analyzer" && type === "result") setPhase("analyze", "done");
  else if (agent === "reporter" && type === "thinking") setPhase("report", "active");
  else if (agent === "reporter" && type === "result") setPhase("report", "done");

  // Group output with previous command from same agent
  if (type === "output" && _lastCmdEntry && _lastCmdEntry.agent === agent) {
    const outDiv = document.createElement("div");
    outDiv.className = "cmd-output";
    outDiv.textContent = data.output || "";
    _lastCmdEntry.el.appendChild(outDiv);
    logStream.scrollTop = logStream.scrollHeight;
    return;
  }

  const el = document.createElement("div");
  el.className = "entry " + type;

  let msgHtml = "";
  if (type === "thinking") {
    msgHtml = '<div class="entry-msg"><span class="info">⟐</span> ' + esc(data.message || "") + "</div>";
  } else if (type === "command") {
    msgHtml = '<div class="entry-msg"><span class="warn">$</span> <code>' + esc(data.command || "") + "</code></div>";
  } else if (type === "output") {
    msgHtml = '<div class="entry-msg">' + esc(data.output || "") + "</div>";
  } else if (type === "result") {
    const txt = typeof data === "object" ? JSON.stringify(data, null, 2) : String(data);
    msgHtml = '<div class="entry-msg"><span class="highlight">✓</span> <span class="highlight">' + esc(txt) + "</span></div>";
  } else if (type === "error") {
    msgHtml = '<div class="entry-msg"><span class="danger">✗</span> ' + esc(data.message || JSON.stringify(data)) + "</div>";
  } else if (type === "summary_detail") {
    const risk = (data.overall_risk || "N/A").toLowerCase();
    const vectors = (data.primary_attack_vectors || []).map(v => "<li>" + esc(v) + "</li>").join("");
    const severityRows = [
      { label: "Critical", count: data.critical || 0, cls: "critical" },
      { label: "High", count: data.high || 0, cls: "high" },
      { label: "Medium", count: data.medium || 0, cls: "medium" },
      { label: "Low", count: data.low || 0, cls: "low" },
      { label: "Info", count: data.info || 0, cls: "info" },
    ].filter(r => r.count > 0).map(r =>
      '<span class="sum-stat ' + r.cls + '">' + r.label + ": " + r.count + "</span>"
    ).join("&nbsp;&nbsp;");
    msgHtml =
      '<div class="entry-summary">' +
        '<div class="sum-header">Analysis Summary</div>' +
        '<div class="sum-total"><span class="sum-label">Total Findings</span> <strong>' + (data.total_findings || 0) + "</strong></div>" +
        (severityRows ? '<div class="sum-sevs">' + severityRows + "</div>" : "") +
        '<div class="sum-risk ' + risk + '">Overall Risk: ' + esc(data.overall_risk || "N/A") + "</div>" +
        (vectors ? '<div class="sum-vectors"><span class="sum-label">Attack Vectors</span><ul>' + vectors + "</ul></div>" : "") +
        (data.highest_risk_component ? '<div class="sum-component"><span class="sum-label">Highest Risk Component</span> ' + esc(data.highest_risk_component) + "</div>" : "") +
      "</div>";
  } else if (type === "finding") {
    const sev = (data.severity || "info").toLowerCase();
    const remSteps = (data.remediation || "").split("\n").filter(s => s.trim()).map(s => "• " + s.trim()).join("<br>");
    msgHtml =
      '<div class="entry-finding">' +
        '<div class="finding-hdr">' +
          '<span class="sev-badge ' + sev + '">' + esc(data.severity || "INFO") + "</span>" +
          '<strong>' + esc(data.title || "") + "</strong>" +
        "</div>" +
        '<div class="finding-meta">CVSS ' + esc(data.cvss_score || "N/A") + "  ·  " + esc(data.affected_component || "") + "</div>" +
        '<div class="finding-desc">' + esc(data.description || "") + "</div>" +
        (remSteps ? '<div class="finding-remediation"><span class="finding-label">Remediation</span><br>' + remSteps + "</div>" : "") +
        (data.attack_scenario ? '<div class="finding-attack"><span class="finding-label">Attack Scenario</span> ' + esc(data.attack_scenario) + "</div>" : "") +
        '<div class="finding-body-actions"><button class="remediation-btn finding-exec-btn" data-finding-id="' + f.id + '" onclick="event.stopPropagation();remediate(this)">Execute Fix</button></div>' +
      "</div></div>";
    list.appendChild(card);
  });
}

function toggleFinding(header) {
  header.parentElement.classList.toggle("expanded");
}

function remediate(btn) {
  const findingId = btn.dataset.findingId;
  const finding = findingDataMap[findingId];
  if (!finding) return;
  btn.disabled = true;
  btn.textContent = "Running...";
  btn.className = "remediation-btn running";
  ws.send(JSON.stringify({cmd: "remediate", finding: finding}));
}

function onRemediationComplete(data) {
  const findingId = data.finding_id;
  const btn = document.querySelector('.remediation-btn[data-finding-id="' + findingId + '"]');
  if (!btn) return;
  btn.disabled = false;
  const success = data.all_success;
  if (success) {
    btn.textContent = "✓ Fixed";
    btn.className = "remediation-btn done";
  } else {
    btn.textContent = "✗ Failed";
    btn.className = "remediation-btn failed";
  }

  // Add to Remediation Activity sidebar
  const section = document.getElementById("remediationSection");
  const list = document.getElementById("remediationList");
  section.style.display = "block";
  const item = document.createElement("div");
  item.className = "remediation-item";
  item.innerHTML =
    '<span class="r-icon">' + (success ? '✓' : '✗') + '</span>' +
    '<span class="r-title">' + esc(findingId) + '</span>' +
    '<span class="r-status ' + (success ? 'success' : 'failed') + '">' + (success ? 'Fixed' : 'Failed') + '</span>';
  list.insertBefore(item, list.firstChild);
}

function onComplete(data) {
  if (data.pdf_path) {
    document.getElementById("dlPdf").href = "/report/" + encodeURIComponent(data.pdf_path.split(/[\\/]/).pop());
  }
  if (data.html_path) {
    document.getElementById("dlHtml").href = "/report/" + encodeURIComponent(data.html_path.split(/[\\/]/).pop());
  }
  if (data.json_path) {
    document.getElementById("dlJson").href = "/report/" + encodeURIComponent(data.json_path.split(/[\\/]/).pop());
  }
  downloadArea.style.display = "block";
}

function startAudit() {
  ws.send(JSON.stringify({cmd: "start_audit"}));
  // Reset state
  downloadArea.style.display = "none";
  execSection.style.display = "none";
  document.getElementById("findingsList").innerHTML = "";
  findingDataMap = {};
  document.getElementById("remediationSection").style.display = "none";
  document.getElementById("remediationList").innerHTML = "";
  document.querySelectorAll(".phase").forEach(p => { p.classList.remove("active","done"); });
  // Keep log but add a separator
  const sep = document.createElement("div");
  sep.style.cssText = "text-align:center;padding:12px;color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:2px;border-bottom:1px solid var(--border);margin-bottom:8px";
  sep.textContent = "——— New Audit ———";
  logStream.appendChild(sep);
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return HTML


@app.route("/report/<path:filename>")
def download_report(filename):
    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    return send_file(os.path.join(report_dir, filename), as_attachment=True)


@sock.route("/ws")
def ws_handler(ws):
    _ws_clients.append(ws)
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue
            if msg.get("cmd") == "start_audit":
                _start_audit_background()
            elif msg.get("cmd") == "remediate":
                finding = msg.get("finding")
                if finding:
                    _start_remediation_background(finding)
    except Exception:
        pass
    finally:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


def broadcast(event: dict):
    dead = []
    for ws in _ws_clients:
        try:
            ws.send(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


def _start_audit_background():
    global _audit_thread
    if _audit_thread and _audit_thread.is_alive():
        return
    _audit_thread = threading.Thread(target=_run_engine, daemon=True)
    _audit_thread.start()


def _run_engine():
    engine = _engine_ref
    if engine is None:
        broadcast({"agent": "system", "type": "error", "data": {"message": "Engine not initialized"}})
        return

    broadcast({"agent": "system", "type": "status", "data": {"status": "running"}})

    def event_handler(agent_name, event_type, data):
        broadcast({"agent": agent_name, "type": event_type, "data": data})

    for agent in [engine.enumerator, engine.analyzer, engine.reporter]:
        agent._handlers = []
        agent.on_event(event_handler)

    try:
        result = engine.run_audit()
        summary = result.get("summary", {})
        findings = result.get("findings", [])
        exec_summary = result.get("executive_summary", "")
        report = result.get("report", {})

        broadcast({"agent": "system", "type": "executive", "data": {
            "executive_summary": exec_summary,
            "overall_risk": summary.get("overall_risk", "N/A"),
            "primary_attack_vectors": summary.get("primary_attack_vectors", []),
        }})
        broadcast({"agent": "system", "type": "summary", "data": summary})
        broadcast({"agent": "system", "type": "findings", "data": {"findings": findings}})
        broadcast({"agent": "system", "type": "complete", "data": {
            "json_path": report.get("json_path", ""),
            "html_path": report.get("html_path", ""),
            "pdf_path": report.get("pdf_path", ""),
        }})
        broadcast({"agent": "system", "type": "status", "data": {"status": "done"}})
    except Exception as e:
        logger.exception("Audit failed")
        broadcast({"agent": "system", "type": "error", "data": {"message": str(e)}})
        broadcast({"agent": "system", "type": "status", "data": {"status": "error"}})


def _start_remediation_background(finding):
    thread = threading.Thread(target=_run_remediation, args=(finding,), daemon=True)
    thread.start()


def _run_remediation(finding):
    engine = _engine_ref
    if engine is None:
        broadcast({"agent": "system", "type": "error", "data": {"message": "Engine not initialized"}})
        return

    claude = engine.analyzer.claude
    remediator = RemediatorAgent(claude)

    def event_handler(agent_name, event_type, data):
        broadcast({"agent": agent_name, "type": event_type, "data": data})

    remediator._handlers = []
    remediator.on_event(event_handler)

    try:
        result = remediator.remediate(finding)
        broadcast({
            "agent": "system",
            "type": "remediation_complete",
            "data": {
                "finding_id": result.get("finding_id", "unknown"),
                "status": result.get("status", "unknown"),
                "all_success": result.get("all_success", False),
            },
        })
    except Exception as e:
        logger.exception("Remediation failed")
        broadcast({"agent": "system", "type": "error", "data": {"message": f"Remediation execution error: {e}"}})


def start_dashboard(engine):
    global _engine_ref
    _engine_ref = engine
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)
