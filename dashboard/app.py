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
.logo-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--accent-cyan),var(--accent-purple));border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:#fff;position:relative}
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
.entry{margin-bottom:4px;padding:8px 12px;border-radius:6px;font-size:13px;line-height:1.5}
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

.finding-exec-btn{margin-left:0!important}
.agent-badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;letter-spacing:.3px}
.agent-badge.enumerator{background:rgba(255,111,60,.15);color:var(--accent-orange)}
.agent-badge.analyzer{background:rgba(0,188,212,.15);color:var(--accent-cyan)}
.agent-badge.reporter{background:rgba(0,230,118,.15);color:var(--accent-green)}
.agent-badge.exploiter{background:rgba(255,23,68,.15);color:var(--accent-red)}
.agent-badge.remediator{background:rgba(255,215,64,.15);color:var(--accent-gold)}
.agent-badge.system{background:rgba(179,136,255,.15);color:var(--accent-purple)}
.agent-icon{font-size:12px}
.entry-sep{font-size:10px;color:var(--text-dim)}
.entry-time{font-size:10px;color:var(--text-dim)}
.entry-msg{margin-top:3px;padding-left:4px;color:var(--text);white-space:pre-wrap;word-break:break-word}
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

/* CVE / MSF / exploit / attack chain badges and blocks */
.cve-badge{display:inline-block;font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(255,23,68,.15);color:var(--accent-red);letter-spacing:.3px;vertical-align:middle;margin-left:4px}
.msf-badge{display:inline-block;font-size:8px;font-weight:700;padding:2px 5px;border-radius:3px;background:rgba(0,188,212,.15);color:var(--accent-cyan);text-transform:uppercase;letter-spacing:.5px;vertical-align:middle;margin-left:4px}
.finding-exploit{margin-top:6px}
.finding-exploit pre{background:rgba(0,0,0,.25);padding:6px 10px;border-radius:4px;font-size:11px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);white-space:pre-wrap;word-break:break-word;line-height:1.5;margin-top:4px;border:1px solid rgba(255,255,255,.04);overflow-x:auto}
.finding-chain{font-size:12px;color:var(--accent-orange);line-height:1.5;margin-top:4px;padding:4px 8px;background:rgba(255,111,60,.06);border-radius:4px;border-left:2px solid var(--accent-orange)}
.exploit-code{background:rgba(0,0,0,.25);padding:8px 10px;border-radius:4px;font-size:11px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);white-space:pre-wrap;word-break:break-word;line-height:1.5;border:1px solid rgba(255,255,255,.04);overflow-x:auto;margin:4px 0}
.attack-chain{font-size:12px;color:var(--accent-orange);line-height:1.5;padding:4px 8px;background:rgba(255,111,60,.06);border-radius:4px;border-left:2px solid var(--accent-orange);margin:4px 0}
.chain-step{display:flex;align-items:baseline;gap:8px;padding:3px 0}
.chain-step+.chain-step{border-top:1px solid rgba(255,111,60,.12)}
.chain-num{flex-shrink:0;width:20px;height:20px;display:flex;align-items:center;justify-content:center;background:var(--accent-orange);color:#fff;border-radius:50%;font-size:10px;font-weight:700}
.chain-text{color:var(--text-primary);font-size:12px}

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

/* Kill chain visualization */
.kill-chain{display:flex;flex-direction:column;gap:2px;margin-top:10px}
.kill-node{display:flex;align-items:flex-start;gap:10px;padding:8px 10px;border-radius:6px;background:var(--bg-card);border:1px solid var(--border);font-size:11px;line-height:1.4;transition:.2s}
.kill-node:hover{border-color:var(--accent-cyan)}
.kill-node .kc-stage{font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--accent-cyan);white-space:nowrap;min-width:85px;padding-top:1px}
.kill-node .kc-body{flex:1}
.kill-node .kc-tech{font-size:11px;font-weight:600;color:var(--text)}
.kill-node .kc-detail{font-size:10px;color:var(--text-dim);margin-top:1px}
.kill-node .kc-status{font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;padding:2px 6px;border-radius:3px;white-space:nowrap}
.kill-node .kc-status.completed{background:rgba(0,230,118,.12);color:var(--accent-green)}
.kill-node .kc-status.confirmed{background:rgba(255,23,68,.12);color:var(--accent-red)}
.kill-node .kc-status.potential{background:rgba(255,215,64,.1);color:var(--accent-gold)}
.kill-chain-arrow{text-align:center;font-size:10px;color:var(--text-dim);padding:0 0 2px;letter-spacing:4px}

/* Vulnerability probe output */
.vuln-entry{background:rgba(255,23,68,.03);border-left:2px solid var(--accent-red);padding:8px 12px;margin-bottom:2px}
.vuln-entry .vuln-hdr{display:flex;align-items:center;gap:6px;font-size:12px}
.vuln-entry .vuln-cve{font-weight:700;color:var(--accent-red)}
.vuln-entry .vuln-service{color:var(--text-dim);font-size:11px}
.vuln-entry .vuln-output{margin-top:4px;padding:4px 8px;background:rgba(0,0,0,.2);border-radius:4px;font-size:11px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);white-space:pre-wrap;word-break:break-word;line-height:1.3}
.vuln-badge{display:inline-block;font-size:8px;font-weight:700;padding:2px 5px;border-radius:3px;text-transform:uppercase;letter-spacing:.3px}
.vuln-badge.confirmed{background:rgba(255,23,68,.15);color:var(--accent-red)}
.vuln-badge.probed{background:rgba(255,215,64,.12);color:var(--accent-gold)}

/* Exploitation summary */
.exploit-summary-card{background:var(--bg-card);border-radius:8px;padding:10px;border:1px solid var(--border);margin-bottom:10px}
.exploit-summary-card .es-header{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--accent-red);margin-bottom:6px;display:flex;align-items:center;gap:6px}
.exploit-summary-card .es-stats{display:grid;grid-template-columns:1fr 1fr;gap:4px}
.exploit-summary-card .es-stat{text-align:center;padding:4px}
.exploit-summary-card .es-stat .es-val{font-size:18px;font-weight:700}
.exploit-summary-card .es-stat .es-val.critical{color:var(--accent-red)}
.exploit-summary-card .es-stat .es-val.success{color:var(--accent-green)}
.exploit-summary-card .es-stat .es-label{font-size:8px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.3px}

/* Credential spray results */
.cred-hit{display:flex;align-items:center;gap:6px;padding:4px 8px;background:rgba(255,23,68,.08);border-radius:4px;margin-top:4px;font-size:11px;border:1px solid var(--accent-red)}
.cred-hit .cred-service{font-weight:600;color:var(--accent-red)}
.cred-hit .cred-creds{color:var(--accent-gold);font-family:'JetBrains Mono','Fira Code',monospace;font-size:10px}

/* Compromised hosts panel */
.compromised-card{background:var(--bg-card);border-radius:8px;border:1px solid var(--accent-green);overflow:hidden;margin-bottom:8px}
.compromised-card .cc-header{display:flex;align-items:center;gap:8px;padding:8px 10px;background:rgba(0,230,118,.06);border-bottom:1px solid rgba(0,230,118,.12)}
.compromised-card .cc-icon{font-size:14px}
.compromised-card .cc-ip{font-size:12px;font-weight:600;color:var(--accent-green)}
.compromised-card .cc-creds{font-size:10px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);margin-left:auto}
.compromised-card .cc-body{padding:8px 10px}
.compromised-card .cc-info{display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:6px}
.compromised-card .cc-info-item{font-size:10px;color:var(--text-dim)}
.compromised-card .cc-info-item strong{color:var(--text);font-weight:600}
.cc-shell-badge{display:inline-block;font-size:8px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(0,230,118,.15);color:var(--accent-green);text-transform:uppercase;letter-spacing:.5px;margin-left:auto}
.shell-output{margin-top:3px;padding:3px 6px;background:rgba(0,0,0,.15);border-radius:3px;font-size:10px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);white-space:pre-wrap;word-break:break-word;line-height:1.3;border-left:2px solid var(--accent-green)}
.shell-output .shell-prompt{color:var(--accent-green);font-weight:600}
.shell-output-header{display:flex;align-items:center;gap:6px;padding:4px 0;font-size:10px;color:var(--text-dim);margin-top:2px}
.shell-output-header .shell-ip{color:var(--accent-green);font-weight:600}

/* Tabs */
.tabs{display:flex;gap:0;align-items:stretch}
.tab{padding:8px 14px;font-size:11px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;color:var(--text-dim);transition:.2s;user-select:none;white-space:nowrap}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent-cyan);border-bottom-color:var(--accent-cyan)}
.tab-panel{display:none;flex:1;overflow:hidden;flex-direction:column}
.tab-panel.active{display:flex}

/* Remediation panel */
#rem-findings-list{overflow-y:auto;padding:8px 12px;flex:1}
.rem-finding-card{background:var(--bg-card);border-radius:8px;border:1px solid var(--border);padding:10px 12px;margin-bottom:6px}
.rem-finding-card.critical{border-left:3px solid var(--accent-red)}
.rem-finding-card.high{border-left:3px solid var(--accent-orange)}
.rem-finding-card.medium{border-left:3px solid var(--accent-gold)}
.rem-finding-card.low{border-left:3px solid var(--accent-cyan)}
.rem-finding-card.info{border-left:3px solid var(--text-dim)}
.rem-finding-header{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.rem-finding-title{font-size:12px;font-weight:500;color:var(--text);flex:1}
.rem-exec-btn{font-size:9px;font-weight:600;padding:4px 10px;border-radius:4px;border:none;background:rgba(0,230,118,.14);color:var(--accent-green);cursor:pointer;font-family:inherit;transition:.2s;white-space:nowrap}
.rem-exec-btn:hover:not(:disabled){background:rgba(0,230,118,.25)}
.rem-exec-btn:disabled{cursor:not-allowed;opacity:.7}
.rem-exec-btn.running{background:rgba(255,215,64,.14);color:var(--accent-gold);animation:pulse 1s infinite}
.rem-exec-btn.done{background:rgba(0,230,118,.2);color:var(--accent-green);cursor:default}
.rem-exec-btn.failed{background:rgba(255,23,68,.14);color:var(--accent-red);cursor:default}
.rem-finding-remediation{font-size:11px;color:var(--accent-green);line-height:1.4;margin-top:4px;padding:4px 8px;background:rgba(0,0,0,.1);border-radius:4px;white-space:pre-wrap}
#rem-output-area{margin:8px 12px;padding:10px;background:var(--bg-card);border-radius:8px;border:1px solid var(--accent-gold);max-height:none;overflow-y:visible}
#rem-output-container{font-size:12px}
#rem-output-container .rc-step{margin-bottom:3px}
#rem-back-btn{font-size:10px;color:var(--accent-cyan);cursor:pointer;margin-bottom:8px;display:inline-block}

/* In-card remediation output */
.remediation-output{margin-top:8px;border-top:1px solid var(--border);padding-top:8px}
.rc-step{padding:4px 8px;border-radius:4px;font-size:12px;line-height:1.5;margin-bottom:2px}
.rc-step.rc-thinking{background:rgba(255,215,64,.04);border-left:2px solid var(--accent-gold)}
.rc-step.rc-command{background:rgba(0,188,212,.04);border-left:2px solid var(--accent-cyan);font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px}
.rc-step.rc-command code{background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px;font-size:11px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold)}
.rc-step.rc-output{background:rgba(96,96,128,.04);border-left:2px solid var(--text-dim);font-family:'JetBrains Mono','Fira Code',monospace;font-size:10px;color:var(--text-dim);padding:4px 8px 4px 16px;margin-left:4px}
.rc-step.rc-result{background:rgba(0,230,118,.04);border-left:2px solid var(--accent-green)}
.rc-preview{background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:8px 10px;margin-bottom:6px}
.rc-preview .rc-preview-header{font-size:11px;font-weight:600;color:var(--text);margin-bottom:4px}
.rc-preview .rc-preview-cmd{font-size:11px;font-family:'JetBrains Mono','Fira Code',monospace;color:var(--accent-gold);background:rgba(0,0,0,.15);padding:6px 8px;border-radius:4px;white-space:pre-wrap;word-break:break-word;margin-top:4px}
.apply-remediation-btn{display:block;width:100%;padding:8px;margin-top:8px;margin-bottom:8px;background:linear-gradient(135deg,var(--accent-green),#00c853);color:#000;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;transition:.2s}
.apply-remediation-btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,230,118,.3)}
.apply-remediation-btn:disabled{opacity:.5;cursor:not-allowed}

/* Scrollbar */
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
::-webkit-scrollbar-thumb:hover{background:var(--text-dim)}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" fill="rgba(255,255,255,0.12)"/>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
        <line x1="12" y1="22.08" x2="12" y2="12"/>
      </svg>
    </div>
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
      <div class="tabs">
        <span class="tab active" data-tab="activity" onclick="switchTab('activity')">📋 Agent Activity Log</span>
        <span class="tab" data-tab="remediation" onclick="switchTab('remediation')">🔧 Remediation</span>
      </div>
      <div id="phase-indicator">
        <span class="phase" id="phase-enum">01 Enumerate</span>
        <span class="phase" id="phase-analyze">02 Analyze</span>
        <span class="phase" id="phase-exploit">03 Exploit</span>
        <span class="phase" id="phase-report">04 Report</span>
      </div>
    </div>
    <div id="tab-activity" class="tab-panel active">
      <div id="log-stream">
        <div id="empty-state">
          <div class="hero-icon">▣</div>
          <h2>Ready to scan attack surface</h2>
          <p>Click <strong>Execute Audit</strong> to deploy autonomous agents that will enumerate, analyze, and report on VirtualBox security misconfigurations from an attacker's perspective.</p>
        </div>
      </div>
    </div>
    <div id="tab-remediation" class="tab-panel">
      <div id="rem-findings-list"></div>
      <div id="rem-output-area" style="display:none">
        <div id="rem-output-container"></div>
      </div>
      <div id="rem-empty-state" style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--text-dim);text-align:center;padding:40px">
        <div style="font-size:48px;margin-bottom:16px">🔧</div>
        <h2 style="color:var(--text);font-size:18px;font-weight:600;margin-bottom:8px">No findings yet</h2>
        <p style="color:var(--text-dim);font-size:13px;max-width:350px;line-height:1.6">Run an audit first. Findings that need remediation will appear here with the ability to execute fixes.</p>
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

    <!-- Kill Chain -->
    <div id="killChainSection" class="sidebar-section" style="display:none">
      <div class="section-title">Kill Chain</div>
      <div id="killChainContainer"></div>
    </div>

    <!-- Exploitation Summary -->
    <div id="exploitSummarySection" class="sidebar-section" style="display:none">
      <div class="section-title">Active Exploitation</div>
      <div id="exploitSummaryContainer"></div>
      <div id="credHitsContainer"></div>
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
      <div class="section-title">Findings <span style="font-weight:400;color:var(--text-dim);font-size:8px;letter-spacing:0;text-transform:none">(click to expand)</span></div>
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

    <!-- Compromised Hosts -->
    <div id="compromisedSection" class="sidebar-section" style="display:none">
      <div class="section-title">Compromised Hosts <span style="font-weight:400;color:var(--accent-green);font-size:8px;letter-spacing:0;text-transform:none">(shell obtained)</span></div>
      <div id="compromisedList"></div>
    </div>
  </div>
</div>

<script>
// Agent display config
const AGENTS = {
  enumerator: { label: "Enumerator", icon: "🔍", cls: "enumerator" },
  analyzer:   { label: "Analyzer",   icon: "🧠", cls: "analyzer" },
  exploiter:  { label: "Exploiter",  icon: "⚔", cls: "exploiter" },
  reporter:   { label: "Reporter",   icon: "📊", cls: "reporter" },
  remediator: { label: "Remediator", icon: "🔧", cls: "remediator" },
  system:     { label: "System",     icon: "⚙️", cls: "system" },
};

// HTML escaping helper
function esc(s) {
  if (s == null) return "";
  const d = document.createElement("div");
  d.textContent = String(s);
  return d.innerHTML;
}

function formatAttackChain(chain) {
  if (!chain) return "";
  return chain.split(/\s*->\s*/).filter(Boolean).map(function(step, i) {
    return '<div class="chain-step"><span class="chain-num">' + (i + 1) + '</span><span class="chain-text">' + esc(step.trim()) + '</span></div>';
  }).join("");
}

// Event queue for slow streaming
const eventQueue = [];
let processing = false;
const STREAM_DELAY = 800; // ms between entries — slowed for readability

// Track last command entry for grouping output beneath it
let _lastCmdEntry = null;

// In-card remediation tracking
let _activeRemediationContainer = null;
let _activeRemediationPlan = null;
let _cardLastCmdEl = null;

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

  // Remediation events route to remediation tab only, NOT main log
  if (msg.agent === "remediator") {
    if (["thinking","command","output","result"].includes(msg.type)) {
      if (_activeRemediationContainer) {
        renderRemediationToCard(msg.type, msg.data);
      }
      // Skip main log for these event types
      setTimeout(processNext, STREAM_DELAY);
      return;
    }
    // remediation_plan, remediation_complete fall through to normal handlers
  }

  if (msg.type === "status") { updateStatus(msg.data); }
  else if (msg.type === "summary") { updateSummary(msg.data); }
  else if (msg.type === "findings") { renderFindings(msg.data); }
  else if (msg.type === "complete") { onComplete(msg.data); }
  else if (msg.type === "executive") { renderExecutive(msg.data); }
  else if (msg.type === "error") { addEntry(msg.agent, "error", msg.data); }
  else if (msg.type === "remediation_plan") { onRemediationPlan(msg.data); }
  else if (msg.type === "remediation_complete") { onRemediationComplete(msg.data); }
  else if (msg.type === "kill_chain") { renderKillChain(msg.data); }
  else if (msg.type === "vulnerability") { addVulnerabilityEntry(msg.data); }
  else if (msg.type === "exploitation_summary") { renderExploitSummary(msg.data); }
  else if (msg.type === "compromise") { addCompromisedHost(msg.data); }
  else if (msg.type === "shell_output") { addShellOutput(msg.data); }
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
  else if (agent === "exploiter" && type === "thinking" && data.message && data.message.includes("Initializing")) setPhase("exploit", "active");
  else if (agent === "exploiter" && type === "result") setPhase("exploit", "done");
  else if (agent === "reporter" && type === "thinking") setPhase("report", "active");
  else if (agent === "reporter" && type === "result") setPhase("report", "done");

  // Clear last command entry on non-output events (avoids stale grouping)
  if (type !== "output") _lastCmdEntry = null;

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
    _lastCmdEntry = { agent: agent, el: el };
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
          (data.cve ? '<span class="cve-badge">' + esc(data.cve) + "</span>" : "") +
          (data.metasploit ? '<span class="msf-badge">MSF</span>' : "") +
        "</div>" +
        '<div class="finding-meta">CVSS ' + esc(data.cvss_score || "N/A") + "  ·  " + esc(data.affected_component || "") + "</div>" +
        '<div class="finding-desc">' + esc(data.description || "") + "</div>" +
        (data.exploit_poc ? '<div class="finding-exploit"><span class="finding-label">Exploit PoC</span><pre>' + esc(data.exploit_poc) + "</pre></div>" : "") +
        (data.attack_chain ? '<div class="finding-chain"><span class="finding-label">Attack Chain</span> ' + esc(data.attack_chain) + "</div>" : "") +
        (remSteps ? '<div class="finding-remediation"><span class="finding-label">Remediation</span><br>' + remSteps + "</div>" : "") +
        (data.attack_scenario ? '<div class="finding-attack"><span class="finding-label">Attack Scenario</span> ' + esc(data.attack_scenario) + "</div>" : "") +
      "</div>";
  }

  // Agent badge + timestamp header with separator
  const time = new Date().toLocaleTimeString("en-US", { hour12: true, hour: "numeric", minute: "2-digit", second: "2-digit" });
  const badgeHtml = '<span class="agent-badge ' + info.cls + '">' + info.icon + ' ' + info.label + '</span><span class="entry-sep"> · </span><span class="entry-time">' + time + '</span>';

  el.innerHTML = badgeHtml + msgHtml;
  logStream.appendChild(el);
  logStream.scrollTop = logStream.scrollHeight;
}

// ===== MISSING UTILITY FUNCTIONS =====

function setPhase(name, state) {
  var el = document.getElementById("phase-" + name);
  if (el) {
    el.classList.remove("active","done");
    el.classList.add(state);
  }
}

function updateStatus(data) {
  var dot = document.getElementById("statusDot");
  var text = document.getElementById("statusText");
  var btn = document.getElementById("execBtn");
  if (!dot || !text) return;
  dot.className = "status-dot";
  if (data.status === "running") {
    dot.classList.add("running");
    text.textContent = "Running...";
  } else if (data.status === "done") {
    dot.classList.add("done");
    text.textContent = "Complete";
    if (btn) { btn.disabled = false; btn.textContent = "▲ Execute Audit"; }
  } else if (data.status === "error") {
    dot.classList.add("error");
    text.textContent = "Error";
    if (btn) { btn.disabled = false; btn.textContent = "▲ Execute Audit"; }
  } else {
    dot.classList.add("ready");
    text.textContent = "Ready";
  }
}

function updateSummary(data) {
  var setVal = function(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val || "0";
  };
  setVal("s-total", data.total_findings);
  setVal("s-critical", data.critical);
  setVal("s-high", data.high);
  setVal("s-medium", data.medium);
  setVal("s-low", data.low);
  setVal("s-info", data.info);
}

function renderExecutive(data) {
  var section = document.getElementById("execSection");
  var textEl = document.getElementById("execText");
  var riskEl = document.getElementById("riskTag");
  var vectorEl = document.getElementById("vectorList");
  if (!section || !textEl) return;
  section.style.display = "block";
  textEl.textContent = data.executive_summary || "";
  if (riskEl) {
    var risk = (data.overall_risk || "N/A").toLowerCase();
    riskEl.className = "risk-tag " + risk;
    riskEl.textContent = "Overall Risk: " + (data.overall_risk || "N/A");
  }
  if (vectorEl) {
    vectorEl.innerHTML = "";
    (data.primary_attack_vectors || []).forEach(function(v) {
      var tag = document.createElement("span");
      tag.className = "vector-tag";
      tag.textContent = v;
      vectorEl.appendChild(tag);
    });
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelector('.tab[data-tab="' + name + '"]').classList.add('active');
}

function remediateFromTab(findingId) {
  var finding = findingDataMap[findingId];
  if (!finding) return;

  var list = document.getElementById('rem-findings-list');
  var outputArea = document.getElementById('rem-output-area');
  var container = document.getElementById('rem-output-container');
  var backBtn = document.getElementById('rem-back-btn');

  // Show output area, hide findings list
  list.style.display = 'none';
  outputArea.style.display = 'block';
  container.innerHTML = '<div style="margin-bottom:6px;font-size:11px;font-weight:600;color:var(--accent-gold)">' + esc(finding.title) + '</div><div class="rc-step rc-thinking"><span class="info">⟐</span> Generating remediation plan...</div>';
  _activeRemediationContainer = container;
  _activeRemediationPlan = null;
  _cardLastCmdEl = null;

  // Update Execute button in rem-findings-list
  var btns = document.querySelectorAll('.rem-exec-btn[data-finding-id="' + findingId + '"]');
  btns.forEach(function(b) { b.disabled = true; b.textContent = "Planning..."; b.className = "rem-exec-btn running"; });

  ws.send(JSON.stringify({cmd: "plan_remediation", finding: finding}));
}

function backToRemList() {
  _activeRemediationContainer = null;
  _activeRemediationPlan = null;
  _cardLastCmdEl = null;
  document.getElementById('rem-findings-list').style.display = 'block';
  document.getElementById('rem-output-area').style.display = 'none';
}

// =====

let findingDataMap = {};

function renderFindings(data) {
  const list = document.getElementById("findingsList");
  list.innerHTML = "";
  // Also populate remediation tab
  const remList = document.getElementById("rem-findings-list");
  remList.innerHTML = "";
  var remEmpty = document.getElementById("rem-empty-state");
  if (remEmpty) remEmpty.style.display = "none";
  (data.findings || []).forEach(f => {
    findingDataMap[f.id] = f;
    const sev = (f.severity || "info").toLowerCase();

    // Sidebar card (no Execute button — remediation moved to tab)
    const card = document.createElement("div");
    card.className = "finding-card " + sev;
    card.dataset.findingId = f.id;
    card.innerHTML =
      '<div class="finding-header" onclick="toggleFinding(this)">' +
        '<span class="sev-badge ' + sev + '">' + (f.severity || "INFO") + "</span>" +
        '<span class="finding-title">' + esc(f.title) + "</span>" +
        '<span class="cvss-tag">CVSS ' + (f.cvss_score || "N/A") + "</span>" +
        (f.cve ? '<span class="cve-badge">' + esc(f.cve) + "</span>" : "") +
        '<span class="expand-icon">▼</span>' +
      "</div>" +
      '<div class="finding-body"><div class="finding-body-inner">' +
        '<div class="desc">' + esc(f.description || "") + "</div>" +
        '<div class="section-label">Attack Scenario</div>' +
        '<div class="attack-scenario">' + esc(f.attack_scenario || "N/A") + "</div>" +
        (f.exploit_poc ? '<div class="section-label">Exploit PoC</div><pre class="exploit-code">' + esc(f.exploit_poc) + "</pre>" : "") +
        (f.attack_chain ? '<div class="section-label">Attack Chain</div><div class="attack-chain">' + formatAttackChain(f.attack_chain) + "</div>" : "") +
      "</div></div>";
    list.appendChild(card);

    // Remediation tab entry
    var remCard = document.createElement("div");
    remCard.className = "rem-finding-card " + sev;
    remCard.innerHTML =
      '<div class="rem-finding-header">' +
        '<span class="sev-badge ' + sev + '">' + (f.severity || "INFO") + "</span>" +
        '<span class="rem-finding-title">' + esc(f.title) + "</span>" +
        '<span class="cvss-tag">CVSS ' + (f.cvss_score || "N/A") + "</span>" +
        '<button class="rem-exec-btn" data-finding-id="' + f.id + '" onclick="remediateFromTab(\'' + f.id + '\')">Execute Fix</button>' +
      "</div>" +
      '<div class="rem-finding-remediation">' + (f.remediation ? f.remediation.split("\n").filter(function(s) { return s.trim(); }).map(function(s) { return "• " + esc(s.trim()); }).join("<br>") : "N/A") + "</div>";
    remList.appendChild(remCard);
  });
}

function toggleFinding(header) {
  header.parentElement.classList.toggle("expanded");
}

function onRemediationPlan(data) {
  const container = _activeRemediationContainer;
  if (!container) return;

  const steps = data.steps || [];
  const findingId = data.finding_id;

  if (steps.length === 0) {
    container.innerHTML = '<div class="rc-step rc-result"><span class="warn">⟐</span> ' + esc(data.note || "No automated remediation available") + '</div>';
    document.querySelectorAll('.rem-exec-btn[data-finding-id="' + findingId + '"]').forEach(function(b) {
      b.disabled = false;
      b.textContent = "N/A";
      b.className = "rem-exec-btn";
    });
    _activeRemediationContainer = null;
    return;
  }

  _activeRemediationPlan = data;

  // Render plan preview with each command, Back button, and Apply button
  var html = '<span id="rem-back-btn" onclick="backToRemList()">← Back to findings list</span>';
  steps.forEach(function(step, i) {
    html += '<div class="rc-preview">' +
      '<div class="rc-preview-header">Step ' + (i+1) + ': ' + esc(step.description || '') + '</div>' +
      '<div class="rc-preview-cmd"><span class="warn">$</span> ' + esc(step.command || '') + '</div>' +
    '</div>';
  });
  html += '<button class="apply-remediation-btn" id="applyRemBtn" onclick="applyRemediation()">Apply ' + steps.length + ' Command' + (steps.length > 1 ? 's' : '') + '</button>';
  html += '<div id="rcExecutionOutput"></div>';
  container.innerHTML = html;

  // Update buttons in remediation tab list
  document.querySelectorAll('.rem-exec-btn[data-finding-id="' + findingId + '"]').forEach(function(b) {
    b.textContent = "Plan Ready";
    b.className = "rem-exec-btn done";
    b.disabled = false;
  });
}

function applyRemediation() {
  if (!_activeRemediationPlan) return;
  const container = _activeRemediationContainer;
  if (!container) return;

  // Remove the Apply button, start execution output
  var applyBtn = container.querySelector('#applyRemBtn');
  if (applyBtn) applyBtn.remove();

  var execDiv = container.querySelector('#rcExecutionOutput');
  if (!execDiv) {
    execDiv = document.createElement('div');
    execDiv.id = 'rcExecutionOutput';
    container.appendChild(execDiv);
  }
  execDiv.innerHTML = '<div class="rc-step rc-thinking"><span class="info">⟐</span> Executing remediation...</div>';
  _cardLastCmdEl = null;

  // Disable all buttons for this finding in remediation tab
  var findingId = _activeRemediationPlan.finding_id;
  document.querySelectorAll('.rem-exec-btn[data-finding-id="' + findingId + '"]').forEach(function(b) {
    b.disabled = true;
    b.textContent = "Running...";
    b.className = "rem-exec-btn running";
  });

  ws.send(JSON.stringify({cmd: "execute_remediation", plan: _activeRemediationPlan}));
}

function renderRemediationToCard(type, data) {
  var container = _activeRemediationContainer;
  if (!container) return;

  // If execution output div exists inside container, append there; else append to container
  var target = container.querySelector('#rcExecutionOutput');
  if (!target) target = container;

  if (type === "thinking") {
    var el = document.createElement('div');
    el.className = 'rc-step rc-thinking';
    el.innerHTML = '<span class="info">⟐</span> ' + esc(data.message || "");
    target.appendChild(el);
    _cardLastCmdEl = null;
  } else if (type === "command") {
    var el = document.createElement('div');
    el.className = 'rc-step rc-command';
    el.innerHTML = '<span class="warn">$</span> <code>' + esc(data.command || "") + '</code>';
    target.appendChild(el);
    _cardLastCmdEl = el;
  } else if (type === "output") {
    var el = document.createElement('div');
    el.className = 'rc-step rc-output';
    el.textContent = data.output || "";
    if (_cardLastCmdEl) {
      // Insert after the command (or after the last output sibling of that command)
      var refEl = _cardLastCmdEl;
      while (refEl.nextSibling && refEl.nextSibling.classList && refEl.nextSibling.classList.contains('rc-output')) {
        refEl = refEl.nextSibling;
      }
      refEl.parentNode.insertBefore(el, refEl.nextSibling);
    } else {
      target.appendChild(el);
    }
  } else if (type === "result") {
    var el = document.createElement('div');
    el.className = 'rc-step rc-result';
    var txt = typeof data === "object" ? JSON.stringify(data, null, 2) : String(data);
    el.innerHTML = '<span class="highlight">✓</span> <span class="highlight">' + esc(txt) + "</span>";
    target.appendChild(el);
    _cardLastCmdEl = null;
  }

  target.scrollTop = target.scrollHeight;
}

function onRemediationComplete(data) {
  var findingId = data.finding_id;
  var success = data.all_success;

  // Update all buttons for this finding in remediation tab
  document.querySelectorAll('.rem-exec-btn[data-finding-id="' + findingId + '"]').forEach(function(btn) {
    btn.disabled = false;
    if (success) {
      btn.textContent = "✓ Fixed";
      btn.className = "rem-exec-btn done";
    } else {
      btn.textContent = "✗ Failed";
      btn.className = "rem-exec-btn failed";
    }
  });

  // Finalize output with Back button
  if (_activeRemediationContainer) {
    var backLink = document.createElement('div');
    backLink.innerHTML = '<span style="font-size:10px;color:var(--accent-cyan);cursor:pointer" onclick="backToRemList()">← Back to findings list</span>';
    _activeRemediationContainer.insertBefore(backLink, _activeRemediationContainer.firstChild);

    var el = document.createElement('div');
    el.className = 'rc-step rc-result';
    el.innerHTML = '<span class="highlight">✓</span> <span class="highlight">' + (success ? 'Completed successfully' : 'Completed with errors') + '</span>';
    var target = _activeRemediationContainer.querySelector('#rcExecutionOutput');
    if (target) target.appendChild(el);
    else _activeRemediationContainer.appendChild(el);
  }

  // Clear references after a brief delay so user can see final state
  setTimeout(function() {
    _activeRemediationContainer = null;
    _activeRemediationPlan = null;
    _cardLastCmdEl = null;
  }, 1000);

  // Add to Remediation Activity sidebar
  var section = document.getElementById("remediationSection");
  var list = document.getElementById("remediationList");
  section.style.display = "block";
  var item = document.createElement("div");
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
  var btn = document.getElementById("execBtn");
  if (btn.disabled) return;
  btn.disabled = true;
  btn.textContent = "Auditing...";
  ws.send(JSON.stringify({cmd: "start_audit"}));
  // Reset state
  downloadArea.style.display = "none";
  execSection.style.display = "none";
  document.getElementById("findingsList").innerHTML = "";
  findingDataMap = {};
  document.getElementById("remediationSection").style.display = "none";
  document.getElementById("remediationList").innerHTML = "";
  document.getElementById("killChainSection").style.display = "none";
  document.getElementById("exploitSummarySection").style.display = "none";
  document.getElementById("exploitSummaryContainer").innerHTML = "";
  document.getElementById("credHitsContainer").innerHTML = "";
  document.getElementById("compromisedSection").style.display = "none";
  document.getElementById("compromisedList").innerHTML = "";
  document.querySelectorAll(".phase").forEach(p => { p.classList.remove("active","done"); });
  // Clear remediation tab state
  _activeRemediationContainer = null;
  _activeRemediationPlan = null;
  _cardLastCmdEl = null;
  _lastCmdEntry = null;
  document.getElementById("rem-findings-list").innerHTML = "";
  document.getElementById("rem-output-area").style.display = "none";
  var remEmpty = document.getElementById("rem-empty-state");
  if (remEmpty) remEmpty.style.display = "flex";
  // Keep log but add a separator
  const sep = document.createElement("div");
  sep.style.cssText = "text-align:center;padding:12px;color:var(--text-dim);font-size:10px;text-transform:uppercase;letter-spacing:2px;border-bottom:1px solid var(--border);margin-bottom:8px";
  sep.textContent = "——— New Audit ———";
  logStream.appendChild(sep);
}

function renderKillChain(data) {
  const container = document.getElementById("killChainContainer");
  container.innerHTML = "";
  const chain = data.chain || [];
  if (chain.length === 0) return;
  document.getElementById("killChainSection").style.display = "block";
  chain.forEach((node, i) => {
    if (i > 0) {
      const arrow = document.createElement("div");
      arrow.className = "kill-chain-arrow";
      arrow.textContent = "▼";
      container.appendChild(arrow);
    }
    const el = document.createElement("div");
    el.className = "kill-node";
    const status = (node.status || "potential").toLowerCase();
    el.innerHTML =
      '<div class="kc-stage">' + esc(node.stage || "") + '</div>' +
      '<div class="kc-body">' +
        '<div class="kc-tech">' + esc(node.technique || "") + '</div>' +
        (node.detail ? '<div class="kc-detail">' + esc(node.detail) + '</div>' : "") +
      '</div>' +
      '<div class="kc-status ' + status + '">' + status + '</div>';
    container.appendChild(el);
  });
}

function addVulnerabilityEntry(data) {
  emptyState && emptyState.remove();
  const confirmed = data.confirmed;
  const el = document.createElement("div");
  el.className = "vuln-entry";
  el.innerHTML =
    '<div class="vuln-hdr">' +
      '<span class="vuln-badge ' + (confirmed ? "confirmed" : "probed") + '">' + (confirmed ? "CONFIRMED" : "PROBED") + '</span>' +
      '<span class="vuln-cve">' + esc(data.cve || "CVE-?") + '</span>' +
      '<span class="vuln-service">' + esc(data.ip || "?") + ":" + data.port + " (" + esc(data.service || "?") + ")</span>" +
    '</div>' +
    (data.probe_output ? '<div class="vuln-output">' + esc(data.probe_output) + "</div>" : "");
  logStream.appendChild(el);
  logStream.scrollTop = logStream.scrollHeight;
}

function renderExploitSummary(data) {
  const container = document.getElementById("exploitSummaryContainer");
  const credContainer = document.getElementById("credHitsContainer");
  container.innerHTML = "";
  credContainer.innerHTML = "";
  document.getElementById("exploitSummarySection").style.display = "block";
  const card = document.createElement("div");
  card.className = "exploit-summary-card";
  card.innerHTML =
    '<div class="es-header">⚔ Active Exploitation Results</div>' +
    '<div class="es-stats">' +
      '<div class="es-stat"><div class="es-val">' + (data.targets_scanned || 0) + '</div><div class="es-label">Targets</div></div>' +
      '<div class="es-stat"><div class="es-val">' + (data.services_probed || 0) + '</div><div class="es-label">Services</div></div>' +
      '<div class="es-stat"><div class="es-val critical">' + (data.cve_probes_executed || 0) + '</div><div class="es-label">CVE Probes</div></div>' +
      '<div class="es-stat"><div class="es-val success">' + (data.confirmed_vulnerabilities || 0) + '</div><div class="es-label">Confirmed Vulns</div></div>' +
      (data.hosts_compromised > 0 ? '<div class="es-stat" style="grid-column:1/-1"><div class="es-val" style="color:var(--accent-green);font-size:22px">' + data.hosts_compromised + '</div><div class="es-label">Hosts Compromised 💀</div></div>' : "") +
    '</div>' +
    (data.credentials_discovered > 0 ? '<div style="margin-top:6px;padding-top:6px;border-top:1px solid var(--border);font-size:11px;color:var(--accent-red);font-weight:600">🔑 ' + data.credentials_discovered + ' credential set(s) discovered</div>' : "");
  container.appendChild(card);
}

function addCompromisedHost(data) {
  document.getElementById("compromisedSection").style.display = "block";
  const list = document.getElementById("compromisedList");

  // Check if this host already exists
  let existing = list.querySelector('.compromised-card[data-ip="' + esc(data.ip) + '"]');
  if (existing) {
    // Update existing card's command output
    const body = existing.querySelector(".cc-commands");
    if (body && data.commands) {
      data.commands.forEach(cmd => {
        if (!cmd.output) return;
        const out = document.createElement("div");
        out.className = "shell-output";
        out.innerHTML = '<span class="shell-prompt">$</span> ' + esc(cmd.cmd) + "\n" + esc(cmd.output);
        body.appendChild(out);
      });
    }
    return;
  }

  const card = document.createElement("div");
  card.className = "compromised-card";
  card.dataset.ip = data.ip;

  const hostname = esc(data.hostname || data.ip);
  const whoami = esc(data.whoami || "?");
  const osInfo = esc((data.os_info || "").slice(0, 100));

  let commandsHtml = "";
  (data.commands || []).forEach(cmd => {
    if (!cmd.output) return;
    commandsHtml += '<div class="shell-output"><span class="shell-prompt">$</span> ' + esc(cmd.cmd) + "\n" + esc(cmd.output) + "</div>";
  });

  card.innerHTML =
    '<div class="cc-header">' +
      '<span class="cc-icon">💀</span>' +
      '<span class="cc-ip">' + esc(data.ip) + ':' + data.port + '</span>' +
      '<span class="cc-creds">' + esc(data.username) + ':' + esc(data.password) + '</span>' +
      '<span class="cc-shell-badge">SHELL</span>' +
    '</div>' +
    '<div class="cc-body">' +
      '<div class="cc-info">' +
        '<div class="cc-info-item"><strong>Hostname:</strong> ' + hostname + '</div>' +
        '<div class="cc-info-item"><strong>User:</strong> ' + whoami + '</div>' +
        (osInfo ? '<div class="cc-info-item" style="grid-column:1/-1"><strong>OS:</strong> ' + osInfo + '</div>' : "") +
      '</div>' +
      (commandsHtml ? '<div class="cc-commands">' + commandsHtml + "</div>" : "") +
    '</div>';

  list.insertBefore(card, list.firstChild);
}

function addShellOutput(data) {
  emptyState && emptyState.remove();
  const el = document.createElement("div");
  el.className = "entry";
  el.innerHTML =
    '<div class="shell-output-header">' +
      '<span style="color:var(--accent-green);font-weight:700">$</span>' +
      '<span class="shell-ip">' + esc(data.ip || "?") + '</span>' +
      '<span style="color:var(--text-dim)">' + esc(data.cmd || "") + '</span>' +
    '</div>' +
    '<div class="shell-output">' + esc(data.output || "") + '</div>';
  logStream.appendChild(el);
  logStream.scrollTop = logStream.scrollHeight;
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
            elif msg.get("cmd") == "plan_remediation":
                finding = msg.get("finding")
                if finding:
                    _start_remediation_plan_background(finding)
            elif msg.get("cmd") == "execute_remediation":
                plan = msg.get("plan")
                if plan:
                    _start_remediation_execute_background(plan)
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

    for agent in [engine.enumerator, engine.analyzer, engine.exploiter, engine.reporter]:
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


def _start_remediation_plan_background(finding):
    thread = threading.Thread(target=_run_remediation_plan, args=(finding,), daemon=True)
    thread.start()


def _start_remediation_execute_background(plan):
    thread = threading.Thread(target=_run_remediation_execute, args=(plan,), daemon=True)
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


def _run_remediation_plan(finding):
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
        plan = remediator.generate_plan(finding)
        broadcast({
            "agent": "remediator",
            "type": "remediation_plan",
            "data": plan,
        })
    except Exception as e:
        logger.exception("Remediation plan failed")
        broadcast({"agent": "system", "type": "error", "data": {"message": f"Remediation planning error: {e}"}})


def _run_remediation_execute(plan):
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
        result = remediator.execute_plan(plan)
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
        logger.exception("Remediation execution failed")
        broadcast({"agent": "system", "type": "error", "data": {"message": f"Remediation execution error: {e}"}})


def start_dashboard(engine):
    global _engine_ref
    _engine_ref = engine
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False, use_reloader=False)
