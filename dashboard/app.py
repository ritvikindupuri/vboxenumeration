import json
import logging
import asyncio

import aiohttp
from aiohttp import web

from config.settings import settings

logger = logging.getLogger(__name__)

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Argus AI-SOC</title>
<style>
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
html{font-size:15px}
body{font-family:-apple-system,'Segoe UI','Inter',system-ui,sans-serif;background:#070b12;color:#d1d5db;min-height:100vh;overflow-x:hidden;line-height:1.5;-webkit-font-smoothing:antialiased}

/* Header */
.header{background:linear-gradient(180deg,#0d1421 0%,#0a0f1a 100%);border-bottom:1px solid #1e293b;padding:18px 28px;display:flex;justify-content:space-between;align-items:center}
.header-left{display:flex;align-items:center;gap:12px}
.header-logo{width:36px;height:36px;background:linear-gradient(135deg,#00d4aa,#059669);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#070b12}
.header h1{font-size:20px;font-weight:700;color:#ecfdf5;letter-spacing:-0.3px}
.header h1 span{color:#ef4444}
.header .sub{font-size:11px;color:#64748b;letter-spacing:1.5px;text-transform:uppercase;margin-top:1px}
.header-right{display:flex;gap:10px;align-items:center}
.badge{display:flex;align-items:center;gap:7px;background:#151e2d;padding:6px 14px;border-radius:20px;font-size:12px;border:1px solid #1e293b;color:#94a3b8}
.badge .dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot.green{background:#10b981;box-shadow:0 0 8px rgba(16,185,129,0.4)}
.dot.red{background:#ef4444;box-shadow:0 0 8px rgba(239,68,68,0.4)}
.dot.yellow{background:#f59e0b;box-shadow:0 0 8px rgba(245,158,11,0.4)}

/* Tabs */
.tabs{display:flex;background:#0a0f1a;border-bottom:1px solid #1e293b;padding:0 28px;gap:0}
.tab{padding:12px 24px;font-size:13px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;color:#64748b;transition:all .15s;user-select:none;letter-spacing:0.3px}
.tab:hover{color:#e2e8f0;background:rgba(30,41,59,0.4)}
.tab.active{color:#10b981;border-bottom-color:#10b981}
.tab-content{display:none}
.tab-content.active{display:block}

/* Stats Bar */
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;padding:20px 28px 12px}
.stat-card{background:linear-gradient(180deg,#0d1421 0%,#0a0f1a 100%);border:1px solid #1e293b;border-radius:12px;padding:18px 20px;transition:border-color .2s}
.stat-card:hover{border-color:#334155}
.stat-card .label{font-size:11px;font-weight:600;text-transform:uppercase;color:#64748b;letter-spacing:0.8px;margin-bottom:6px}
.stat-card .value{font-size:30px;font-weight:700;letter-spacing:-0.5px;line-height:1.1}
.stat-card .value.green{color:#10b981}
.stat-card .value.red{color:#ef4444}
.stat-card .value.yellow{color:#f59e0b}
.stat-card .value.blue{color:#3b82f6}
.stat-card .value.purple{color:#8b5cf6}

/* Agent Pill Bar */
.agent-strip{display:flex;gap:8px;padding:8px 28px 16px;flex-wrap:wrap}
.agent-pill{display:flex;align-items:center;gap:8px;padding:7px 14px;border-radius:20px;font-size:12px;font-weight:600;white-space:nowrap;border:1px solid;cursor:default;transition:all .15s}
.agent-pill .pill-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.agent-pill .pill-iter{font-weight:500;opacity:0.7;margin-left:2px}

/* Main grid (Security tab) */
.main-grid{display:grid;grid-template-columns:1fr 360px;gap:16px;padding:0 28px 28px}
@media(max-width:1000px){.main-grid{grid-template-columns:1fr}}
.panel{background:linear-gradient(180deg,#0d1421 0%,#0a0f1a 100%);border:1px solid #1e293b;border-radius:12px;overflow:hidden}
.panel-header{padding:14px 20px;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;font-size:14px;font-weight:600;color:#e2e8f0}
.panel-header .count{background:#1e293b;padding:2px 10px;border-radius:8px;font-size:12px;font-weight:500;color:#94a3b8}
.panel-scroll{max-height:540px;overflow-y:auto}

/* Event rows */
.event-row{padding:12px 20px;border-bottom:1px solid #111927;display:flex;gap:12px;align-items:start;transition:background .12s}
.event-row:hover{background:rgba(30,41,59,0.3)}
.event-row:last-child{border-bottom:none}
.event-sev{font-size:10px;font-weight:700;text-transform:uppercase;padding:4px 10px;border-radius:6px;min-width:60px;text-align:center;letter-spacing:0.5px;flex-shrink:0;margin-top:1px}
.sev-CRITICAL{background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.25)}
.sev-HIGH{background:rgba(249,115,22,0.15);color:#f97316;border:1px solid rgba(249,115,22,0.25)}
.sev-MEDIUM{background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.25)}
.sev-LOW{background:rgba(59,130,246,0.15);color:#3b82f6;border:1px solid rgba(59,130,246,0.25)}
.sev-NOTICE{background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.25)}
.event-body{flex:1;min-width:0}
.event-body .rule{font-weight:600;font-size:14px;color:#f1f5f9}
.event-body .meta{color:#64748b;font-size:12px;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.event-time{color:#475569;font-size:11px;white-space:nowrap;flex-shrink:0;margin-top:3px}

/* Response / Agent feed in sidebar */
.response-row{font-size:12px;padding:10px 16px;border-bottom:1px solid #111927;display:flex;gap:8px;align-items:start}
.response-row .act{font-weight:700;font-size:11px;padding:2px 8px;border-radius:4px;flex-shrink:0}
.response-row .act.KILL{background:rgba(239,68,68,0.15);color:#ef4444}
.response-row .act.BLOCK{background:rgba(249,115,22,0.15);color:#f97316}
.response-row .act.ISOLATE{background:rgba(245,158,11,0.15);color:#f59e0b}
.response-row .act.ALERT{background:rgba(59,130,246,0.15);color:#3b82f6}
.response-row .desc{color:#94a3b8}

.feed-row{font-size:12px;padding:9px 16px;border-bottom:1px solid #111927}
.feed-row .feed-hdr{display:flex;justify-content:space-between;color:#64748b}
.feed-row .feed-hdr .feed-agent{font-weight:600}
.feed-row .feed-msg{color:#94a3b8;margin-top:2px;font-size:11px;line-height:1.4}

/* Agent Operations tab */
.agent-layout{display:grid;grid-template-columns:300px 1fr;gap:16px;padding:16px 28px 28px;height:calc(100vh - 170px)}
@media(max-width:1100px){.agent-layout{grid-template-columns:1fr;height:auto}}

.agent-selector{display:flex;flex-direction:column;gap:8px;overflow-y:auto;padding-right:4px}
.agent-card{border:1px solid;border-radius:12px;padding:16px 18px;cursor:pointer;transition:all .15s;background:rgba(13,20,33,0.6)}
.agent-card:hover{border-color:rgba(255,255,255,0.15);background:rgba(13,20,33,0.9)}
.agent-card.active{box-shadow:0 0 0 1px, 0 4px 20px rgba(0,0,0,0.3)}
.agent-card .card-top{display:flex;justify-content:space-between;align-items:center}
.agent-card .card-name{font-weight:700;font-size:14px;letter-spacing:-0.2px}
.agent-card .card-iter{font-size:11px;font-weight:600;padding:2px 10px;border-radius:8px}
.agent-card .card-status{display:flex;gap:12px;margin-top:6px;font-size:12px;color:#94a3b8}
.agent-card .card-status .stat-ind{display:flex;align-items:center;gap:5px}
.agent-card .card-status .stat-ind::before{content:'';width:6px;height:6px;border-radius:50%}
.agent-card .card-status .stat-ind.active::before{background:#10b981}
.agent-card .card-status .stat-ind.idle::before{background:#475569}

.timeline-panel{display:flex;flex-direction:column;border:1px solid #1e293b;border-radius:12px;overflow:hidden;background:linear-gradient(180deg,#0d1421 0%,#0a0f1a 100%)}
.timeline-header{padding:14px 20px;border-bottom:1px solid #1e293b;display:flex;justify-content:space-between;align-items:center;font-size:14px;font-weight:600;color:#e2e8f0}
.timeline-header .clear-btn{background:transparent;border:1px solid #334155;color:#64748b;padding:5px 14px;border-radius:8px;cursor:pointer;font-size:11px;font-weight:500;transition:all .12s}
.timeline-header .clear-btn:hover{background:#1e293b;color:#e2e8f0}
.timeline-body{flex:1;overflow-y:auto;padding:12px 0}

/* Timeline entries */
.tl-entry{padding:10px 20px;border-left:3px solid;margin:0 16px 8px 16px;position:relative;background:rgba(13,20,33,0.4);border-radius:0 8px 8px 0;transition:background .12s}
.tl-entry:hover{background:rgba(13,20,33,0.8)}
.tl-entry::before{content:'';position:absolute;left:-9px;top:16px;width:14px;height:14px;border-radius:50%;background:inherit;border:3px solid #070b12}
.tl-entry .tl-top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px}
.tl-entry .tl-agent{font-weight:700;font-size:13px}
.tl-entry .tl-time{color:#475569;font-size:11px}
.tl-entry .tl-badge{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;padding:3px 10px;border-radius:6px;letter-spacing:0.3px}
.tl-entry .tl-thought{color:#94a3b8;margin-top:6px;font-size:13px;line-height:1.6}
.tl-entry .tl-thought .collapse{max-height:3.2em;overflow:hidden;cursor:pointer;position:relative}
.tl-entry .tl-thought .collapse::after{content:'... Click to expand';color:#475569;font-size:11px}
.tl-entry .tl-thought .collapse.expanded{max-height:none}
.tl-entry .tl-thought .collapse.expanded::after{content:''}

.tl-entry .cmd-block{background:#070b12;border:1px solid #1e293b;border-radius:8px;margin-top:8px;overflow:hidden;font-family:'SF Mono','Fira Code','Cascadia Code','Consolas',monospace;font-size:12px;line-height:1.5}
.tl-entry .cmd-block .cmd-line{color:#10b981;padding:10px 14px;border-bottom:1px solid #1e293b;word-break:break-all;font-weight:500}
.tl-entry .cmd-block .cmd-output{color:#e2e8f0;padding:10px 14px;max-height:150px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;background:#05080f;font-size:12px}
.tl-entry .cmd-block .cmd-exit{color:#64748b;padding:6px 14px 10px;font-size:11px;border-top:1px solid #111927}

.tl-entry .tl-decision-block{margin-top:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.tl-entry .tl-decision-badge{display:inline-block;font-size:12px;font-weight:700;padding:5px 14px;border-radius:8px;letter-spacing:0.3px}
.tl-entry .tl-reasoning{color:#94a3b8;font-size:12px;line-height:1.5}
.tl-entry .tl-details{color:#475569;font-size:11px;margin-top:4px;font-family:'SF Mono','Fira Code','Consolas',monospace;background:#070b12;padding:8px 12px;border-radius:6px;border:1px solid #111927;max-height:80px;overflow-y:auto}

/* Decision badge colors */
.badge-KILL{background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.25)}
.badge-BLOCK{background:rgba(249,115,22,0.15);color:#f97316;border:1px solid rgba(249,115,22,0.25)}
.badge-ISOLATE{background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.25)}
.badge-ALERT{background:rgba(59,130,246,0.15);color:#3b82f6;border:1px solid rgba(59,130,246,0.25)}
.badge-IGNORE{background:rgba(100,116,139,0.15);color:#64748b;border:1px solid rgba(100,116,139,0.25)}
.badge-ANALYZING{background:rgba(139,92,246,0.15);color:#8b5cf6;border:1px solid rgba(139,92,246,0.25)}
.badge-EXECUTING{background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.25)}
.badge-THINKING{background:rgba(139,92,246,0.15);color:#a78bfa;border:1px solid rgba(139,92,246,0.25)}
.badge-EXEC{background:rgba(16,185,129,0.15);color:#34d399;border:1px solid rgba(16,185,129,0.25)}

/* Scrollbar */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:#070b12}
::-webkit-scrollbar-thumb{background:#1e293b;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#334155}

/* Empty state */
.empty-state{padding:40px 20px;text-align:center;color:#475569;font-size:13px}
.empty-state .empty-icon{font-size:32px;margin-bottom:8px;opacity:0.5}
</style>
</head>
<body>
<div class="header">
<div class="header-left">
<div class="header-logo">A</div>
<div>
<h1>Argus <span>SOC</span></h1>
<div class="sub">AI-Powered Container Security Platform</div>
</div>
</div>
<div class="header-right">
<span class="badge"><span class="dot green" id="statusDot"></span><span id="statusText">Connected</span></span>
<span class="badge" id="esBadge"><span class="dot red"></span>Elasticsearch</span>
</div>
</div>

<div class="tabs">
<div class="tab active" data-tab="security" onclick="switchTab('security')">&#x26A0; Security Events</div>
<div class="tab" data-tab="agents" onclick="switchTab('agents')">&#x1F916; Agent Operations</div>
</div>

<div class="tab-content active" id="tab-security">
<div class="stats-row">
<div class="stat-card"><div class="label">Total Events</div><div class="value blue" id="totalEvents">0</div></div>
<div class="stat-card"><div class="label">Critical</div><div class="value red" id="criticalEvents">0</div></div>
<div class="stat-card"><div class="label">Detections</div><div class="value yellow" id="detectionsCount">0</div></div>
<div class="stat-card"><div class="label">Killed</div><div class="value red" id="killedCount">0</div></div>
<div class="stat-card"><div class="label">Isolated</div><div class="value yellow" id="isolatedCount">0</div></div>
<div class="stat-card"><div class="label">Containers</div><div class="value green" id="containerCount">0</div></div>
</div>
<div class="agent-strip" id="agentStrip"></div>
<div class="main-grid">
<div class="panel">
<div class="panel-header">&#x26A0; Security Events <span class="count" id="eventCount">0</span></div>
<div class="panel-scroll" id="eventList"><div class="empty-state"><div class="empty-icon">&#x1F6E1;</div>Waiting for Falco events...</div></div>
</div>
<div class="panel" style="display:flex;flex-direction:column;gap:0">
<div class="panel" style="border-radius:0;border:none;border-bottom:1px solid #1e293b">
<div class="panel-header">&#x1F6E1; Response Actions <span class="count" id="respCount">0</span></div>
<div class="panel-scroll" id="responseList" style="max-height:220px"><div class="empty-state" style="padding:20px">No responses yet</div></div>
</div>
<div class="panel" style="border-radius:0;border:none">
<div class="panel-header">&#x1F916; Agent Feed <span class="count" id="feedCount">0</span></div>
<div class="panel-scroll" id="feedList" style="max-height:220px"><div class="empty-state" style="padding:20px">Waiting for agent activity...</div></div>
</div>
</div>
</div>
</div>

<div class="tab-content" id="tab-agents">
<div class="agent-layout">
<div class="agent-selector" id="agentSelector"></div>
<div class="timeline-panel">
<div class="timeline-header"><span id="tlTitle">Agent Activity Timeline</span><button class="clear-btn" onclick="clearTimeline()">Clear</button></div>
<div class="timeline-body" id="tlBody"><div class="empty-state"><div class="empty-icon">&#x1F4CB;</div>Agent activity will appear here in real time...<br><span style="font-size:12px;color:#334155">Select an agent on the left to filter</span></div></div>
</div>
</div>
</div>

<script>
const AGENT_COLORS={Orchestrator:'#8b5cf6',Detection:'#ef4444',Response:'#f97316',AttackAgent:'#dc2626',Reporting:'#3b82f6'};
const AGENT_ICONS={Orchestrator:'\u2699',Detection:'\ud83d\udd0d',Response:'\ud83d\udee1',AttackAgent:'\ud83d\udd25',Reporting:'\ud83d\udcca'};
const BADGE_MAP={thinking:'THINKING',executing_command:'EXEC',analysis_complete:'ANALYZED',decision_made:'DECISION',error:'ERROR'};
const BADGE_CLASS={thinking:'badge-THINKING',executing_command:'badge-EXEC',analysis_complete:'badge-ANALYZING',decision_made:'badge-KILL',error:'badge-ALERT'};

let selectedAgent=null;
const ws=new WebSocket('ws://'+location.host+'/ws');

ws.onmessage=function(e){
var d=JSON.parse(e.data);
if(d.type==='event')addEvent(d);
else if(d.type==='response')addResponse(d);
else if(d.type==='agent_log')addFeed(d);
else if(d.type==='stats')updateStats(d);
else if(d.type==='agent_action')addTimeline(d);
};

function switchTab(tab){
document.querySelectorAll('.tab').forEach(function(t){t.classList.toggle('active',t.dataset.tab===tab)});
document.querySelectorAll('.tab-content').forEach(function(t){t.classList.toggle('active',t.id==='tab-'+tab)});
}

function addEvent(d){
var el=document.createElement('div');el.className='event-row';
var sev=(d.priority||'NOTICE').toUpperCase();
el.innerHTML='<div class="event-sev sev-'+sev+'">'+sev+'</div><div class="event-body"><div class="rule">'+(d.rule||'Unknown')+'</div><div class="meta">'+(d.process_name||'')+(d.process_name&&d.container_name?' / ':'')+(d.container_name||'')+'</div></div><div class="event-time">'+new Date().toLocaleTimeString()+'</div>';
var list=document.getElementById('eventList');
var ph=list.querySelector('.empty-state');if(ph)ph.remove();
list.prepend(el);if(list.children.length>200)list.removeChild(list.lastChild);
document.getElementById('eventCount').textContent=list.children.length;
}

function addResponse(d){
var el=document.createElement('div');el.className='response-row';
el.innerHTML='<span class="act '+(d.action||'ALERT')+'">'+(d.action||'ALERT')+'</span><span class="desc">'+(d.container||'')+': '+(d.reasoning||d.reason||'')+'</span>';
var list=document.getElementById('responseList');
var ph=list.querySelector('.empty-state');if(ph)ph.remove();
var first=list.querySelector('.response-row');
if(first)list.insertBefore(el,first);else list.prepend(el);
if(list.children.length>50)list.removeChild(list.lastChild);
document.getElementById('respCount').textContent=list.children.length;
}

function addFeed(d){
var el=document.createElement('div');el.className='feed-row';
var c=AGENT_COLORS[d.agent]||'#888';
el.innerHTML='<div class="feed-hdr"><span class="feed-agent" style="color:'+c+'">'+d.agent+'</span><span>#'+(d.iteration||0)+'</span></div><div class="feed-msg">'+(d.thought||d.message||'')+'</div>';
var list=document.getElementById('feedList');
var ph=list.querySelector('.empty-state');if(ph)ph.remove();
var first=list.querySelector('.feed-row');
if(first)list.insertBefore(el,first);else list.prepend(el);
if(list.children.length>40)list.removeChild(list.lastChild);
document.getElementById('feedCount').textContent=list.children.length;
}

function updateStats(d){
document.getElementById('totalEvents').textContent=d.total_events||0;
document.getElementById('criticalEvents').textContent=d.critical||0;
document.getElementById('detectionsCount').textContent=d.detections||0;
document.getElementById('killedCount').textContent=d.killed||0;
document.getElementById('isolatedCount').textContent=d.isolated||0;
document.getElementById('containerCount').textContent=d.active||0;
document.getElementById('esBadge').innerHTML='<span class="dot '+(d.es_available?'green':'red')+'"></span>Elasticsearch';
if(d.agents)renderAgents(d.agents);
else renderAgents([
{name:'Orchestrator',iterations:0,active:true,description:'Coordinates all operations'},
{name:'Detection',iterations:0,active:true,description:'Analyzes Falco events'},
{name:'Response',iterations:0,active:true,description:'Decides actions'},
{name:'AttackAgent',iterations:0,active:true,description:'Simulates attacks'},
{name:'Reporting',iterations:0,active:true,description:'Generates reports'}
]);
}

function renderAgents(agents){
document.getElementById('agentStrip').innerHTML=agents.map(function(a){
var c=AGENT_COLORS[a.name]||'#64748b';
return '<div class="agent-pill" style="border-color:'+c+'44;background:'+c+'11;color:'+c+'"><span class="pill-dot" style="background:'+(a.active?'#10b981':'#475569')+'"></span>'+a.name+'<span class="pill-iter">#'+a.iterations+'</span></div>';
}).join('');
document.getElementById('agentSelector').innerHTML=agents.map(function(a){
var c=AGENT_COLORS[a.name]||'#64748b';
var active=selectedAgent===a.name;
return '<div class="agent-card'+(active?' active':'')+'" data-agent="'+a.name+'" style="border-color:'+c+'44" onclick="selectAgent(\''+a.name+'\')"><div class="card-top"><span class="card-name" style="color:'+c+'">'+(AGENT_ICONS[a.name]||'')+' '+a.name+'</span><span class="card-iter" style="background:'+c+'18;color:'+c+'">#'+a.iterations+'</span></div><div class="card-status"><span class="stat-ind '+(a.active?'active':'idle')+'">'+(a.active?'Active':'Idle')+'</span><span style="color:#64748b">'+(a.description||'')+'</span></div></div>';
}).join('');
}

function selectAgent(name){
selectedAgent=name;
document.querySelectorAll('.agent-card').forEach(function(c){c.classList.toggle('active',c.dataset.agent===name)});
document.getElementById('tlTitle').textContent=name+' Activity';
}

function clearTimeline(){
document.getElementById('tlBody').innerHTML='<div class="empty-state"><div class="empty-icon">&#x1F4CB;</div>Timeline cleared</div>';
document.getElementById('tlTitle').textContent=selectedAgent?selectedAgent+' Activity':'Agent Activity Timeline';
}

function addTimeline(d){
var badgeText=BADGE_MAP[d.action_type]||(d.action_type||'').toUpperCase();
var badgeClass=BADGE_CLASS[d.action_type]||'badge-IGNORE';
var c=d.color||'#64748b';

var html='<div class="tl-entry" style="border-left-color:'+c+'" data-agent="'+d.agent+'">'+
'<div class="tl-top"><span><span class="tl-agent" style="color:'+c+'">'+(d.icon||'')+' '+d.agent+'</span> <span class="tl-badge '+badgeClass+'">'+badgeText+'</span></span><span class="tl-time">'+new Date(d.timestamp).toLocaleTimeString()+'</span></div>';

if(d.thought){
var t=d.thought;
html+='<div class="tl-thought">'+(t.length>180?'<div class="collapse" onclick="this.classList.toggle(\'expanded\')">'+escHtml(t)+'</div>':escHtml(t))+'</div>';
}

if(d.command){
html+='<div class="cmd-block"><div class="cmd-line">$ '+escHtml(d.command)+'</div>';
if(d.command_output)html+='<div class="cmd-output">'+escHtml(d.command_output)+'</div>';
if(d.exit_code!==undefined)html+='<div class="cmd-exit">Exit code: '+d.exit_code+'</div>';
html+='</div>';
}

if(d.decision){
html+='<div class="tl-decision-block"><span class="tl-decision-badge badge-'+d.decision+'">'+d.decision+'</span>';
if(d.reasoning)html+='<span class="tl-reasoning">'+escHtml(d.reasoning)+'</span>';
html+='</div>';
}

if(d.details){
try{html+='<div class="tl-details">'+escHtml(JSON.stringify(d.details,null,1))+'</div>';}catch(e){}
}

html+='</div>';

var list=document.getElementById('tlBody');
var ph=list.querySelector('.empty-state');if(ph)ph.remove();

if(!selectedAgent||d.agent===selectedAgent){
var temp=document.createElement('div');temp.innerHTML=html;
list.prepend(temp.firstElementChild);
if(list.children.length>300)list.removeChild(list.lastChild);
}
document.getElementById('tlTitle').textContent=selectedAgent?selectedAgent+' Activity':'Agent Activity Timeline';
}

function escHtml(s){
if(!s)return'';
return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

ws.onclose=function(){document.getElementById('statusDot').className='dot red';document.getElementById('statusText').textContent='Disconnected';};
ws.onerror=function(){document.getElementById('statusDot').className='dot red';document.getElementById('statusText').textContent='Error';};
</script>
</body>
</html>"""


class SOCDashboard:
    def __init__(self, soc):
        self.soc = soc
        self.clients = set()

    async def handle_root(self, request):
        return web.Response(text=HTML, content_type="text/html")

    async def handle_ws(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.clients.add(ws)
        logger.info(f"Dash client connected ({len(self.clients)} total)")
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.ERROR:
                    break
        finally:
            self.clients.discard(ws)
        return ws

    async def broadcast(self, message):
        msg = json.dumps(message, default=str)
        dead = set()
        for ws in self.clients:
            try:
                await ws.send_str(msg)
            except Exception:
                dead.add(ws)
        self.clients -= dead

    async def broadcast_event(self, event, detection, response):
        await self.broadcast({
            "type": "event",
            "rule": event.get("rule", "unknown"),
            "priority": event.get("priority", "NOTICE"),
            "process_name": event.get("process_name", ""),
            "container_name": event.get("container_name", ""),
            "time": event.get("time", ""),
        })
        await self.broadcast({
            "type": "response",
            "action": response.get("action", "ALERT"),
            "container": event.get("container_name", ""),
            "reasoning": response.get("reasoning", ""),
        })
        await self.broadcast({
            "type": "agent_log",
            "agent": "Detection",
            "iteration": detection.get("iteration", 0),
            "thought": detection.get("thought", detection.get("explanation", "")),
            "message": f"{detection.get('attack_type', 'unknown')} ({detection.get('mitre_id', '')})",
        })

    async def broadcast_report(self, report):
        await self.broadcast({
            "type": "agent_log",
            "agent": "Reporting",
            "iteration": 0,
            "thought": report.get("thought", ""),
            "message": report.get("summary", "")[:200],
        })

    async def broadcast_stats(self):
        detections = len(self.soc.detections)
        killed = sum(1 for r in self.soc.responses if r.get("action") == "KILL")
        isolated = sum(1 for r in self.soc.responses if r.get("action") == "ISOLATE")
        critical = sum(1 for e in self.soc.events if e.get("priority") == "CRITICAL")
        active = len(self.soc.docker.list_containers()) if self.soc.docker else 0
        es_avail = self.soc.elastic.available if self.soc.elastic else False

        await self.broadcast({
            "type": "stats",
            "total_events": len(self.soc.events),
            "critical": critical,
            "detections": detections,
            "killed": killed,
            "isolated": isolated,
            "active": active,
            "es_available": es_avail,
            "agents": [
                {"name": "Orchestrator", "iterations": self.soc.orchestrator.iteration, "active": True, "description": self.soc.orchestrator.description},
                {"name": "Detection", "iterations": self.soc.detection.iteration, "active": True, "description": self.soc.detection.description},
                {"name": "Response", "iterations": self.soc.response_agent.iteration, "active": True, "description": self.soc.response_agent.description},
                {"name": "AttackAgent", "iterations": self.soc.attack.iteration, "active": True, "description": self.soc.attack.description},
                {"name": "Reporting", "iterations": self.soc.reporting.iteration, "active": True, "description": self.soc.reporting.description},
            ],
        })

    async def start(self):
        app = web.Application()
        app.router.add_get("/", self.handle_root)
        app.router.add_get("/ws", self.handle_ws)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, settings.DASHBOARD_HOST, settings.DASHBOARD_PORT)
        await site.start()
        logger.info(f"  Dashboard: http://{settings.DASHBOARD_HOST}:{settings.DASHBOARD_PORT}")
