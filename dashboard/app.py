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
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#05080f;color:#e0e0e0;min-height:100vh;overflow-x:hidden}
.header{background:linear-gradient(135deg,#0a0e17 0%,#111b24 100%);border-bottom:1px solid #1a2a3a;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:18px;font-weight:700;color:#00d4aa;letter-spacing:0.5px}
.header h1 span{color:#ff4757}
.header .sub{font-size:10px;color:#4a5a6a;letter-spacing:2px;text-transform:uppercase;margin-top:1px}
.badge{display:flex;align-items:center;gap:6px;background:#111b24;padding:5px 12px;border-radius:14px;font-size:11px;border:1px solid #1a2a3a}
.badge .dot{width:7px;height:7px;border-radius:50%}
.dot.green{background:#00d4aa;box-shadow:0 0 5px #00d4aa55}.dot.red{background:#ff4757;box-shadow:0 0 5px #ff475755}

.tabs{display:flex;background:#0a0e17;border-bottom:1px solid #1a2a3a;padding:0 24px;gap:0}
.tab{padding:10px 20px;font-size:12px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;color:#4a5a6a;transition:all .15s;user-select:none}
.tab:hover{color:#e0e0e0;background:#111b24}
.tab.active{color:#00d4aa;border-bottom-color:#00d4aa}
.tab-content{display:none}
.tab-content.active{display:block}

/* Stats */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;padding:12px 24px}
.stat{border:1px solid #16212e;border-radius:8px;padding:12px}
.stat .lbl{font-size:9px;text-transform:uppercase;color:#4a5a6a;letter-spacing:1px}
.stat .val{font-size:24px;font-weight:700;margin-top:3px}
.stat .val.green{color:#00d4aa}.stat .val.red{color:#ff4757}.stat .val.yellow{color:#ffc312}.stat .val.blue{color:#3498db}.stat .val.purple{color:#8b5cf6}

/* Agent bar */
.agent-bar{display:flex;gap:5px;padding:8px 24px;overflow-x:auto;flex-wrap:wrap}
.agent-pill{display:flex;align-items:center;gap:5px;padding:4px 10px;border-radius:14px;font-size:10px;white-space:nowrap;border:1px solid;font-weight:600}
.agent-pill .iter{opacity:0.7}

/* Main grid (Security tab) */
.main-grid{display:grid;grid-template-columns:1fr 320px;gap:12px;padding:0 24px 24px}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}}
.panel{border:1px solid #16212e;border-radius:8px;overflow:hidden}
.panel-hdr{padding:10px 14px;border-bottom:1px solid #16212e;display:flex;justify-content:space-between;align-items:center;font-size:12px;font-weight:600}
.panel-hdr .count{background:#16212e;padding:1px 7px;border-radius:7px;font-size:10px;font-weight:400}
.scroll{max-height:480px;overflow-y:auto}
.event{padding:7px 14px;border-bottom:1px solid #0f1520;font-size:11px;display:flex;gap:7px;align-items:start;transition:background .12s}
.event:hover{background:#111b24}
.event .sev{font-size:8px;text-transform:uppercase;font-weight:700;padding:2px 5px;border-radius:3px;min-width:44px;text-align:center}
.sev.CRITICAL{background:#ff475722;color:#ff4757;border:1px solid #ff475744}
.sev.HIGH{background:#ff634822;color:#ff6348;border:1px solid #ff634844}
.sev.MEDIUM{background:#ffc31222;color:#ffc312;border:1px solid #ffc31244}
.sev.LOW{background:#3498db22;color:#3498db;border:1px solid #3498db44}
.event .info{flex:1;min-width:0}
.event .info .rule{font-weight:600;font-size:11px}
.event .info .detail{color:#4a5a6a;font-size:10px;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.event .time{color:#2a3a4a;font-size:9px;white-space:nowrap}
.action{font-size:10px;padding:5px 10px;border-bottom:1px solid #0f1520;display:flex;gap:5px}
.action .act{font-weight:700;font-size:9px}
.action .act.KILL{color:#ff4757}.action .act.BLOCK{color:#ff6348}.action .act.ISOLATE{color:#ffc312}.action .act.ALERT{color:#3498db}
.action .desc{color:#4a5a6a}
.agent-log{font-size:10px;padding:5px 10px;border-bottom:1px solid #0f1520}
.agent-log .hdr{display:flex;justify-content:space-between;color:#4a5a6a}
.agent-log .msg{color:#6b7b8d;margin-top:1px;font-size:9px}

/* Agent Operations tab */
.agent-ops-grid{display:grid;grid-template-columns:280px 1fr;gap:12px;padding:12px 24px 24px;height:calc(100vh - 180px)}
@media(max-width:1000px){.agent-ops-grid{grid-template-columns:1fr}}
.agent-list{display:flex;flex-direction:column;gap:6px}
.agent-card{border:1px solid;border-radius:8px;padding:10px 12px;cursor:pointer;transition:all .12s;font-size:11px}
.agent-card:hover{filter:brightness(1.3)}
.agent-card.active{box-shadow:0 0 12px rgba(255,255,255,0.08)}
.agent-card .top{display:flex;justify-content:space-between;align-items:center}
.agent-card .name{font-weight:700;font-size:12px}
.agent-card .iter-badge{font-size:9px;padding:1px 6px;border-radius:6px;opacity:0.8}
.agent-card .status-line{display:flex;gap:8px;margin-top:4px;color:#4a5a6a;font-size:9px}
.agent-card .desc{font-size:9px;color:#4a5a6a;margin-top:2px}

.agent-timeline{border:1px solid #16212e;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.timeline-hdr{padding:10px 14px;border-bottom:1px solid #16212e;font-size:12px;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.timeline-hdr .clear-btn{background:transparent;border:1px solid #2a3a4a;color:#6b7b8d;padding:3px 10px;border-radius:5px;cursor:pointer;font-size:10px}
.timeline-hdr .clear-btn:hover{background:#1a2a3a;color:#e0e0e0}
.timeline-scroll{flex:1;overflow-y:auto;padding:8px 0}
.tl-item{padding:6px 14px;border-left:2px solid;margin:0 12px 4px 12px;position:relative;font-size:11px}
.tl-item::before{content:'';position:absolute;left:-5px;top:10px;width:8px;height:8px;border-radius:50%;background:inherit;border:2px solid #05080f}
.tl-item .tl-hdr{display:flex;justify-content:space-between;align-items:center}
.tl-item .tl-agent{font-weight:700;font-size:10px}
.tl-item .tl-time{color:#4a5a6a;font-size:9px}
.tl-item .tl-action{display:inline-block;font-size:8px;padding:1px 5px;border-radius:3px;margin-left:4px;text-transform:uppercase;font-weight:700}
.tl-item .tl-thought{color:#6b7b8d;margin-top:3px;font-size:10px;line-height:1.4}
.tl-item .tl-thought .collapse{max-height:60px;overflow:hidden;cursor:pointer}
.tl-item .tl-thought .collapse.expanded{max-height:none}
.tl-item .tl-command{background:#0a0e17;border:1px solid #16212e;border-radius:4px;margin-top:4px;font-family:'Cascadia Code','Fira Code','Consolas',monospace;font-size:10px;overflow:hidden}
.tl-item .tl-command .cmd-line{color:#00d4aa;padding:5px 8px;border-bottom:1px solid #16212e;word-break:break-all}
.tl-item .tl-command .cmd-output{color:#e0e0e0;padding:5px 8px;max-height:100px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;background:#05080f}
.tl-item .tl-command .cmd-exit{color:#4a5a6a;padding:3px 8px 5px;font-size:9px}
.tl-item .tl-decision{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;margin-top:3px}
.kill-badge{background:#ff475722;color:#ff4757;border:1px solid #ff475744}
.block-badge{background:#ff634822;color:#ff6348;border:1px solid #ff634844}
.isolate-badge{background:#ffc31222;color:#ffc312;border:1px solid #ffc31244}
.alert-badge{background:#3498db22;color:#3498db;border:1px solid #3498db44}
.thinking-badge{background:#8b5cf622;color:#8b5cf6;border:1px solid #8b5cf644}
.exec-badge{background:#00d4aa22;color:#00d4aa;border:1px solid #00d4aa44}

::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#05080f}::-webkit-scrollbar-thumb{background:#1a2a3a;border-radius:2px}
</style>
</head>
<body>
<div class="header">
<div><h1>Argus <span>SOC</span></h1><div class="sub">AI-Powered Container Security</div></div>
<div style="display:flex;gap:8px;align-items:center">
<span class="badge"><span class="dot green" id="statusDot"></span><span id="statusText" style="font-size:10px">Connected</span></span>
<span class="badge" id="esBadge"><span class="dot red"></span>ES</span>
</div>
</div>

<div class="tabs">
<div class="tab active" data-tab="security" onclick="switchTab('security')">&#x26A0; Security Events</div>
<div class="tab" data-tab="agents" onclick="switchTab('agents')">&#x1F916; Agent Operations</div>
</div>

<div class="tab-content active" id="tab-security">
<div class="agent-bar" id="agentBar"></div>
<div class="stats-grid">
<div class="stat"><div class="lbl">Events</div><div class="val blue" id="totalEvents">0</div></div>
<div class="stat"><div class="lbl">Critical</div><div class="val red" id="criticalEvents">0</div></div>
<div class="stat"><div class="lbl">Detections</div><div class="val yellow" id="detectionsCount">0</div></div>
<div class="stat"><div class="lbl">Killed</div><div class="val red" id="killedCount">0</div></div>
<div class="stat"><div class="lbl">Isolated</div><div class="val yellow" id="isolatedCount">0</div></div>
<div class="stat"><div class="lbl">Containers</div><div class="val green" id="containerCount">0</div></div>
</div>
<div class="main-grid">
<div class="panel"><div class="panel-hdr">&#x26A0; Security Events <span class="count" id="eventCount">0</span></div><div class="scroll" id="events"></div></div>
<div class="panel" style="display:flex;flex-direction:column;gap:0">
<div class="panel" style="border-radius:0;border:none;border-bottom:1px solid #16212e"><div class="panel-hdr">&#x1F6E1; Responses <span class="count" id="respCount">0</span></div><div class="scroll" id="responses" style="max-height:160px"></div></div>
<div class="panel" style="border-radius:0;border:none"><div class="panel-hdr">&#x1F916; Agent Feed <span class="count" id="agentLogCount">0</span></div><div class="scroll" id="agentLogs" style="max-height:160px"></div></div>
</div>
</div>
</div>

<div class="tab-content" id="tab-agents">
<div class="agent-ops-grid">
<div class="agent-list" id="agentList"></div>
<div class="agent-timeline">
<div class="timeline-hdr"><span id="tlAgentLabel">Agent Activity Timeline</span><button class="clear-btn" onclick="document.getElementById('tlList').innerHTML=''">Clear</button></div>
<div class="timeline-scroll" id="tlList"><div style="color:#4a5a6a;font-size:12px;padding:20px;text-align:center">Waiting for agent activity...</div></div>
</div>
</div>
</div>

<script>
const AGENT_COLORS={Orchestrator:'#8b5cf6',Detection:'#ef4444',Response:'#f97316',AttackAgent:'#dc2626',Reporting:'#3b82f6'};
const AGENT_ICONS={Orchestrator:'\u2699',Detection:'\ud83d\udd0d',Response:'\ud83d\udee1',AttackAgent:'\ud83d\udd25',Reporting:'\ud83d\udcca'};
const ACTION_LABELS={thinking:{text:'THINKING',cls:'thinking-badge'},executing_command:{text:'EXEC',cls:'exec-badge'},analysis_complete:{text:'ANALYZED',cls:'thinking-badge'},decision_made:{text:'DECISION',cls:'kill-badge'},error:{text:'ERROR',cls:'alert-badge'}};

let selectedAgent=null;
const ws=new WebSocket('ws://'+location.host+'/ws');
ws.onmessage=e=>{
const d=JSON.parse(e.data);
if(d.type==='event')addEvent(d);
if(d.type==='response')addResponse(d);
if(d.type==='agent_log')addAgentLog(d);
if(d.type==='stats')updateStats(d);
if(d.type==='agents')updateAgents(d);
if(d.type==='agent_action')addAgentAction(d);
};

function switchTab(tab){
document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active',t.dataset.tab===tab));
document.querySelectorAll('.tab-content').forEach(t=>t.classList.toggle('active',t.id==='tab-'+tab));
}

function addEvent(d){
const el=document.createElement('div');el.className='event';
el.innerHTML='<div class="sev '+d.priority+'">'+d.priority+'</div><div class="info"><div class="rule">'+(d.rule||'Unknown')+'</div><div class="detail">'+(d.process_name||'')+' / '+(d.container_name||'')+'</div></div><div class="time">'+new Date().toLocaleTimeString()+'</div>';
const list=document.getElementById('events');
list.prepend(el);if(list.children.length>200)list.removeChild(list.lastChild);
document.getElementById('eventCount').textContent=list.children.length;
}
function addResponse(d){
const el=document.createElement('div');el.className='action';
el.innerHTML='<span class="act '+d.action+'">'+d.action+'</span><span class="desc">'+d.container+': '+(d.reasoning||d.reason||'')+'</span>';
const list=document.getElementById('responses');
const first=list.querySelector('.action');if(first)list.insertBefore(el,first);else list.prepend(el);
if(list.children.length>50)list.removeChild(list.lastChild);
document.getElementById('respCount').textContent=list.children.length;
}
function addAgentLog(d){
const el=document.createElement('div');el.className='agent-log';
el.innerHTML='<div class="hdr"><span style="color:'+(AGENT_COLORS[d.agent]||'#888')+'">'+d.agent+'</span><span>#'+d.iteration+'</span></div><div class="msg">'+(d.thought||d.message||'')+'</div>';
const list=document.getElementById('agentLogs');
const first=list.querySelector('.agent-log');if(first)list.insertBefore(el,first);else list.prepend(el);
if(list.children.length>30)list.removeChild(list.lastChild);
document.getElementById('agentLogCount').textContent=list.children.length;
}
function updateStats(d){
document.getElementById('totalEvents').textContent=d.total_events||0;
document.getElementById('criticalEvents').textContent=d.critical||0;
document.getElementById('detectionsCount').textContent=d.detections||0;
document.getElementById('killedCount').textContent=d.killed||0;
document.getElementById('isolatedCount').textContent=d.isolated||0;
document.getElementById('containerCount').textContent=d.active||0;
document.getElementById('esBadge').innerHTML='<span class="dot '+(d.es_available?'green':'red')+'"></span>ES';
if(d.agents)updateAgents(d);
else updateAgents({agents:[
{name:'Orchestrator',iterations:0,active:true,description:''},
{name:'Detection',iterations:0,active:true,description:''},
{name:'Response',iterations:0,active:true,description:''},
{name:'AttackAgent',iterations:0,active:true,description:''},
{name:'Reporting',iterations:0,active:true,description:''}
]});
}
function updateAgents(d){
const agents=d.agents||[];
document.getElementById('agentBar').innerHTML=agents.map(a=>
'<div class="agent-pill" style="border-color:'+(AGENT_COLORS[a.name]||'#444')+'55;background:'+(AGENT_COLORS[a.name]||'#444')+'11;color:'+(AGENT_COLORS[a.name]||'#888')+'"><span class="status dot '+(a.active?'green':'red')+'"></span><span>'+a.name+'</span><span class="iter">#'+a.iterations+'</span></div>'
).join('');
document.getElementById('agentList').innerHTML=agents.map(a=>{
const c=AGENT_COLORS[a.name]||'#888';
const active=selectedAgent===a.name;
return '<div class="agent-card '+(active?'active':'')+'" data-agent="'+a.name+'" style="border-color:'+c+'55;background:'+c+'11" onclick="selectAgent(\''+a.name+'\')"><div class="top"><span class="name" style="color:'+c+'">'+(AGENT_ICONS[a.name]||'')+' '+a.name+'</span><span class="iter-badge" style="background:'+c+'22;color:'+c+'">#'+a.iterations+'</span></div><div class="status-line"><span>'+(a.active?'ACTIVE':'IDLE')+'</span><span>'+(a.description||'')+'</span></div></div>'
}).join('');
}
function selectAgent(name){
selectedAgent=name;
document.querySelectorAll('.agent-card').forEach(c=>{
c.classList.toggle('active',c.dataset.agent===name);
});
document.getElementById('tlAgentLabel').textContent=name+' Activity';
}

function addAgentAction(d){
const al=ACTION_LABELS[d.action_type]||{text:d.action_type,cls:''};
const c=d.color||'#888';
const html='<div class="tl-item" style="border-left-color:'+c+'" data-agent="'+d.agent+'"><div class="tl-hdr"><span><span class="tl-agent" style="color:'+c+'">'+(d.icon||'')+' '+d.agent+'</span><span class="tl-action '+al.cls+'">'+al.text+'</span></span><span class="tl-time">'+new Date(d.timestamp).toLocaleTimeString()+'</span></div>'+
(d.thought?'<div class="tl-thought">'+(d.thought.length>200?'<div class="collapse" onclick="this.classList.toggle(\'expanded\')">'+d.thought+'</div>':d.thought)+'</div>':'')+
(d.command?'<div class="tl-command"><div class="cmd-line">$ '+(d.command||'')+'</div>'+(d.command_output?'<div class="cmd-output">'+(d.command_output||'')+'</div>':'')+(d.exit_code!==undefined?'<div class="cmd-exit">Exit code: '+d.exit_code+'</div>':'')+'</div>':'')+
(d.decision?'<div><span class="tl-decision kill-badge">'+(d.decision||'')+'</span>'+(d.reasoning?' <span style="color:#6b7b8d;font-size:10px">'+d.reasoning+'</span>':'')+'</div>':'')+
(d.details?'<div style="margin-top:3px;font-size:9px;color:#4a5a6a">'+JSON.stringify(d.details).substring(0,300)+'</div>':'')+
'</div>';

const list=document.getElementById('tlList');
const placeholder=list.querySelector('div[style*="text-align"]');
if(placeholder)placeholder.remove();

if(!selectedAgent||d.agent===selectedAgent){
const temp=document.createElement('div');
temp.innerHTML=html;
list.prepend(temp.firstElementChild);
if(list.children.length>200)list.removeChild(list.lastChild);
}
document.getElementById('tlAgentLabel').textContent=selectedAgent?selectedAgent+' Activity':'Agent Activity Timeline';
}
ws.onclose=()=>{document.getElementById('statusDot').className='dot red';document.getElementById('statusText').textContent='DC';};
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
