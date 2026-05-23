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
body{font-family:'Segoe UI',system-ui,sans-serif;background:#05080f;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#0a0e17 0%,#111b24 100%);border-bottom:1px solid #1a2a3a;padding:16px 24px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:20px;font-weight:700;color:#00d4aa}
.header h1 span{color:#ff4757}
.header .subtitle{font-size:11px;color:#4a5a6a;letter-spacing:2px;text-transform:uppercase}
.badge{display:flex;align-items:center;gap:8px;background:#111b24;padding:6px 14px;border-radius:16px;font-size:12px;border:1px solid #1a2a3a}
.badge .dot{width:8px;height:8px;border-radius:50%}
.dot.green{background:#00d4aa;box-shadow:0 0 6px #00d4aa66}.dot.red{background:#ff4757;box-shadow:0 0 6px #ff475766}
.agent-bar{display:flex;gap:6px;padding:12px 24px;background:#0a0e17;border-bottom:1px solid #111b24;overflow-x:auto}
.agent-pill{display:flex;align-items:center;gap:6px;background:#111b24;border:1px solid #1a2a3a;padding:6px 12px;border-radius:20px;font-size:11px;white-space:nowrap}
.agent-pill .status{width:6px;height:6px;border-radius:50%}
.agent-pill .name{color:#6b7b8d}.agent-pill .iter{color:#00d4aa;font-weight:600}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;padding:16px 24px}
.stat{background:linear-gradient(135deg,#0f1520 0%,#0a0e17 100%);border:1px solid #16212e;border-radius:10px;padding:14px}
.stat .lbl{font-size:10px;text-transform:uppercase;color:#4a5a6a;letter-spacing:1px}
.stat .val{font-size:28px;font-weight:700;margin-top:4px}
.stat .val.green{color:#00d4aa}.stat .val.red{color:#ff4757}.stat .val.yellow{color:#ffc312}.stat .val.blue{color:#3498db}
.main-grid{display:grid;grid-template-columns:1fr 340px;gap:16px;padding:0 24px 24px}
@media(max-width:900px){.main-grid{grid-template-columns:1fr}}
.panel{background:linear-gradient(135deg,#0f1520 0%,#0a0e17 100%);border:1px solid #16212e;border-radius:10px;overflow:hidden}
.panel-hdr{padding:12px 16px;border-bottom:1px solid #16212e;display:flex;justify-content:space-between;align-items:center;font-size:13px;font-weight:600}
.panel-hdr .count{background:#16212e;padding:1px 8px;border-radius:8px;font-size:11px;font-weight:400}
.scroll{max-height:500px;overflow-y:auto}
.event{padding:8px 16px;border-bottom:1px solid #0f1520;font-size:12px;display:flex;gap:8px;align-items:start;transition:background .15s}
.event:hover{background:#111b24}
.event .sev{font-size:9px;text-transform:uppercase;font-weight:700;padding:2px 6px;border-radius:3px;min-width:48px;text-align:center}
.sev.CRITICAL{background:#ff475722;color:#ff4757;border:1px solid #ff475744}
.sev.HIGH{background:#ff634822;color:#ff6348;border:1px solid #ff634844}
.sev.MEDIUM{background:#ffc31222;color:#ffc312;border:1px solid #ffc31244}
.sev.LOW{background:#3498db22;color:#3498db;border:1px solid #3498db44}
.event .info{flex:1;min-width:0}
.event .info .rule{font-weight:600;font-size:12px}
.event .info .detail{color:#4a5a6a;font-size:11px;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.event .time{color:#2a3a4a;font-size:10px;white-space:nowrap}
.action{font-size:11px;padding:6px 12px;border-bottom:1px solid #0f1520;display:flex;gap:6px}
.action .act{font-weight:700;font-size:10px}
.action .act.KILL{color:#ff4757}.action .act.BLOCK{color:#ff6348}.action .act.ISOLATE{color:#ffc312}.action .act.ALERT{color:#3498db}
.action .desc{color:#4a5a6a}
.agent-log{font-size:11px;padding:6px 12px;border-bottom:1px solid #0f1520}
.agent-log .hdr{display:flex;justify-content:space-between;color:#4a5a6a}
.agent-log .msg{color:#6b7b8d;margin-top:2px;font-size:10px}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#05080f}::-webkit-scrollbar-thumb{background:#1a2a3a;border-radius:2px}
</style>
</head>
<body>
<div class="header">
<div><h1>Falco<span>Shield</span> SOC</h1><div class="subtitle">AI-Powered Container Security</div></div>
<div style="display:flex;gap:10px;align-items:center">
<span class="badge"><span class="dot green" id="statusDot"></span><span id="statusText" style="font-size:11px">Connected</span></span>
<span class="badge" id="esBadge"><span class="dot red"></span>ES</span>
</div>
</div>
<div class="agent-bar" id="agentBar"></div>
<div class="stats-grid" id="statsGrid">
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
<div class="panel" style="border-radius:0;border:none;border-bottom:1px solid #16212e"><div class="panel-hdr">&#x1F6E1; Responses <span class="count" id="respCount">0</span></div><div class="scroll" id="responses" style="max-height:180px"></div></div>
<div class="panel" style="border-radius:0;border:none"><div class="panel-hdr">&#x1F916; Agent Thoughts <span class="count" id="agentLogCount">0</span></div><div class="scroll" id="agentLogs" style="max-height:180px"></div></div>
</div>
</div>
<script>
const ws=new WebSocket('ws://'+location.host+'/ws');
ws.onmessage=e=>{
const d=JSON.parse(e.data);
if(d.type==='event') addEvent(d);
if(d.type==='response') addResponse(d);
if(d.type==='agent_log') addAgentLog(d);
if(d.type==='stats') updateStats(d);
if(d.type==='agents') updateAgents(d);
};
function addEvent(d){
const el=document.createElement('div');el.className='event';
el.innerHTML='<div class="sev '+d.priority+'">'+d.priority+'</div><div class="info"><div class="rule">'+(d.rule||'Unknown')+'</div><div class="detail">'+(d.process_name||'')+' / '+(d.container_name||'')+'</div></div><div class="time">'+new Date().toLocaleTimeString()+'</div>';
const list=document.getElementById('events');
list.prepend(el);
if(list.children.length>200)list.removeChild(list.lastChild);
document.getElementById('eventCount').textContent=list.children.length;
}
function addResponse(d){
const el=document.createElement('div');el.className='action';
el.innerHTML='<span class="act '+d.action+'">'+d.action+'</span><span class="desc">'+d.container+': '+(d.reasoning||d.reason||'')+'</span>';
const list=document.getElementById('responses');
const first=list.querySelector('.action');
if(first)list.insertBefore(el,first);else list.prepend(el);
if(list.children.length>50)list.removeChild(list.lastChild);
document.getElementById('respCount').textContent=list.children.length;
}
function addAgentLog(d){
const el=document.createElement('div');el.className='agent-log';
el.innerHTML='<div class="hdr"><span>'+d.agent+'</span><span>#'+d.iteration+'</span></div><div class="msg">'+(d.thought||d.message||'')+'</div>';
const list=document.getElementById('agentLogs');
const first=list.querySelector('.agent-log');
if(first)list.insertBefore(el,first);else list.prepend(el);
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
}
function updateAgents(d){
document.getElementById('agentBar').innerHTML=d.agents.map(a=>
'<div class="agent-pill"><span class="status '+(a.active?'green':'red')+'"></span><span class="name">'+a.name+'</span><span class="iter">#'+a.iterations+'</span></div>'
).join('');
}
ws.onclose=()=>{document.getElementById('statusDot').className='dot red';document.getElementById('statusText').textContent='Disconnected';};
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
        logger.info(f"Dashboard client connected ({len(self.clients)} total)")
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
        d = {
            "type": "event",
            "rule": event.get("rule", "unknown"),
            "priority": event.get("priority", "NOTICE"),
            "process_name": event.get("process_name", ""),
            "container_name": event.get("container_name", ""),
            "time": event.get("time", ""),
        }
        await self.broadcast(d)

        rd = {
            "type": "response",
            "action": response.get("action", "ALERT"),
            "container": event.get("container_name", ""),
            "reasoning": response.get("reasoning", ""),
        }
        await self.broadcast(rd)

        agent_thought = {
            "type": "agent_log",
            "agent": "Detection",
            "iteration": detection.get("iteration", 0),
            "thought": detection.get("thought", detection.get("explanation", "")),
            "message": f"{detection.get('attack_type', 'unknown')} ({detection.get('mitre_id', '')})",
        }
        await self.broadcast(agent_thought)

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
        blocked = sum(1 for r in self.soc.responses if r.get("action") == "BLOCK")
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
        })

        agents_data = {
            "type": "agents",
            "agents": [
                {"name": "Orchestrator", "iterations": self.soc.orchestrator.iteration, "active": True},
                {"name": "Detection", "iterations": self.soc.detection.iteration, "active": True},
                {"name": "Response", "iterations": self.soc.response_agent.iteration, "active": True},
                {"name": "Attack", "iterations": self.soc.attack.iteration, "active": True},
                {"name": "Reporting", "iterations": self.soc.reporting.iteration, "active": True},
            ],
        }
        await self.broadcast(agents_data)

    async def start(self):
        app = web.Application()
        app.router.add_get("/", self.handle_root)
        app.router.add_get("/ws", self.handle_ws)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, settings.DASHBOARD_HOST, settings.DASHBOARD_PORT)
        await site.start()
        logger.info(f"  Dashboard: http://{settings.DASHBOARD_HOST}:{settings.DASHBOARD_PORT}")
