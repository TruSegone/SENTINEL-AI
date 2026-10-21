import { useEffect, useMemo, useState } from 'react';
import { Activity, AlertTriangle, Shield, Radio, GitBranch, Play, CheckCircle, RefreshCw, Search, ChevronRight, Clock3, Server, BrainCircuit, Pause, Square, ExternalLink, Filter } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
const API = '';
type Any = Record<string, any>;
type Tab = 'Overview' | 'Events' | 'Incidents' | 'Investigation' | 'Replay Lab' | 'Response' | 'Detection Health' | 'Observability';
type IconComponent = typeof Activity;

const tabs: Array<[Tab, IconComponent]> = [
    ['Overview', Activity],
    ['Events', Radio],
    ['Incidents', AlertTriangle],
    ['Investigation', GitBranch],
    ['Replay Lab', Play],
    ['Response', Shield],
    ['Detection Health', BrainCircuit],
    ['Observability', Server],
];

// Keep request headers and API errors consistent across analyst actions.
async function request(path: string, options: RequestInit = {}) {
    const response = await fetch(API + path, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'X-Analyst-Token': localStorage.getItem('sentinelToken') || 'demo-analyst',
            'X-Analyst-Role': localStorage.getItem('sentinelRole') || 'admin',
            ...(options.headers || {}),
        },
    });

    if (!response.ok) {
        let message = `Request failed (${response.status})`;
        try {
            const errorResponse = await response.json();
            message = errorResponse.detail?.message || message;
        } catch {
            // Keep the HTTP status if the server did not return a JSON error body.
        }
        throw new Error(message);
    }

    return response.json();
}

const dt = (value: string) => (value ? new Date(value).toLocaleString() : '');
const sev = (severity: string) => (
    <span className={`pill ${severity || 'low'}`}>{severity || 'low'}</span>
);

export default function App() {
    // Polling refreshes each view; SSE adds prompt updates and polling recovers after reconnects.
    const [tab, setTab] = useState<Tab>('Overview');
    const [overview, setOverview] = useState<Any>();
    const [events, setEvents] = useState<Any[]>([]);
    const [incidents, setIncidents] = useState<Any[]>([]);
    const [findings, setFindings] = useState<Any[]>([]);
    const [rules, setRules] = useState<Any[]>([]);
    const [actions, setActions] = useState<Any[]>([]);
    const [scenarios, setScenarios] = useState<Any[]>([]);
    const [model, setModel] = useState<Any>();
    const [selected, setSelected] = useState<Any>();
    const [detail, setDetail] = useState<Any>();
    const [replay, setReplay] = useState<Any>();
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [paused, setPaused] = useState(false);
    const [search, setSearch] = useState('');
    const [connected, setConnected] = useState(false);

    async function load() {
        try {
            setError('');
            const [overviewData, eventData, incidentData, findingData, ruleData, actionData, scenarioData, modelData] =
                await Promise.all([
                    request('/api/v1/overview'),
                    request('/api/v1/events?limit=60'),
                    request('/api/v1/incidents?limit=60'),
                    request('/api/v1/findings?limit=60'),
                    request('/api/v1/rules'),
                    request('/api/v1/response-actions'),
                    request('/api/v1/scenarios'),
                    request('/api/v1/models/status'),
                ]);

            setOverview(overviewData);
            setEvents(eventData.items);
            setIncidents(incidentData.items);
            setFindings(findingData.items);
            setRules(ruleData.items);
            setActions(actionData.items);
            setScenarios(scenarioData.items);
            setModel(modelData);
            setConnected(true);
        } catch (loadError: any) {
            setConnected(false);
            setError(loadError.message);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        load();
        const interval = setInterval(() => {
            if (!paused) load();
        }, 5000);
        return () => clearInterval(interval);
    }, [paused]);

    // EventSource can redeliver after reconnect; stable IDs keep the event table deduplicated.
    useEffect(() => {
        const eventStream = new EventSource('/api/v1/stream/events');
        eventStream.onopen = () => setConnected(true);
        eventStream.onmessage = (message) => {
            try {
                const event = JSON.parse(message.data);
                setEvents((current) =>
                    [event, ...current.filter((item) => item.event_id !== event.event_id)].slice(0, 60),
                );
            } catch {
                // Ignore malformed stream data; the next poll refreshes the current view.
            }
        };
        eventStream.onerror = () => setConnected(false);
        return () => eventStream.close();
    }, []);

    async function act(path: string, method = 'POST', body?: Any) {
        try {
            await request(path, {
                method,
                body: body ? JSON.stringify(body) : undefined,
            });
            await load();
        } catch (actionError: any) {
            setError(actionError.message);
        }
    }

    async function inspect(incident: Any) {
        setSelected(incident);
        try {
            setDetail(await request(`/api/v1/incidents/${incident.incident_id}`));
            setTab('Investigation');
        } catch (detailError: any) {
            setError(detailError.message);
        }
    }

    async function investigate() {
        if (!selected) return;
        try {
            const result = await request(
                `/api/v1/incidents/${selected.incident_id}/investigate`,
                { method: 'POST' },
            );
            setDetail({ ...detail, investigation: result });
        } catch (investigationError: any) {
            setError(investigationError.message);
        }
    }

    const filtered = useMemo(
        () => events.filter((event) => JSON.stringify(event).toLowerCase().includes(search.toLowerCase())),
        [events, search],
    );
    const chart = overview?.detections?.length
        ? overview.detections
        : [{ name: 'No detections yet', count: 0 }];
    return <div className="shell"><aside className="sidebar"><div className="brand"><div className="brandMark"><Shield size={20}/></div><div><b>SENTINEL<span> AI</span></b><small>SECURITY OPERATIONS</small></div></div><div className="workspace"><span className="liveDot"/> LOCAL ENVIRONMENT <ChevronRight size={13}/></div><nav>{tabs.map(([name, Icon]) => <button className={tab === name ? 'nav active' : 'nav'} onClick={() => setTab(name)} key={name}><Icon size={17}/><span>{name}</span>{name === 'Incidents' && overview?.active_incidents > 0 && <i>{overview.active_incidents}</i>}</button>)}</nav><div className="sideBottom"><div className="sensor"><div className="sensorIcon"><Activity size={15}/></div><div><b>Pipeline status</b><small>{connected ? 'All systems operational' : 'API unavailable'}</small></div><span className={connected ? 'statusDot' : 'statusDot off'}/></div><small className="build">SENTINEL CONSOLE <span>v1.0.0</span></small></div></aside>
    <main className="main"><header className="topbar"><div><div className="crumb">SECURITY OPERATIONS <span>/</span> {tab.toUpperCase()}</div><h1>{tab === 'Overview' ? 'Operations overview' : tab === 'Replay Lab' ? 'Replay laboratory' : tab}</h1></div><div className="topRight"><span className="utc"><Clock3 size={14}/> UTC · {new Date().toLocaleTimeString()}</span><button className="iconButton" onClick={load} aria-label="Refresh"><RefreshCw size={16}/></button><button className="analyst"><span>AN</span> Analyst <small>ADMIN</small></button></div></header>
    {error && <div className="error"><AlertTriangle size={16}/>{error}<button onClick={() => setError('')}>Dismiss</button></div>}{loading && <div className="loading">Connecting to Sentinel API…</div>}
    {tab === 'Overview' && <><div className="banner"><div className="bannerIcon"><Shield size={18}/></div><div><b>Local synthetic telemetry environment</b><p>Detections are rule-based signals for investigation. ATT&amp;CK mappings describe detection coverage, not confirmed adversary behavior.</p></div><span className="envTag">DEMO</span></div><section className="stats"><Stat title="Events processed" value={overview?.events_processed ?? '—'} note="All-time accepted" icon={Activity} color="blue"/><Stat title="Active incidents" value={overview?.active_incidents ?? '—'} note="Open · investigating · contained" icon={AlertTriangle} color="amber"/><Stat title="High severity findings" value={overview?.high_findings ?? '—'} note="High and critical" icon={Shield} color="red"/><Stat title="Detection model" value="Cold start" note="Deterministic rules active" icon={BrainCircuit} color="violet"/></section><section className="grid2"><div className="panel"><div className="panelHead"><div><h2>Detection activity</h2><p>Findings by rule · persisted signals</p></div><span className="range">ALL TIME</span></div><div className="chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={chart} margin={{ top: 10, right: 12, bottom: 0, left: -20 }}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#202b38"/><XAxis dataKey="name" tick={{ fill: '#8493a5', fontSize: 10 }} interval={0} angle={-15} textAnchor="end" height={52}/><YAxis tick={{ fill: '#8493a5', fontSize: 10 }} allowDecimals={false}/><Tooltip contentStyle={{ background: '#121a24', border: '1px solid #263344', borderRadius: 8, color: '#e8eef6' }}/><Bar dataKey="count" fill="#42b9aa" radius={[4, 4, 0, 0]}/></BarChart></ResponsiveContainer></div></div><div className="panel"><div className="panelHead"><div><h2>Recent incidents</h2><p>Latest correlated activity</p></div><button className="textButton" onClick={() => setTab('Incidents')}>View queue <ChevronRight size={14}/></button></div><div className="recent">{(overview?.recent_incidents || []).map((i: Any) => <button key={i.incident_id} className="recentRow" onClick={() => inspect(i)}><span className="severityRail"/><div><b>{i.title}</b><small>{i.incident_id.slice(0, 8)} · {dt(i.updated_at)}</small></div>{sev(i.severity)}</button>)}{!overview?.recent_incidents?.length && <Empty text="No incidents yet. Ingest synthetic data or start a replay."/>}</div></div></section><section className="panel eventPanel"><div className="panelHead"><div><h2>Live event stream</h2><p>Most recent normalized telemetry</p></div><div className="headActions"><span className="streamStatus"><i className={connected ? 'liveDot' : 'liveDot muted'}/>{connected ? 'STREAMING' : 'RECONNECTING'}</span><button className="smallButton" onClick={() => setPaused(!paused)}>{paused ? <Play size={14}/> : <Pause size={14}/>} {paused ? 'Resume' : 'Pause'}</button><button className="textButton" onClick={() => setTab('Events')}>Open stream <ChevronRight size={14}/></button></div></div><EventTable rows={events.slice(0, 7)} onSelect={setSelected}/></section></>}
    {tab === 'Events' && <section className="panel fullPanel"><div className="panelHead"><div><h2>Security event stream</h2><p>Auto-updating · bounded to 60 recent events</p></div><div className="headActions"><button className="smallButton" onClick={() => setPaused(!paused)}>{paused ? <Play size={14}/> : <Pause size={14}/>} {paused ? 'Resume' : 'Pause'}</button><button className="smallButton" onClick={() => setTab('Replay Lab')}><Filter size={14}/> Replay filter</button></div></div><label className="search"><Search size={15}/><input placeholder="Search events, users, hosts…" value={search} onChange={e => setSearch(e.target.value)}/></label><EventTable rows={filtered} onSelect={setSelected}/></section>}
    {tab === 'Incidents' && <section className="panel fullPanel"><div className="panelHead"><div><h2>Incident queue</h2><p>{incidents.length} incidents · severity is derived from deterministic finding rules</p></div><button className="smallButton" onClick={load}><RefreshCw size={14}/> Refresh</button></div><div className="tableWrap"><table><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>STATUS</th><th>ASSIGNEE</th><th>UPDATED</th><th /></tr></thead><tbody>{incidents.map(i => <tr key={i.incident_id} onClick={() => inspect(i)}><td><b>{i.title}</b><small className="sub">{i.incident_id.slice(0, 8)} · {i.summary}</small></td><td>{sev(i.severity)}</td><td><span className="state">{i.status}</span></td><td>{i.assignee || 'Unassigned'}</td><td>{dt(i.updated_at)}</td><td><ChevronRight size={15}/></td></tr>)}</tbody></table>{!incidents.length && <Empty text="No incidents available."/>}</div></section>}
    {tab === 'Investigation' && <><div className="panel fullPanel"><div className="panelHead"><div><h2>{detail?.title || 'Threat investigation'}</h2><p>{selected ? `Incident ${selected.incident_id}` : 'Select an incident from the queue to review its evidence.'}</p></div>{selected && <div className="headActions"><button className="smallButton" onClick={() => act(`/api/v1/incidents/${selected.incident_id}`, 'PATCH', { status: 'investigating' })}>Mark investigating</button><button className="primary" onClick={investigate}><BrainCircuit size={15}/> Generate evidence summary</button></div>}</div>{detail && <><div className="investSummary"><span>{sev(detail.severity)}</span><p>{detail.summary}</p><span className="state">{detail.status}</span></div><div className="investGrid"><div className="subPanel"><h3>Observed evidence <span>{detail.events?.length || 0} events</span></h3>{detail.events?.map((e: Any) => <div className="evidence" key={e.event_id}><div className="evidenceLine"/><div><small>{dt(e.timestamp)} · {e.event_category}</small><b>{e.event_action} <em>{e.outcome}</em></b><p>{e.username || '—'} · {e.hostname || '—'} · {e.source_ip || '—'}</p><code>{e.event_id}</code></div></div>)}</div><div className="subPanel"><h3>Investigation assistant</h3>{detail.investigation ? <><span className="fallback"><BrainCircuit size={14}/> Deterministic fallback · evidence package {detail.investigation.evidence_package_id.slice(0, 8)}</span><p className="summaryText">{detail.investigation.summary}</p><h4>Potential explanations</h4>{detail.investigation.potential_explanations?.map((x: string) => <p className="smallCopy">• {x}</p>)}<h4>Benign alternatives</h4>{detail.investigation.benign_alternatives?.map((x: string) => <p className="smallCopy">• {x}</p>)}<h4>Known unknowns</h4>{detail.investigation.unknowns?.map((x: string) => <p className="smallCopy">• {x}</p>)}</> : <Empty text="Generate a bounded evidence summary for this incident."/>}<button className="smallButton fullWidth" onClick={() => { setTab('Response'); setActions([]); }}>Review response actions <ChevronRight size={14}/></button></div></div><div className="subPanel graphPanel"><h3>Entity relationship view <span>Observed links only</span></h3><Graph incident={detail}/></div></>}</div></>}
    {tab === 'Replay Lab' && <><div className="banner"><div className="bannerIcon"><Play size={18}/></div><div><b>Replay events pass through normal ingestion</b><p>Scenarios contain synthetic identities, reserved IP ranges and documentation-only test behavior.</p></div><span className="envTag">SYNTHETIC</span></div><div className="scenarioGrid">{scenarios.map(s => <div className="panel scenario" key={s.scenario_id}><div className="scenarioIcon"><GitBranch size={18}/></div><span className="envTag">{s.event_count} EVENTS</span><h2>{s.name}</h2><p>{s.description}</p><div className="expected">EXPECTED RULES <span>{JSON.parse(s.expected_rules).join(' · ')}</span></div><div className="replayControls"><label>Speed<select id={'speed-' + s.scenario_id}><option value="1">1×</option><option value="4">4×</option><option value="10">10×</option></select></label><button className="primary" onClick={async () => { const speed = Number((document.getElementById('speed-' + s.scenario_id) as HTMLSelectElement).value); try {
        const r = await request('/api/v1/replays', { method: 'POST', body: JSON.stringify({ scenario_id: s.scenario_id, speed }) });
        setReplay(r);
    }
    catch (e: any) {
        setError(e.message);
    } }}><Play size={15}/> Start replay</button></div></div>)}</div>{replay && <div className="panel replayProgress"><div className="panelHead"><div><h2>Replay session</h2><p>{replay.replay_id} · {replay.state}</p></div><div className="headActions"><button className="smallButton" onClick={() => act(`/api/v1/replays/${replay.replay_id}/${replay.state === 'paused' ? 'resume' : 'pause'}`)}>{replay.state === 'paused' ? <Play size={14}/> : <Pause size={14}/>} {replay.state === 'paused' ? 'Resume' : 'Pause'}</button><button className="smallButton danger" onClick={() => act(`/api/v1/replays/${replay.replay_id}/cancel`)}><Square size={14}/> Cancel</button><button className="iconButton" onClick={async () => setReplay(await request(`/api/v1/replays/${replay.replay_id}`))} aria-label="Refresh replay"><RefreshCw size={15}/></button></div></div><div className="progress"><i style={{ width: `${Math.min(100, 100 * replay.progress / Math.max(1, replay.total))}%` }}/></div><p className="progressMeta">{replay.progress} / {replay.total} events · {replay.error || 'Processing through ingestion pipeline'}</p></div>}</>}
    {tab === 'Response' && <section className="panel fullPanel"><div className="panelHead"><div><h2>Response approval centre</h2><p>Every adapter changes Sentinel simulation state only. Approval and execution require admin role.</p></div><label className="rolePicker">DEMO ROLE<select onChange={e => { localStorage.setItem('sentinelRole', e.target.value); load(); }} value={localStorage.getItem('sentinelRole') || 'admin'}><option value="admin">Admin</option><option value="analyst">Analyst</option></select></label></div><div className="responseGrid">{actions.map(a => <div className="actionCard" key={a.action_id}><div className="actionTop"><span className="actionIcon"><Shield size={16}/></span><span className={`state ${a.state}`}>{a.state}</span></div><h3>{a.action_type.replaceAll('_', ' ')}</h3><p className="target">Target <b>{a.target}</b></p><p>{a.rationale}</p><div className="actionMeta"><span>RISK <b>{a.risk}</b></span><span>EXPIRY <b>{dt(a.expires_at)}</b></span></div>{a.result && <code className="result">{a.result}</code>}<div className="actionButtons">{a.state === 'pending' && <><button className="smallButton" onClick={() => act(`/api/v1/response-actions/${a.action_id}/reject`)}>Reject</button><button className="primary" onClick={() => act(`/api/v1/response-actions/${a.action_id}/approve`)}><CheckCircle size={14}/> Approve</button></>}{a.state === 'approved' && <button className="primary" onClick={() => act(`/api/v1/response-actions/${a.action_id}/execute`)}><Shield size={14}/> Execute simulation</button>}</div></div>)}{!actions.length && <div className="emptyCard"><Empty text="No actions proposed. Open an incident and create a simulation proposal."/>{incidents[0] && <button className="primary" onClick={() => act(`/api/v1/incidents/${incidents[0].incident_id}/response-actions?action_type=open_investigation&target=demo-investigation`)}>Propose investigation task</button>}</div>}</div></section>}
    {tab === 'Detection Health' && <><section className="stats"><Stat title="Active rules" value={rules.filter(x => x.enabled).length} note="Versioned deterministic rules" icon={Shield} color="blue"/><Stat title="Model state" value="Cold start" note="No training performed" icon={BrainCircuit} color="violet"/><Stat title="Model algorithm" value="Isolation Forest" note="Optional scikit-learn scorer" icon={Activity} color="amber"/><Stat title="Threshold" value={model?.threshold ?? '—'} note="Score is not a probability" icon={Filter} color="red"/></section><div className="panel fullPanel"><div className="panelHead"><div><h2>Rule catalogue</h2><p>MITRE mapping is shown only where detector logic supports it.</p></div><a className="textButton" href="https://attack.mitre.org/" target="_blank" rel="noreferrer">ATT&amp;CK reference <ExternalLink size={14}/></a></div><div className="ruleGrid">{rules.map(r => <div className="rule" key={r.rule_id}><div><span className="ruleId">{r.rule_id}</span>{sev(r.severity)}</div><h3>{r.name}</h3><p>{r.description}</p><small>VERSION {r.version} {r.technique_id && <>· <a href={`https://attack.mitre.org/techniques/${r.technique_id.replace('.', '/')}/`} target="_blank" rel="noreferrer">{r.technique_id} {r.technique_name}</a></>}</small></div>)}</div><div className="limitation"><AlertTriangle size={15}/>{'Unusual source IP baseline and robust cross-host clustering are known coverage gaps. Synthetic benchmark performance has not been measured.'}</div></div></>}
    {tab === 'Observability' && <><section className="stats"><Stat title="API health" value={connected ? 'Operational' : 'Unavailable'} note="/health · /ready" icon={Server} color={connected ? 'green' : 'red'}/><Stat title="Events accepted" value={overview?.events_processed ?? '—'} note="Local database total" icon={Activity} color="blue"/><Stat title="Queue depth" value="N/A" note="Inline processor; no queue" icon={GitBranch} color="amber"/><Stat title="Processing latency" value="Not measured" note="No benchmark run recorded" icon={Clock3} color="violet"/></section><div className="panel fullPanel"><div className="panelHead"><div><h2>Service health</h2><p>Operational metrics and current implementation boundaries.</p></div><button className="smallButton" onClick={load}><RefreshCw size={14}/> Refresh</button></div><div className="healthRows"><div><span className={connected ? 'statusDot' : 'statusDot off'}/> API service <b>{connected ? 'Connected' : 'Unavailable'}</b><small>FastAPI · local</small></div><div><span className="statusDot"/> Persistence <b>{connected ? 'SQLite / configured database' : 'Unknown'}</b><small>SQLAlchemy</small></div><div><span className="statusDot amberDot"/> Worker queue <b>Inline processing</b><small>Redis buffering not yet wired</small></div><div><span className="statusDot amberDot"/> Anomaly model <b>Cold start</b><small>Deterministic rules remain active</small></div></div><p className="limitation">Prometheus exposition: <a href="http://localhost:8000/metrics" target="_blank">/metrics</a>. Detailed OpenTelemetry tracing, queue backlog and processing latency instrumentation are not implemented in this build.</p></div></>}
    <footer>Sentinel AI <span>·</span> Synthetic telemetry only <span>·</span> No live response adapters</footer></main>
    {selected && tab !== 'Investigation' && <div className="drawerBackdrop" onClick={() => setSelected(null)}><div className="drawer" onClick={e => e.stopPropagation()}><button className="drawerClose" onClick={() => setSelected(null)}>×</button><span className="crumb">EVENT DETAIL</span><h2>{selected.event_action || selected.title}</h2><p>{selected.event_id || selected.incident_id}</p>{sev(selected.severity)}<div className="drawerFields">{Object.entries(selected).filter(([k, v]) => v !== null && typeof v !== 'object').map(([k, v]) => <div key={k}><small>{k.replaceAll('_', ' ').toUpperCase()}</small><b>{String(v)}</b></div>)}</div>{selected.incident_id && <button className="primary fullWidth" onClick={() => inspect(selected)}>Open investigation</button>}</div></div>}</div>;
}
function Stat({ title, value, note, icon: Icon, color }: Any) { return <div className="stat"><div className={`statIcon ${color}`}><Icon size={17}/></div><div className="statTitle">{title}</div><b className="statValue">{value}</b><small>{note}</small></div>; }
function Empty({ text }: {
    text: string;
}) { return <div className="empty"><div><Activity size={18}/></div><p>{text}</p></div>; }
function EventTable({ rows, onSelect }: {
    rows: Any[];
    onSelect: (x: Any) => void;
}) { return <div className="tableWrap"><table><thead><tr><th>TIME</th><th>SEVERITY</th><th>CATEGORY</th><th>ACTION</th><th>IDENTITY / HOST</th><th>SOURCE IP</th></tr></thead><tbody>{rows.map(e => <tr key={e.event_id} onClick={() => onSelect(e)}><td className="mono">{dt(e.timestamp)}</td><td>{sev(e.severity)}</td><td><span className="category">{e.event_category}</span></td><td><b>{e.event_action}</b>{e.outcome && <small className="sub">Outcome: {e.outcome}</small>}</td><td>{e.username || '—'}<small className="sub">{e.hostname || '—'}</small></td><td className="mono">{e.source_ip || '—'}</td></tr>)}</tbody></table>{!rows.length && <Empty text="No events match this view."/>}</div>; }
function Graph({ incident }: Any) { const names = Array.from(new Set((incident.events || []).flatMap((e: Any) => [e.username, e.source_ip, e.hostname].filter(Boolean)))); return <div className="graph"><div className="graphLinks">{incident.events?.slice(0, 12).map((e: Any) => <div className="graphRow" key={e.event_id}><span className="node eventNode">{e.event_action}</span><span className="edge">observed from</span><span className="node ipNode">{e.source_ip || 'source unknown'}</span><span className="edge">on</span><span className="node hostNode">{e.hostname || 'host unknown'}</span>{e.username && <><span className="edge">by</span><span className="node userNode">{e.username}</span></>}</div>)}</div><div className="graphLegend"><span className="eventNode"/>Event <span className="ipNode"/>IP address <span className="hostNode"/>Host <span className="userNode"/>User <small>{names.length} distinct entities · edges are directly observed in stored event records</small></div></div>; }
