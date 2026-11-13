'use client'
import { useState, useEffect, useRef } from 'react'
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine
} from 'recharts'
import {
  Shield, Activity, Zap, Wifi, AlertTriangle, 
  CheckCircle, XCircle, Clock, Server, Users,
  Radio, TrendingUp, BarChart2, Lock, Unlock,
  ChevronRight, RefreshCw
} from 'lucide-react'

const API_BASE = 'http://localhost:5000'

// ── Status helpers ──────────────────────────────────────────────────────────
function getStatusConfig(status) {
  switch (status) {
    case 'DDOS_DETECTED':
      return { label: 'DDoS DETECTED', cls: 'status-ddos', icon: XCircle, dot: '#f43f5e', glow: 'animate-glow-red', pulse: true }
    case 'SUSPICIOUS':
      return { label: 'SUSPICIOUS', cls: 'status-suspicious', icon: AlertTriangle, dot: '#f59e0b', glow: 'animate-glow-amber', pulse: false }
    case 'BASELINE_COLLECTION':
      return { label: 'LEARNING BASELINE', cls: 'status-baseline', icon: Activity, dot: '#38bdf8', glow: 'animate-glow-cyan', pulse: false }
    default:
      return { label: 'NORMAL', cls: 'status-normal', icon: CheckCircle, dot: '#10b981', glow: '', pulse: false }
  }
}

function getScoreColor(score) {
  if (score >= 60) return '#f43f5e'
  if (score >= 30) return '#f59e0b'
  return '#10b981'
}

function formatLocalTime(timestamp, fallbackIso) {
  if (timestamp && !isNaN(Number(timestamp))) {
    const num = Number(timestamp)
    const ms = num > 1e11 ? num : num * 1000
    const d = new Date(ms)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  }
  return fallbackIso?.split(' ')[1] || fallbackIso || ''
}

function formatFullLocalTime(timestamp, fallbackIso) {
  if (timestamp && !isNaN(Number(timestamp))) {
    const num = Number(timestamp)
    const ms = num > 1e11 ? num : num * 1000
    const d = new Date(ms)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true })
  }
  return fallbackIso || ''
}

// ── Custom Tooltip ───────────────────────────────────────────────────────────
function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: 'rgba(15,23,42,0.95)', border: '1px solid rgba(51,65,85,0.8)', borderRadius: 10, padding: '10px 14px' }}>
      <p style={{ color: '#94a3b8', fontSize: 11, marginBottom: 4 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color, fontSize: 13, fontWeight: 600 }}>
          {p.name}: {typeof p.value === 'number' ? p.value.toFixed(1) : p.value}
        </p>
      ))}
    </div>
  )
}

// ── Metric Card ───────────────────────────────────────────────────────────────
function MetricCard({ icon: Icon, label, value, unit, subtext, color = '#38bdf8', delay = 0 }) {
  return (
    <div className="card p-5 animate-fade-in-up" style={{ animationDelay: `${delay}ms` }}>
      <div className="flex justify-between items-center mb-3">
        <span style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
        <Icon size={16} style={{ color }} />
      </div>
      <div className="flex items-baseline gap-2">
        <span style={{ fontSize: 32, fontWeight: 800, color: '#f1f5f9', lineHeight: 1 }}>{value}</span>
        {unit && <span style={{ fontSize: 12, color: '#64748b' }}>{unit}</span>}
      </div>
      {subtext && <p style={{ fontSize: 11, color: '#64748b', marginTop: 8 }}>{subtext}</p>}
    </div>
  )
}

// ── Score Gauge ───────────────────────────────────────────────────────────────
function ScoreGauge({ score }) {
  const color = getScoreColor(score)
  const pct = Math.min(100, score)
  const r = 54, cx = 70, cy = 70
  const circ = 2 * Math.PI * r
  const dash = (pct / 100) * circ

  return (
    <div className="card p-5 animate-fade-in-up flex flex-col items-center justify-center" style={{ animationDelay: '0ms' }}>
      <span style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
        Suspicion Score
      </span>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(51,65,85,0.5)" strokeWidth="10" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          transform={`rotate(-90 ${cx} ${cy})`}
          style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.6s ease', filter: `drop-shadow(0 0 6px ${color})` }}
        />
        <text x={cx} y={cy - 6} textAnchor="middle" fill={color} fontSize="26" fontWeight="800">{score}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" fill="#64748b" fontSize="11">/ 100</text>
      </svg>
      <p style={{ fontSize: 11, color: '#64748b', marginTop: 8 }}>
        Threshold: <span style={{ color: '#f59e0b', fontWeight: 700 }}>60 / 100</span>
      </p>
    </div>
  )
}

// ── Network Topology SVG ──────────────────────────────────────────────────────
function NetworkTopology({ blockedMacs = [], detectionStatus = 'NORMAL' }) {
  const isAttacking = detectionStatus === 'DDOS_DETECTED' || detectionStatus === 'SUSPICIOUS'

  const nodes = {
    s1:       { x: 320, y: 200, label: 'Switch S1', type: 'switch' },
    s2:       { x: 560, y: 200, label: 'Switch S2', type: 'switch' },
    client1:  { x: 140, y: 80,  label: 'Client 1\n10.0.0.1', type: 'client', mac: '00:00:00:00:00:01' },
    client2:  { x: 280, y: 60,  label: 'Client 2\n10.0.0.2', type: 'client', mac: '00:00:00:00:00:02' },
    client3:  { x: 150, y: 330, label: 'Client 3\n10.0.0.3', type: 'client', mac: '00:00:00:00:00:03' },
    atk1:     { x: 700, y: 80,  label: 'Attacker1\n10.0.0.100', type: 'attacker', mac: '00:00:00:00:00:a1' },
    atk2:     { x: 710, y: 330, label: 'Attacker2\n10.0.0.101', type: 'attacker', mac: '00:00:00:00:00:a2' },
    server1:  { x: 560, y: 360, label: 'Server1\n10.0.0.200', type: 'server', mac: '00:00:00:00:00:fe' },
  }

  const links = [
    ['client1','s1'],['client2','s1'],['client3','s1'],
    ['s1','s2'],
    ['atk1','s2'],['atk2','s2'],['server1','s2'],
  ]

  const typeStyle = {
    switch:   { fill: '#1e1b4b', stroke: '#a78bfa', r: 26, textColor: '#c4b5fd' },
    client:   { fill: '#0c2233', stroke: '#38bdf8', r: 22, textColor: '#7dd3fc' },
    attacker: { fill: '#2d0f17', stroke: '#f43f5e', r: 22, textColor: '#fca5a5' },
    server:   { fill: '#022c22', stroke: '#10b981', r: 26, textColor: '#6ee7b7' },
  }

  return (
    <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
      <div className="flex justify-between items-center mb-4">
        <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
          <span style={{ color: '#a78bfa', marginRight: 8 }}>◈</span>Network Topology
        </h2>
        <div className="flex gap-4" style={{ fontSize: 11, color: '#64748b' }}>
          <span>🔵 Client</span><span>🔴 Attacker</span><span>🟢 Server</span><span>🟣 Switch</span>
        </div>
      </div>
      <svg viewBox="0 0 860 440" style={{ width: '100%', height: 260 }}>
        <defs>
          <filter id="glow-cyan"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
          <filter id="glow-red"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
        </defs>

        {/* Links */}
        {links.map(([a, b], i) => {
          const na = nodes[a], nb = nodes[b]
          const isAttackLink = (a === 'atk1' || a === 'atk2') && isAttacking
          const isBlocked = (a === 'atk1' && blockedMacs.includes(nodes.atk1.mac)) ||
                            (a === 'atk2' && blockedMacs.includes(nodes.atk2.mac))
          return (
            <line key={i}
              x1={na.x} y1={na.y} x2={nb.x} y2={nb.y}
              stroke={isBlocked ? '#374151' : isAttackLink ? '#f43f5e' : '#334155'}
              strokeWidth={isAttackLink ? 2.5 : 1.5}
              strokeDasharray={isBlocked ? '5,5' : 'none'}
              opacity={isBlocked ? 0.4 : 0.8}
              style={isAttackLink && !isBlocked ? { animation: 'pulse-glow 1s ease-in-out infinite' } : {}}
            />
          )
        })}

        {/* Nodes */}
        {Object.entries(nodes).map(([id, node]) => {
          const s = typeStyle[node.type]
          const isBlocked = node.mac && blockedMacs.map(m => m.toLowerCase()).includes(node.mac)
          const lines = node.label.split('\n')
          return (
            <g key={id}>
              <circle cx={node.x} cy={node.y} r={s.r + 6} fill="none"
                stroke={isBlocked ? '#374151' : s.stroke} strokeWidth="1"
                opacity={isBlocked ? 0.2 : 0.15}
              />
              <circle cx={node.x} cy={node.y} r={s.r} fill={s.fill}
                stroke={isBlocked ? '#374151' : s.stroke} strokeWidth="2"
                filter={node.type === 'server' ? 'url(#glow-cyan)' : 'none'}
                opacity={isBlocked ? 0.5 : 1}
              />
              {isBlocked && (
                <text x={node.x} y={node.y + 5} textAnchor="middle" fill="#f43f5e" fontSize="16">⛔</text>
              )}
              {lines.map((line, li) => (
                <text key={li} x={node.x} y={node.y + 38 + li * 14}
                  textAnchor="middle" fill={isBlocked ? '#475569' : s.textColor}
                  fontSize="10" fontWeight="600">
                  {line}
                </text>
              ))}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

// ── Blocked Attackers Panel ───────────────────────────────────────────────────
function BlockedPanel({ blocked }) {
  return (
    <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '150ms' }}>
      <div className="flex justify-between items-center mb-4">
        <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
          <span style={{ color: '#f43f5e', marginRight: 8 }}>⛔</span>Blocked Attackers
        </h2>
        <span style={{ fontSize: 11, color: blocked.length > 0 ? '#f43f5e' : '#10b981',
          background: blocked.length > 0 ? 'rgba(244,63,94,0.1)' : 'rgba(16,185,129,0.1)',
          padding: '2px 10px', borderRadius: 99, border: `1px solid ${blocked.length > 0 ? 'rgba(244,63,94,0.3)' : 'rgba(16,185,129,0.3)'}` }}>
          {blocked.length} blocked
        </span>
      </div>
      {blocked.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '24px 0', color: '#475569' }}>
          <CheckCircle size={28} style={{ margin: '0 auto 8px', color: '#10b981' }} />
          <p style={{ fontSize: 13 }}>No attackers currently blocked</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {blocked.map((b, i) => (
            <div key={i} style={{ background: 'rgba(244,63,94,0.06)', border: '1px solid rgba(244,63,94,0.2)', borderRadius: 10, padding: '10px 14px' }}>
              <div className="flex justify-between items-center">
                <div className="flex items-center gap-2">
                  <Lock size={14} style={{ color: '#f43f5e' }} />
                  <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#fca5a5' }}>{b.attacker_mac}</span>
                </div>
                <span style={{ fontSize: 10, color: '#f43f5e', fontWeight: 700, textTransform: 'uppercase',
                  background: 'rgba(244,63,94,0.15)', padding: '2px 8px', borderRadius: 99 }}>
                  {b.action?.replace(/_/g,' ')}
                </span>
              </div>
              <p style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
                Target: <span style={{ color: '#6ee7b7' }}>{b.target_ip}</span> • {formatFullLocalTime(b.timestamp, b.iso_time)}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Detection Log Table ───────────────────────────────────────────────────────
function DetectionLog({ history }) {
  const rows = [...history].reverse().slice(0, 12)
  return (
    <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
      <div className="flex justify-between items-center mb-4">
        <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
          <span style={{ color: '#6366f1', marginRight: 8 }}>📋</span>Detection Audit Log
        </h2>
        <span style={{ fontSize: 11, color: '#64748b' }}>Last {rows.length} events</span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr style={{ color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', fontSize: 10 }}>
              {['Time','PPS','Kbps','Flows','Conc.','Score','Status','Reason'].map(h => (
                <th key={h} style={{ padding: '6px 10px', textAlign: 'left', fontWeight: 700, borderBottom: '1px solid rgba(51,65,85,0.5)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={8} style={{ textAlign: 'center', color: '#475569', padding: 24 }}>Waiting for Ryu controller events...</td></tr>
            ) : rows.map((row, i) => {
              const sc = getStatusConfig(row.detection_status)
              const scoreColor = getScoreColor(row.suspicion_score)
              return (
                <tr key={i} style={{ borderBottom: '1px solid rgba(51,65,85,0.3)', transition: 'background 0.15s' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(56,189,248,0.04)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: '#94a3b8' }}>{formatLocalTime(row.timestamp, row.iso_time)}</td>
                  <td style={{ padding: '8px 10px', color: '#38bdf8', fontWeight: 600 }}>{Number(row.packet_rate).toFixed(1)}</td>
                  <td style={{ padding: '8px 10px', color: '#818cf8' }}>{Number(row.byte_rate).toFixed(1)}</td>
                  <td style={{ padding: '8px 10px', color: '#f1f5f9' }}>{row.active_flows}</td>
                  <td style={{ padding: '8px 10px', color: '#c084fc' }}>{Number(row.traffic_concentration).toFixed(1)}%</td>
                  <td style={{ padding: '8px 10px', fontWeight: 800, color: scoreColor }}>{row.suspicion_score}</td>
                  <td style={{ padding: '8px 10px' }}>
                    <span style={{ color: sc.dot, background: `${sc.dot}18`, padding: '2px 8px', borderRadius: 99, fontSize: 10, fontWeight: 700, border: `1px solid ${sc.dot}40` }}>
                      {sc.label}
                    </span>
                  </td>
                  <td style={{ padding: '8px 10px', color: '#64748b', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    title={row.reason}>{row.reason}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── MAIN PAGE ─────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [latest, setLatest] = useState({ detection_status: 'BASELINE_COLLECTION', suspicion_score: 0, packet_rate: 0, byte_rate: 0, active_flows: 0, unique_sources: 0, traffic_concentration: 0, consecutive_suspicious: 0, iso_time: '...', reason: '' })
  const [history, setHistory] = useState([])
  const [blocked, setBlocked] = useState([])
  const [connected, setConnected] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(null)

  useEffect(() => {
    let active = true

    async function fetchAll() {
      try {
        const [statsRes, mitRes] = await Promise.all([
          fetch(`${API_BASE}/api/stats`).catch(() => null),
          fetch(`${API_BASE}/api/mitigation`).catch(() => null),
        ])
        if (!active) return

        if (statsRes?.ok) {
          const d = await statsRes.json()
          if (d.latest) setLatest(d.latest)
          if (d.history) setHistory(d.history)
          setConnected(true)
        } else {
          setConnected(false)
        }

        if (mitRes?.ok) {
          const m = await mitRes.json()
          setBlocked(m.blocked || [])
        }

        setLastUpdate(new Date().toLocaleTimeString())
      } catch {
        if (active) setConnected(false)
      }
    }

    fetchAll()
    const interval = setInterval(fetchAll, 1000)
    return () => { active = false; clearInterval(interval) }
  }, [])

  const statusCfg = getStatusConfig(latest.detection_status)
  const StatusIcon = statusCfg.icon
  const blockedMacs = blocked.map(b => b.attacker_mac?.toLowerCase())

  // Chart data
  const chartData = history.slice(-30).map(h => ({
    t: formatLocalTime(h.timestamp, h.iso_time),
    pps: Number(h.packet_rate),
    bps: Number(h.byte_rate),
    score: Number(h.suspicion_score),
    flows: Number(h.active_flows),
  }))

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-primary)' }}>

      {/* Navbar */}
      <nav style={{ background: 'rgba(15,23,42,0.9)', borderBottom: '1px solid rgba(51,65,85,0.5)', backdropFilter: 'blur(16px)', position: 'sticky', top: 0, zIndex: 50 }}>
        <div style={{ maxWidth: 1400, margin: '0 auto', padding: '0 24px', height: 64, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="flex items-center gap-3">
            <div style={{ width: 38, height: 38, borderRadius: 10, background: 'linear-gradient(135deg,#1e3a5f,#0c2233)', border: '1px solid rgba(56,189,248,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={20} style={{ color: '#38bdf8' }} />
            </div>
            <div>
              <h1 className="gradient-text" style={{ fontSize: 17, fontWeight: 800, letterSpacing: '-0.02em' }}>SDN DDoS Protection Center</h1>
              <p style={{ fontSize: 11, color: '#64748b' }}>Ryu OpenFlow 1.3 • Statistical Detection Engine</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Connection indicator */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 99, background: connected ? 'rgba(16,185,129,0.1)' : 'rgba(244,63,94,0.1)', border: `1px solid ${connected ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'}` }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: connected ? '#10b981' : '#f43f5e', display: 'inline-block' }} />
              <span style={{ fontSize: 11, fontWeight: 700, color: connected ? '#10b981' : '#f43f5e' }}>{connected ? 'API CONNECTED' : 'API OFFLINE'}</span>
            </div>

            {/* Status badge */}
            <div className={`flex items-center gap-2 ${statusCfg.glow}`} style={{ padding: '6px 16px', borderRadius: 99, border: '1px solid', fontSize: 12, fontWeight: 800, letterSpacing: '0.06em',
              ...( latest.detection_status === 'DDOS_DETECTED' ? { color: '#f43f5e', background: 'rgba(244,63,94,0.12)', borderColor: 'rgba(244,63,94,0.4)' }
                : latest.detection_status === 'SUSPICIOUS'    ? { color: '#f59e0b', background: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.4)' }
                : latest.detection_status === 'BASELINE_COLLECTION' ? { color: '#38bdf8', background: 'rgba(56,189,248,0.1)', borderColor: 'rgba(56,189,248,0.3)' }
                : { color: '#10b981', background: 'rgba(16,185,129,0.1)', borderColor: 'rgba(16,185,129,0.3)' }
              )
            }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusCfg.dot, display: 'inline-block',
                animation: statusCfg.pulse ? 'ping 1s cubic-bezier(0,0,0.2,1) infinite' : 'none' }} />
              <StatusIcon size={13} />
              {statusCfg.label}
            </div>

            {lastUpdate && <span style={{ fontSize: 11, color: '#475569' }}><RefreshCw size={10} style={{ display: 'inline', marginRight: 4 }} />{lastUpdate}</span>}
          </div>
        </div>
      </nav>

      <main style={{ maxWidth: 1400, margin: '0 auto', padding: '24px' }}>

        {/* Top metrics row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 20 }}>
          <ScoreGauge score={latest.suspicion_score} />
          <MetricCard icon={Zap} label="Packet Rate" value={Number(latest.packet_rate).toFixed(1)} unit="pps" subtext="Packets per second to server" color="#38bdf8" delay={50} />
          <MetricCard icon={Activity} label="Bandwidth" value={Number(latest.byte_rate).toFixed(1)} unit="Kbps" subtext="Bytes per second × 8" color="#818cf8" delay={100} />
          <MetricCard icon={BarChart2} label="Active Flows" value={latest.active_flows} subtext={`${latest.unique_sources} unique sources`} color="#a78bfa" delay={150} />
          <MetricCard icon={TrendingUp} label="Concentration" value={`${Number(latest.traffic_concentration).toFixed(1)}%`} subtext="Dominant source share" color={latest.traffic_concentration > 70 ? '#f43f5e' : '#10b981'} delay={200} />
          <MetricCard icon={Radio} label="Persistence" value={`${latest.consecutive_suspicious}/3`} unit="cycles" subtext="Suspicious intervals" color={latest.consecutive_suspicious >= 3 ? '#f43f5e' : '#f59e0b'} delay={250} />
        </div>

        {/* Network topology */}
        <div style={{ marginBottom: 20 }}>
          <NetworkTopology blockedMacs={blockedMacs} detectionStatus={latest.detection_status} />
        </div>

        {/* Charts row */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          {/* PPS Chart */}
          <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
            <div className="flex justify-between items-center mb-4">
              <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
                <span style={{ color: '#38bdf8', marginRight: 8 }}>▲</span>Live Packet Rate (PPS)
              </h2>
              <span style={{ fontSize: 10, color: '#38bdf8', background: 'rgba(56,189,248,0.1)', padding: '2px 8px', borderRadius: 99, border: '1px solid rgba(56,189,248,0.2)' }}>1s polling</span>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51,65,85,0.5)" />
                <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="pps" name="PPS" stroke="#38bdf8" fill="url(#ppsGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Score Chart */}
          <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '150ms' }}>
            <div className="flex justify-between items-center mb-4">
              <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
                <span style={{ color: '#f59e0b', marginRight: 8 }}>◎</span>Suspicion Score
              </h2>
              <span style={{ fontSize: 10, color: '#f59e0b', background: 'rgba(245,158,11,0.1)', padding: '2px 8px', borderRadius: 99, border: '1px solid rgba(245,158,11,0.2)' }}>Threshold = 60</span>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51,65,85,0.5)" />
                <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <ReferenceLine y={60} stroke="#f43f5e" strokeDasharray="4 4" strokeWidth={1.5} label={{ value: 'Threshold', fill: '#f43f5e', fontSize: 10 }} />
                <Area type="monotone" dataKey="score" name="Score" stroke="#f59e0b" fill="url(#scoreGrad)" strokeWidth={2.5} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Bottom row: blocked panel + flow chart */}
        <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: 16, marginBottom: 20 }}>
          <BlockedPanel blocked={blocked} />

          {/* Flow + BPS chart */}
          <div className="card p-5 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
            <div className="flex justify-between items-center mb-4">
              <h2 style={{ fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e2e8f0' }}>
                <span style={{ color: '#a78bfa', marginRight: 8 }}>◉</span>Flow Count & Bandwidth
              </h2>
            </div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(51,65,85,0.5)" />
                <XAxis dataKey="t" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} />
                <YAxis yAxisId="left" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} />
                <YAxis yAxisId="right" orientation="right" tick={{ fill: '#64748b', fontSize: 10 }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Line yAxisId="left" type="monotone" dataKey="flows" name="Flows" stroke="#a78bfa" strokeWidth={2} dot={false} />
                <Line yAxisId="right" type="monotone" dataKey="bps" name="Kbps" stroke="#6ee7b7" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Detection log */}
        <DetectionLog history={history} />

        {/* Footer info bar */}
        <div style={{ marginTop: 20, padding: '14px 20px', borderRadius: 12, background: 'rgba(15,23,42,0.5)', border: '1px solid rgba(51,65,85,0.4)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          {[
            { label: 'Protected Server', val: '10.0.0.200', color: '#6ee7b7' },
            { label: 'Baseline Duration', val: '15 seconds', color: '#38bdf8' },
            { label: 'Score Threshold', val: '60 / 100', color: '#f59e0b' },
            { label: 'Persistence Cycles', val: '3 intervals', color: '#c084fc' },
            { label: 'Poll Interval', val: 'Every 1s', color: '#94a3b8' },
            { label: 'Protocol', val: 'OpenFlow 1.3', color: '#818cf8' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ fontSize: 11 }}>
              <span style={{ color: '#475569' }}>{label}: </span>
              <span style={{ color, fontWeight: 700, fontFamily: 'monospace' }}>{val}</span>
            </div>
          ))}
        </div>

      </main>
    </div>
  )
}
