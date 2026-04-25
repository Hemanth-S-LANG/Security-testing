import { useState, useRef } from 'react'
import { api } from './api.js'
import './index.css'

const SEVERITY_COLOR = { critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#4ade80' }
const STATUS_COLOR = { PASS: '#4ade80', FAIL: '#f43f5e', ERROR: '#94a3b8' }
const OWASP_LABEL = {
  'A01:BrokenAccess':    'Broken Access Control',
  'A03:Injection':       'SQL / NoSQL Injection',
  'A03:InputValidation': 'Input Validation',
  'A05:Misconfig':       'Security Misconfiguration',
  'A07:BrokenAuth':      'Broken Authentication',
}

function Donut({ passed, failed, errors, total }) {
  const r = 46, cx = 60, cy = 60, sw = 14
  const C = 2 * Math.PI * r
  const pP = total ? passed / total : 0
  const fP = total ? failed / total : 0
  const eP = total ? errors / total : 0
  const g = 0.012
  const segs = [
    { v: Math.max(pP - g, 0), c: '#4ade80', o: 0 },
    { v: Math.max(fP - g, 0), c: '#f43f5e', o: pP },
    { v: Math.max(eP, 0),     c: '#64748b', o: pP + fP },
  ].filter(s => s.v > 0)
  return (
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth={sw} />
      {segs.map((s, i) => (
        <circle key={i} cx={cx} cy={cy} r={r} fill="none"
          stroke={s.c} strokeWidth={sw}
          strokeDasharray={String(s.v * C) + ' ' + String(C)}
          strokeDashoffset={String(-s.o * C)}
          style={{ transform: 'rotate(-90deg)', transformOrigin: cx + 'px ' + cy + 'px' }}
          strokeLinecap="round"
        />
      ))}
      <text x={cx} y={cy - 6} textAnchor="middle" fontSize="20" fontWeight="700" fill="#f1f5f9">
        {total ? Math.round(passed / total * 100) : 0}%
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fontSize="10" fill="#64748b">pass rate</text>
    </svg>
  )
}

export default function App() {
  const fileRef = useRef()
  const [swaggerSpec, setSwaggerSpec] = useState(null)
  const [fileName, setFileName]       = useState('')
  const [baseUrl, setBaseUrl]         = useState('')
  const [fileErr, setFileErr]         = useState('')
  const [preview, setPreview]         = useState(null)
  const [results, setResults]         = useState(null)
  const [genLoading, setGenLoading]   = useState(false)
  const [runLoading, setRunLoading]   = useState(false)
  const [progress, setProgress]       = useState(0)
  const [runError, setRunError]       = useState('')
  const [expandedId, setExpandedId]   = useState(null)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [sevFilter, setSevFilter]       = useState('ALL')
  const [catFilter, setCatFilter]       = useState('ALL')
  const [search, setSearch]             = useState('')
  const [copyMsg, setCopyMsg]           = useState('')
  const [payloadModal, setPayloadModal] = useState({ open: false, title: '', body: '' })

  const loadFile = file => {
    if (!file) return
    if (!file.name.endsWith('.json')) { setFileErr('Please upload a .json file.'); return }
    setFileErr('')
    const reader = new FileReader()
    reader.onload = ev => {
      try {
        const parsed = JSON.parse(ev.target.result)
        if (!parsed.paths) { setFileErr('Invalid spec — "paths" key missing.'); return }
        setSwaggerSpec(parsed); setFileName(file.name); setPreview(null); setResults(null)
      } catch { setFileErr('Could not parse JSON.') }
    }
    reader.readAsText(file)
  }

  const onDrop = e => { e.preventDefault(); loadFile(e.dataTransfer.files[0]) }
  const onPaste = e => {
    try {
      const p = JSON.parse(e.target.value)
      if (p.paths) { setSwaggerSpec(p); setFileName('pasted-spec.json'); setFileErr('') }
    } catch {}
  }

  const handleGenerate = async () => {
    if (!swaggerSpec) { setFileErr('Upload or paste a Swagger spec first.'); return }
    if (!baseUrl) { setFileErr('Enter a base URL.'); return }
    setFileErr(''); setGenLoading(true)
    try { setPreview(await api.generate(swaggerSpec, baseUrl)); setResults(null) }
    catch (e) { setFileErr(e.message) }
    finally { setGenLoading(false) }
  }

  const handleRun = async () => {
    if (!swaggerSpec) { setRunError('Upload a spec first.'); return }
    if (!baseUrl) { setRunError('Enter a base URL.'); return }
    setRunError(''); setRunLoading(true); setProgress(0); setResults(null)
    const t = setInterval(() => setProgress(p => Math.min(p + Math.random() * 7, 91)), 700)
    try {
      const run = await api.run(swaggerSpec, baseUrl)
      const full = await api.getResults(run.id)
      clearInterval(t); setProgress(100); setResults(full)
    } catch (e) { clearInterval(t); setRunError(e.message) }
    finally { setRunLoading(false) }
  }

  const filtered = (results?.results || []).filter(r => {
    const s = r.result?.result_status || 'ERROR'
    return (statusFilter === 'ALL' || s === statusFilter)
        && (sevFilter === 'ALL' || r.severity === sevFilter)
        && (catFilter === 'ALL' || r.owasp_category === catFilter)
        && (!search || r.endpoint_path.includes(search) || r.attack_type.includes(search))
  })
  const cats = results ? [...new Set(results.results.map(r => r.owasp_category))] : []
  const copyToken = async () => {
    const token = results?.session?.token
    if (!token) return
    try {
      await navigator.clipboard.writeText(token)
      setCopyMsg('Token copied')
      setTimeout(() => setCopyMsg(''), 1500)
    } catch {
      setCopyMsg('Copy failed')
      setTimeout(() => setCopyMsg(''), 1500)
    }
  }
  const isProbablyJson = (value) => {
    const t = value.trim()
    return (t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))
  }
  const tryParseJsonString = (value) => {
    if (typeof value !== 'string' || !isProbablyJson(value)) return value
    try {
      return JSON.parse(value)
    } catch {
      return value
    }
  }
  const normalizePayload = (value, depth = 0) => {
    if (depth > 3) return value
    if (value == null) return value

    if (typeof value === 'string') {
      const parsed = tryParseJsonString(value)
      if (parsed !== value) return normalizePayload(parsed, depth + 1)
      return value
    }

    if (Array.isArray(value)) {
      return value.map((item) => normalizePayload(item, depth + 1))
    }

    if (typeof value === 'object') {
      const out = {}
      for (const [k, v] of Object.entries(value)) {
        out[k] = normalizePayload(v, depth + 1)
      }
      return out
    }

    return value
  }
  const formatPayload = payload => {
    if (payload == null || payload === '') return 'No payload captured'

    const normalized = normalizePayload(payload)

    if (typeof normalized === 'string') return normalized

    try {
      return JSON.stringify(normalized, null, 2)
    } catch {
      // Fallback for non-serializable values (e.g. circular refs).
      try {
        return String(normalized)
      } catch {
        return 'Unable to render payload'
      }
    }
  }
  const openPayloadModal = (row) => {
    setPayloadModal({
      open: true,
      title: `${row.http_method} ${row.endpoint_path}`,
      body: formatPayload(row.payload_used),
    })
  }
  const getOutcomeLabel = (row) => {
    const status = row.result?.result_status || 'ERROR'
    if (status === 'FAIL') return (row.severity || 'fail').toUpperCase()
    return status
  }
  const getOutcomeColor = (row) => {
    const status = row.result?.result_status || 'ERROR'
    if (status === 'FAIL') return SEVERITY_COLOR[row.severity] || STATUS_COLOR.FAIL
    return STATUS_COLOR[status] || STATUS_COLOR.ERROR
  }

  return (
    <>
    <div className="root">
      <header className="topbar">
        <span className="brand-icon">⚡</span>
        <span className="brand-name">SecureTester</span>
        <span className="brand-tag">OWASP Automated Security Testing</span>
      </header>

      <section className="input-panel">
        <div className="panel-inner">
          <label className="field-label">Swagger / OpenAPI Spec <em>JSON format</em></label>
          <div className={'dropzone' + (swaggerSpec ? ' has-file' : '')}
            onDrop={onDrop} onDragOver={e => e.preventDefault()}
            onClick={() => fileRef.current?.click()}>
            <input ref={fileRef} type="file" accept=".json" style={{display:'none'}} onChange={e => loadFile(e.target.files[0])} />
            {swaggerSpec ? (
              <div className="file-loaded">
                <span className="file-check">✓</span>
                <div>
                  <p className="file-name">{fileName}</p>
                  <p className="file-meta">{Object.keys(swaggerSpec.paths||{}).length} endpoints · {swaggerSpec.info?.title || 'OpenAPI Spec'}</p>
                </div>
                <button className="clear-btn" onClick={e => { e.stopPropagation(); setSwaggerSpec(null); setFileName(''); setPreview(null); setResults(null) }}>✕</button>
              </div>
            ) : (
              <div className="drop-hint">
                <span className="drop-icon">📂</span>
                <p className="drop-title">Drop Swagger JSON here or click to browse</p>
                <p className="drop-sub">Supports OpenAPI 2.x and 3.x</p>
              </div>
            )}
          </div>

          <div className="divider-or"><span>or paste JSON</span></div>
          <textarea className="json-area" rows={5} placeholder={'{\n  "openapi": "3.0.0",\n  "paths": { ... }\n}'} onChange={onPaste} />

          <label className="field-label" style={{marginTop:20}}>Base URL</label>
          <input className="url-input" type="url" placeholder="https://api.yourapp.com" value={baseUrl} onChange={e => setBaseUrl(e.target.value)} />

          {fileErr && <p className="inline-error">{fileErr}</p>}

          <div className="action-row">
            <button className="btn-generate" onClick={handleGenerate} disabled={genLoading || runLoading}>
              {genLoading ? <><span className="spin"/>Generating…</> : '⚙  Generate Test Cases'}
            </button>
            <button className="btn-run" onClick={handleRun} disabled={runLoading || genLoading}>
              {runLoading ? <><span className="spin"/>Running…</> : '▶  Run Test Cases'}
            </button>
          </div>
        </div>
      </section>

      {preview && !results && (
        <section className="content-section">
          <div className="panel-inner">
            <h2 className="s-heading">Generated Test Cases <span className="count-badge">{preview.total}</span></h2>
            <div className="sev-pills">
              {['critical','high','medium','low'].map(sev => {
                const n = preview.cases.filter(c => c.severity === sev).length
                return n > 0 && <div key={sev} className="sev-pill" style={{borderColor: SEVERITY_COLOR[sev]}}>
                  <span style={{color: SEVERITY_COLOR[sev]}}>{n}</span>
                  <span className="sev-lbl">{sev}</span>
                </div>
              })}
            </div>
            <div className="table-wrap">
              <table className="dtable">
                <thead><tr><th>Method</th><th>Endpoint</th><th>OWASP Category</th><th>Attack Type</th><th>Parameter</th><th>Severity</th></tr></thead>
                <tbody>
                  {preview.cases.map((c,i) => (
                    <tr key={i}>
                      <td><span className={'mbadge ' + c.http_method.toLowerCase()}>{c.http_method}</span></td>
                      <td className="mono">{c.endpoint_path}</td>
                      <td>{OWASP_LABEL[c.owasp_category] || c.owasp_category}</td>
                      <td className="mono dim">{c.attack_type}</td>
                      <td className="mono dim">{c.target_parameter || '—'}</td>
                      <td><span style={{color: SEVERITY_COLOR[c.severity], fontWeight:600}}>{c.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {preview.total > 300 && <p className="table-more">Showing all generated test cases. Scroll to view more.</p>}
            </div>
          </div>
        </section>
      )}

      {runLoading && (
        <section className="content-section">
          <div className="panel-inner">
            <div className="running-block">
              <p className="run-label">Running security tests against <span className="mono">{baseUrl}</span></p>
              <div className="pbar-track"><div className="pbar-fill" style={{width: progress + '%'}}/></div>
              <p className="pbar-pct">{Math.round(progress)}%</p>
              <div className="run-cats">
                {['SQL/NoSQL Injection','Broken Authentication','Broken Access Control','Security Misconfiguration','Input Validation'].map((cat,i) => (
                  <div key={i} className={'rcat' + (progress > (i+1)*18 ? ' done' : progress > i*18 ? ' active' : '')}>
                    <span className="rcat-dot"/>{cat}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {runError && <div className="panel-inner"><p className="inline-error">{runError}</p></div>}

      {results && (
        <section className="content-section">
          <div className="panel-inner">
            <h2 className="s-heading">Analytics Dashboard</h2>
            <div className="analytics-grid">
              <div className="a-card donut-card">
                <p className="a-card-title">Overall</p>
                <Donut passed={results.run.passed} failed={results.run.failed} errors={results.run.errors} total={results.run.total_cases}/>
                <div className="donut-legend">
                  <div className="dl-row"><span className="dl-dot" style={{background:'#4ade80'}}/>Passed<strong>{results.run.passed}</strong></div>
                  <div className="dl-row"><span className="dl-dot" style={{background:'#f43f5e'}}/>Failed<strong>{results.run.failed}</strong></div>
                  <div className="dl-row"><span className="dl-dot" style={{background:'#64748b'}}/>Errors<strong>{results.run.errors}</strong></div>
                </div>
                <p className="a-meta">{results.run.duration_seconds}s · {results.run.total_cases} tests</p>
              </div>

              <div className="a-card">
                <p className="a-card-title">Failures by Severity</p>
                <div className="sev-chart">
                  {['critical','high','medium','low'].map(sev => {
                    const n = results.analytics.by_severity[sev] || 0
                    const max = Math.max(...Object.values(results.analytics.by_severity), 1)
                    return (
                      <div key={sev} className="sev-row">
                        <span className="sev-name" style={{color: SEVERITY_COLOR[sev]}}>{sev}</span>
                        <div className="sev-track"><div className="sev-bar" style={{width: (n/max*100) + '%', background: SEVERITY_COLOR[sev]}}/></div>
                        <span className="sev-n">{n}</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              <div className="a-card">
                <p className="a-card-title">By OWASP Category</p>
                <div className="cat-chart">
                  {Object.entries(results.analytics.by_category).map(([cat, d]) => {
                    const max = Math.max(...Object.values(results.analytics.by_category).map(x=>x.total), 1)
                    return (
                      <div key={cat} className="cat-row">
                        <span className="cat-name">{OWASP_LABEL[cat] || cat}</span>
                        <div className="cat-bars">
                          <div className="cat-bar-pass" style={{width: (d.passed/max*100) + '%'}}/>
                          <div className="cat-bar-fail" style={{width: (d.failed/max*100) + '%'}}/>
                        </div>
                        <span className="cat-nums">{d.passed}P {d.failed}F</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {results.analytics.top_vulnerabilities?.length > 0 && (
                <div className="a-card top-card">
                  <p className="a-card-title">Top Vulnerabilities</p>
                  <div className="vuln-list">
                    {results.analytics.top_vulnerabilities.slice(0,6).map((v,i) => (
                      <div key={i} className="vuln-item">
                        <span className="vuln-sev" style={{color: SEVERITY_COLOR[v.severity], borderColor: SEVERITY_COLOR[v.severity]+'44'}}>{v.severity}</span>
                        <div>
                          <p className="mono vuln-ep">{v.endpoint}</p>
                          <p className="vuln-txt">{v.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="a-card top-card">
                <p className="a-card-title">Stateful Session</p>
                <div className="session-grid">
                  <div><span className="session-k">Email</span><p className="mono">{results.session?.email || 'Not captured'}</p></div>
                  <div><span className="session-k">Register Endpoint</span><p className="mono">{results.session?.register_endpoint || 'Not detected'}</p></div>
                  <div><span className="session-k">Login Endpoint</span><p className="mono">{results.session?.login_endpoint || (results.session?.token ? 'Detected indirectly from token response' : 'Not detected')}</p></div>
                  <div>
                    <span className="session-k">Token</span>
                    <p className="mono">{results.session?.token_masked || 'Not captured'}</p>
                  </div>
                </div>
                <div className="session-actions">
                  <button className="chip active" onClick={copyToken} disabled={!results.session?.token}>Copy Token</button>
                  {copyMsg && <span className="session-copy-msg">{copyMsg}</span>}
                </div>
              </div>
            </div>

            <h2 className="s-heading" style={{marginTop:36}}>Test Results</h2>
            <div className="filters">
              <input className="search-box" placeholder="Search endpoint or attack…" value={search} onChange={e=>setSearch(e.target.value)}/>
              <div className="chip-group">
                {['ALL','PASS','FAIL','ERROR'].map(s => (
                  <button key={s} className={'chip' + (statusFilter===s?' active':'')}
                    style={statusFilter===s&&s!=='ALL'?{background:STATUS_COLOR[s]+'22',color:STATUS_COLOR[s],borderColor:STATUS_COLOR[s]}:{}}
                    onClick={()=>setStatusFilter(s)}>{s}</button>
                ))}
              </div>
              <div className="chip-group">
                <button className={'chip'+(sevFilter==='ALL'?' active':'')} onClick={()=>setSevFilter('ALL')}>All Severity</button>
                {['critical','high','medium','low'].map(s=>(
                  <button key={s} className={'chip'+(sevFilter===s?' active':'')}
                    style={sevFilter===s?{background:SEVERITY_COLOR[s]+'22',color:SEVERITY_COLOR[s],borderColor:SEVERITY_COLOR[s]}:{}}
                    onClick={()=>setSevFilter(s)}>{s}</button>
                ))}
              </div>
              <div className="chip-group">
                <button className={'chip'+(catFilter==='ALL'?' active':'')} onClick={()=>setCatFilter('ALL')}>All Categories</button>
                {cats.map(c=>(
                  <button key={c} className={'chip'+(catFilter===c?' active':'')} onClick={()=>setCatFilter(c)}>
                    {(OWASP_LABEL[c]||c).split(' ').slice(0,2).join(' ')}
                  </button>
                ))}
              </div>
            </div>
            <p className="results-meta">{filtered.length} results</p>

            <div className="result-rows">
              {filtered.map(r => {
                const status = r.result?.result_status || 'ERROR'
                const open = expandedId === r.id
                return (
                  <div key={r.id} className={'rrow ' + status.toLowerCase() + (open?' open':'')}>
                    <div className="rrow-head" onClick={() => setExpandedId(open ? null : r.id)}>
                      <span className="rrow-dot" style={{background: STATUS_COLOR[status]}}/>
                      <span className={'mbadge '+r.http_method.toLowerCase()}>{r.http_method}</span>
                      <span className="rrow-path mono">{r.endpoint_path}</span>
                      <span className="rrow-attack mono">{r.attack_type}</span>
                      <span className="rrow-outcome" style={{color: getOutcomeColor(r)}}>{getOutcomeLabel(r)}</span>
                      {r.result?.http_status_code > 0 && <span className="rrow-code">{r.result.http_status_code}</span>}
                      {r.result?.response_time_ms && <span className="rrow-ms">{Math.round(r.result.response_time_ms)}ms</span>}
                      <span className="rrow-chev">{open?'▲':'▼'}</span>
                    </div>
                    {open && (
                      <div className="rrow-detail">
                        <div className="detail-cols">
                          <div className="dc"><h5>OWASP Category</h5><p>{OWASP_LABEL[r.owasp_category]||r.owasp_category}</p></div>
                          <div className="dc"><h5>Target Parameter</h5><p className="mono">{r.target_parameter||'—'}</p></div>
                          <div className="dc">
                            <h5>Payload</h5>
                            <button className="payload-btn" onClick={(e) => { e.stopPropagation(); openPayloadModal(r) }}>
                              View Payload
                            </button>
                          </div>
                          <div className="dc"><h5>HTTP Status</h5><p className="mono">{r.result?.http_status_code??'—'}</p></div>
                        </div>
                        {status==='FAIL'&&r.result?.vulnerability_detail&&(
                          <div className="vuln-alert">
                            <span>🚨</span>
                            <div><h5>Vulnerability Found</h5><p>{r.result.vulnerability_detail}</p></div>
                          </div>
                        )}
                        {status==='FAIL'&&r.result?.recommendation&&(
                          <div className="rec-block">
                            <span>💡</span>
                            <div><h5>Recommendation</h5><p>{r.result.recommendation}</p></div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
              {filtered.length===0&&<p className="empty-msg">No results match the current filters.</p>}
            </div>
          </div>
        </section>
      )}
    </div>
    {payloadModal.open && (
      <div className="payload-modal-backdrop" onClick={() => setPayloadModal({ open: false, title: '', body: '' })}>
        <div className="payload-modal" onClick={(e) => e.stopPropagation()}>
          <div className="payload-modal-head">
            <div>
              <p className="payload-modal-title">Payload Details</p>
              <p className="mono payload-modal-sub">{payloadModal.title}</p>
            </div>
            <button className="clear-btn" onClick={() => setPayloadModal({ open: false, title: '', body: '' })}>Close</button>
          </div>
          <pre className="payload-pre mono">{payloadModal.body}</pre>
        </div>
      </div>
    )}
    </>
  )
}