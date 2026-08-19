#!/usr/bin/env python3
"""
Browser front end for esx_beacon_ies.py.

Runs a small local server and opens your default browser. Nothing is uploaded
and nothing leaves the machine — the server binds to 127.0.0.1 only and reads
the .esx straight off disk.

This exists instead of a tkinter window because Apple's bundled Python ships
Tcl/Tk 8.5, which renders blank windows on current macOS. The browser is
always available and always renders.

Usage
    python3 esx_beacon_web.py [optional/path/to/survey.esx]

Standard library only. Keep esx_beacon_ies.py in the same folder.
"""
import base64
import collections
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = secrets.token_urlsafe(16)
CACHE = {}
CACHE_LOCK = threading.Lock()


def load_decoder():
    """Return the esx_beacon_ies module, however this program is being run.

    A plain import covers both loose scripts (the script's own directory is
    first on sys.path) and frozen builds, where PyInstaller bundles the module
    rather than shipping a .py file to sit beside us. The path lookup is the
    fallback for the case where neither applies — running from a symlink, say,
    or importing this file from somewhere else.
    """
    try:
        import esx_beacon_ies
        return esx_beacon_ies
    except ImportError:
        pass

    search = [HERE]
    bundled = getattr(sys, "_MEIPASS", None)        # PyInstaller extraction dir
    if bundled:
        search.insert(0, bundled)
    for folder in search:
        path = os.path.join(folder, "esx_beacon_ies.py")
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location("esx_beacon_ies", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise ImportError("esx_beacon_ies.py must sit next to this file (looked in %s)"
                      % ", ".join(search))


DEC = load_decoder()


def survey_path(path):
    return DEC.resolve_esx_path(path)


def _capture_rank(s):
    return (1 if s["tpc"] is not None else 0, s["ie_count"])


def decode_survey(path):
    """Parse every beacon in a survey. Cached per path+mtime."""
    path = survey_path(path)
    key = (path, os.path.getmtime(path))
    with CACHE_LOCK:
        if key in CACHE:
            return CACHE[key]

    measurements = DEC.load(path)
    captured, counts, radios = [], collections.Counter(), set()
    for m in measurements:
        blob = m.get("informationElements")
        if not blob:
            continue
        try:
            body = base64.b64decode(blob)
        except (ValueError, TypeError):
            continue
        ies = DEC.parse_ies(body)
        s = DEC.summarise(m, ies)
        s["id"] = "%s|%s" % (s["bssid"], s["freq"])
        counts.update({e for e, _ in ies})
        radios.add(s["bssid"])
        captured.append((s, m, body, ies))

    captured.sort(key=lambda item: _capture_rank(item[0]), reverse=True)
    rows = [s for s, _m, _b, _ies in captured]
    raw = {}
    for s, m, body, ies in captured:
        raw.setdefault(s["id"], (m, body, ies))

    total = len(rows)
    summary = [
        {"id": eid, "name": DEC.IE_NAMES.get(eid, "(unrecognised)"), "count": n,
         "share": round(100 * n / max(total, 1), 1)}
        for eid, n in counts.most_common()
    ]
    real, placeholder = {}, {}
    for _rid, (m, _b, ies) in raw.items():
        s = DEC.summarise(m, ies)
        if s["tpc"] is not None:
            real[s["bssid"]] = {"power": s["tpc"], "ssid": s["ssid"]}
        elif any(eid == 35 and v and DEC.signed(v[0]) == 63 for eid, v in ies):
            placeholder[s["bssid"]] = s["ssid"]
    placeholder = {k: v for k, v in placeholder.items() if k not in real}

    payload = {
        "rows": rows,
        "summary": summary,
        "total": total,
        "radios": len(radios),
        "txpower": sorted(
            ({"bssid": k, **v} for k, v in real.items()),
            key=lambda d: -d["power"]),
        "placeholders": [{"bssid": k, "ssid": v} for k, v in sorted(placeholder.items())],
        "file": os.path.basename(path),
    }
    with CACHE_LOCK:
        CACHE.clear()           # only ever hold one survey
        CACHE[key] = (payload, raw)
    return payload, raw


POWERSHELL_PICKER = r"""
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title  = 'Choose an Ekahau survey'
$d.Filter = 'Ekahau survey (*.esx)|*.esx|All files (*.*)|*.*'
$top = New-Object System.Windows.Forms.Form
$top.TopMost = $true
if ($d.ShowDialog($top) -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($d.FileName)
}
"""

APPLESCRIPT_PICKER = (
    'tell application "System Events" to activate\n'
    'POSIX path of (choose file with prompt "Choose an Ekahau survey"{})'
)


def _run(cmd, timeout=600):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def native_file_picker():
    """Ask the OS for a file path, so the page gets a real path not an upload.

    Returns None when the user cancels or no dialog helper is available; the
    page then falls back to typing a path in by hand.
    """
    if sys.platform == "darwin":
        p = _run(["osascript", "-e", APPLESCRIPT_PICKER.format(' of type {"esx"}')])
        if p is None:
            return None
        if p.returncode != 0:
            if "User canceled" in (p.stderr or ""):
                return None
            # some macOS builds reject the type filter - retry without it
            p = _run(["osascript", "-e", APPLESCRIPT_PICKER.format("")])
            if p is None or p.returncode != 0:
                return None
        return p.stdout.strip() or None

    if os.name == "nt":
        for exe in ("powershell", "pwsh"):
            p = _run([exe, "-NoProfile", "-NonInteractive", "-STA",
                      "-Command", POWERSHELL_PICKER])
            if p is not None and p.returncode == 0:
                return p.stdout.strip() or None
        return None

    for cmd in (["zenity", "--file-selection", "--title=Choose an Ekahau survey"],
                ["kdialog", "--getopenfilename", ".", "*.esx"]):
        if shutil.which(cmd[0]):
            p = _run(cmd)
            if p is not None and p.returncode == 0:
                return p.stdout.strip() or None
    return None


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Ekahau beacon element viewer</title>
<style>
:root{
  --bg:#f5f5f7; --panel:#fff; --line:#d8d8dc; --ink:#1d1d1f; --dim:#6e6e73;
  --accent:#0b6bcb; --warn:#8a5a00; --ok:#1a7f37;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:13px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",sans-serif}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:14px 20px}
h1{margin:0 0 10px;font-size:15px;font-weight:600}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
input[type=text]{flex:1;min-width:240px;padding:6px 9px;border:1px solid var(--line);
  border-radius:6px;font:inherit;background:#fff}
input[type=text].sm{flex:0 0 170px;min-width:0}
select{padding:6px 8px;border:1px solid var(--line);border-radius:6px;font:inherit;background:#fff}
button{padding:6px 13px;border:1px solid var(--line);border-radius:6px;background:#fff;
  font:inherit;cursor:pointer}
button:hover{background:#f0f0f2}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{filter:brightness(1.08)}
.panel{background:var(--panel);border-bottom:1px solid var(--line);padding:11px 20px}
.lbl{color:var(--dim);font-size:12px;margin-right:2px}
fieldset{border:0;margin:0;padding:0;display:flex;gap:18px;flex-wrap:wrap}
label.cb{display:flex;gap:6px;align-items:center;cursor:pointer;user-select:none}
#status{padding:8px 20px;color:var(--dim);font-size:12px;
  border-bottom:1px solid var(--line);background:var(--panel)}
nav{display:flex;gap:4px;padding:10px 20px 0}
nav button{border-radius:6px 6px 0 0;border-bottom:none}
nav button.on{background:var(--panel);font-weight:600}
main{padding:0 20px 24px}
.tab{display:none;background:var(--panel);border:1px solid var(--line);border-radius:0 8px 8px 8px}
.tab.on{display:block}
.scroll{overflow:auto;max-height:calc(100vh - 330px)}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #eee;white-space:nowrap}
th{position:sticky;top:0;background:#fafafa;cursor:pointer;font-weight:600;
  border-bottom:1px solid var(--line);z-index:1}
th:hover{background:#f0f0f2}
th .ar{color:var(--accent);margin-left:4px}
td.num,th.num{text-align:right}
tbody tr{cursor:pointer}
tbody tr:hover{background:#eef5fd}
tbody tr.sel{background:#dcebfb}
.dim{color:#bbb}
.note{padding:14px 20px;color:var(--dim)}
.warn{color:var(--warn)} .ok{color:var(--ok)}
.empty{padding:44px 20px;text-align:center;color:var(--dim)}

/* header strip above a table: a few labelled facts, not a table itself */
.meta{display:flex;flex-wrap:wrap;gap:22px;padding:13px 20px;
  border-bottom:1px solid var(--line);background:#fcfcfd}
.meta .kv{display:flex;flex-direction:column;gap:1px;min-width:0}
.meta .k{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.04em}
.meta .v{font-weight:600}
.meta .v.mono{font-family:"SF Mono",Menlo,monospace;font-weight:500}

.sect{padding:14px 20px 8px;font-weight:600;border-top:1px solid var(--line)}
.sect .n{font-weight:400;color:var(--dim);margin-left:6px}

/* proportion bar behind the share figure in the element table */
.bar{position:relative;min-width:120px}
.bar i{position:absolute;left:0;top:50%;transform:translateY(-50%);height:13px;
  background:#dbe9fb;border-radius:2px}
.bar span{position:relative;padding-left:6px}

.b64{margin:0 20px 18px;padding:11px 13px;border:1px solid var(--line);border-radius:6px;
  background:#fafafa;font:11px/1.55 "SF Mono",Menlo,monospace;color:#444;
  word-break:break-all;max-height:132px;overflow:auto;user-select:all}
.rowsub{color:var(--dim)}
td.wrap{white-space:normal}

/* these tables are for reading, not sorting or selecting */
table.static th{cursor:default}
table.static th:hover{background:#fafafa}
table.static tbody tr{cursor:default}
table.static tbody tr:hover{background:#fafbfc}
</style></head><body>

<header>
  <h1>Ekahau beacon element viewer</h1>
  <div class="row">
    <input type="text" id="path" placeholder="Path to an .esx survey, or click Browse">
    <button id="browse">Browse…</button>
    <button class="primary" id="go">Analyse</button>
  </div>
</header>

<div class="panel">
  <div class="row">
    <span class="lbl">SSID contains</span><input type="text" class="sm" id="f_ssid">
    <span class="lbl">BSSID starts with</span><input type="text" class="sm" id="f_bssid"
      placeholder="e.g. f8:e7:1e">
    <span class="lbl">Band</span>
    <select id="f_band"><option>All bands</option><option>2.4 GHz</option>
      <option>5 GHz</option><option>6 GHz</option></select>
    <label class="cb"><input type="checkbox" id="f_uniq" checked> One row per radio</label>
  </div>
</div>

<div class="panel">
  <fieldset id="groups">
    <label class="cb"><input type="checkbox" data-g="security" checked> Security and standards</label>
    <label class="cb"><input type="checkbox" data-g="power" checked> Transmit power</label>
    <label class="cb"><input type="checkbox" data-g="load" checked> Channel load</label>
    <label class="cb"><input type="checkbox" data-g="roaming"> Roaming (802.11k/v/r)</label>
    <label class="cb"><input type="checkbox" data-g="vendor"> Vendor elements</label>
    <label class="cb"><input type="checkbox" data-g="count"> Element count</label>
    <button id="csv">Export CSV</button>
    <button id="quit">Quit</button>
  </fieldset>
</div>

<div id="status">Choose an .esx file to begin.</div>

<nav>
  <button class="on" data-t="t_aps">Access points</button>
  <button data-t="t_sum">Element summary</button>
  <button data-t="t_raw">Raw elements</button>
</nav>
<main>
  <div class="tab on" id="t_aps"><div class="scroll"><table>
    <thead><tr id="head"></tr></thead><tbody id="body"></tbody></table>
    <div class="empty" id="empty">No survey loaded yet.</div></div></div>
  <div class="tab" id="t_sum">
    <div class="empty" id="sum_empty">Analyse a survey to see which information elements it contains.</div>
    <div id="sum_body" hidden>
      <div class="meta" id="sum_meta"></div>
      <div class="scroll" id="sum_elements"></div>
      <div id="sum_power"></div>
    </div>
  </div>
  <div class="tab" id="t_raw">
    <div class="empty" id="raw_empty">Click any access point to see its full decoded element list.</div>
    <div id="raw_body" hidden>
      <div class="meta" id="raw_meta"></div>
      <div class="scroll" id="raw_elements"></div>
      <div class="sect">As stored by Ekahau</div>
      <div class="b64" id="raw_b64"></div>
    </div>
  </div>
</main>

<script>
const TOKEN = new URLSearchParams(location.search).get('t') || '';
const COLS = [
  ['ssid','SSID',null,0],['bssid','BSSID',null,0],['band','Band',null,0],['channel','Ch',null,1],
  ['security','Security','security',0],['technologies','802.11','security',0],
  ['tpc','TX power','power',1],['country_max','Regulatory max','power',1],
  ['vht_max','VHT max EIRP','power',1],
  ['stations','Clients','load',1],['utilisation','Ch. util','load',1],
  ['dot11k','11k','roaming',0],['dot11v','11v','roaming',0],['dot11r','11r','roaming',0],
  ['vendors','Vendor OUIs','vendor',0],['ie_count','IEs','count',1],
];
let DATA = null, view = [], sortKey = null, sortDesc = false, selected = null;
const $ = id => document.getElementById(id);
const on = g => document.querySelector('[data-g="'+g+'"]').checked;
const cols = () => COLS.filter(c => !c[2] || on(c[2]));
const escAttr = s => String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;');

function fmt(k, v){
  if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length))
    return '<span class="dim">—</span>';
  if (k==='dot11k'||k==='dot11v'||k==='dot11r') return v ? 'yes' : '<span class="dim">—</span>';
  if (k==='tpc'||k==='country_max') return v+' dBm';
  if (k==='vht_max') return v+' dBm';
  if (k==='utilisation') return v+'%';
  if (Array.isArray(v)) return v.join(', ');
  return String(v).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
}

function applyFilters(){
  if (!DATA) return;
  const ss = $('f_ssid').value.trim().toLowerCase();
  const bs = $('f_bssid').value.trim().toLowerCase();
  const bd = $('f_band').value, uq = $('f_uniq').checked;
  const seen = new Set(); view = [];
  for (const r of DATA.rows){
    if (ss && !(r.ssid||'').toLowerCase().includes(ss)) continue;
    if (bs && !(r.bssid||'').toLowerCase().startsWith(bs)) continue;
    if (bd !== 'All bands' && r.band !== bd) continue;
    if (uq){ if (seen.has(r.id)) continue; seen.add(r.id); }
    view.push(r);
  }
  if (sortKey) sortRows();
  render();
}

function sortRows(){
  const k = sortKey;
  const blank = v => v===null||v===undefined||v===''||(Array.isArray(v)&&!v.length);
  const present = view.filter(r => !blank(r[k])), gone = view.filter(r => blank(r[k]));
  present.sort((a,b)=>{
    let x=a[k], y=b[k];
    if (Array.isArray(x)) { x=x.join(); y=y.join(); }
    if (typeof x==='boolean') { x=x?1:0; y=y?1:0; }
    if (typeof x==='number' && typeof y==='number') return sortDesc ? y-x : x-y;
    x=String(x).toLowerCase(); y=String(y).toLowerCase();
    return sortDesc ? (x<y?1:x>y?-1:0) : (x>y?1:x<y?-1:0);
  });
  view = present.concat(gone);     // unknowns always sink
}

function render(){
  const cs = cols();
  $('head').innerHTML = cs.map(c =>
    '<th class="'+(c[3]?'num':'')+'" data-k="'+c[0]+'">'+c[1]+
    (sortKey===c[0] ? '<span class="ar">'+(sortDesc?'▾':'▴')+'</span>' : '')+'</th>').join('');
  $('body').innerHTML = view.map(r =>
    '<tr data-id="'+escAttr(r.id)+'"'+(r.id===selected?' class="sel"':'')+'>'+
    cs.map(c => '<td class="'+(c[3]?'num':'')+'">'+fmt(c[0], r[c[0]])+'</td>').join('')+
    '</tr>').join('');
  $('empty').style.display = view.length ? 'none' : 'block';
  if (DATA && !view.length) $('empty').textContent = 'No access points match these filters.';
  $('head').querySelectorAll('th').forEach(th => th.onclick = () => {
    const k = th.dataset.k;
    if (sortKey === k) sortDesc = !sortDesc; else { sortKey = k; sortDesc = false; }
    sortRows(); render();
  });
  $('body').querySelectorAll('tr').forEach(tr => tr.onclick = () => showRaw(tr.dataset.id));
}

async function analyse(){
  const p = $('path').value.trim();
  if (!p) return;
  $('status').textContent = 'Decoding…';
  let r;
  try {
    r = await fetch('/api/analyse?t='+TOKEN, {method:'POST',
        headers:{'Content-Type':'application/json'}, body: JSON.stringify({path:p})});
  } catch(e){ $('status').textContent = 'Server unreachable — the app may have quit.'; return; }
  if (!r.ok){ $('status').textContent = 'Error: '+(await r.text()); return; }
  DATA = await r.json();
  sortKey = null; selected = null;
  applyFilters();
  buildSummary();
  const st = $('status');
  st.textContent = '';
  const b = document.createElement('b');
  b.textContent = DATA.file;
  st.append(b, document.createTextNode(' — '+DATA.total.toLocaleString()+
    ' beacon captures from '+DATA.radios.toLocaleString()+' radios'));
}

// Everything below builds DOM nodes and sets textContent rather than assembling
// HTML strings, so decoded beacon text can never be parsed as markup.
function el(tag, cls, text){
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

function fillMeta(node, pairs){
  node.replaceChildren();
  for (const [k, v, mono] of pairs){
    if (v === null || v === undefined || v === '') continue;
    const kv = el('div','kv');
    kv.append(el('div','k',k), el('div','v'+(mono ? ' mono' : ''), v));
    node.append(kv);
  }
}

function staticTable(headers, rows){
  const t = el('table','static');
  const tr = el('tr');
  for (const h of headers) tr.append(el('th', h.num ? 'num' : '', h.label));
  const thead = el('thead');
  thead.append(tr);
  t.append(thead);
  const tb = el('tbody');
  for (const r of rows){
    const row = el('tr');
    r.forEach((cell, i) => {
      const td = el('td', [headers[i].num && 'num', headers[i].wrap && 'wrap']
                          .filter(Boolean).join(' '));
      if (cell instanceof Node) td.append(cell); else td.textContent = cell;
      row.append(td);
    });
    tb.append(row);
  }
  t.append(tb);
  return t;
}

function sect(title, count){
  const s = el('div','sect', title);
  if (count !== undefined) s.append(el('span','n', count));
  return s;
}

function scrolled(node){
  const d = el('div','scroll');
  d.append(node);
  return d;
}

function shareBar(share){
  const bar = el('div','bar');
  const fill = el('i');
  fill.style.width = Math.max(0, Math.min(100, share)) + '%';
  bar.append(fill, el('span', share.toFixed(1) + '%'));
  return bar;
}

function buildSummary(){
  fillMeta($('sum_meta'), [
    ['Survey', DATA.file],
    ['Beacon captures', DATA.total.toLocaleString()],
    ['Distinct radios', DATA.radios.toLocaleString()],
    ['Element types', String(DATA.summary.length)],
  ]);

  $('sum_elements').replaceChildren(staticTable(
    [{label:'ID', num:true}, {label:'Element'}, {label:'Captures', num:true}, {label:'Share'}],
    DATA.summary.map(e => [
      String(e.id),
      e.name,
      e.count.toLocaleString(),
      shareBar(e.share),
    ])));

  const power = document.createDocumentFragment();
  if (DATA.txpower.length){
    power.append(sect('Radios reporting a usable transmit power', DATA.txpower.length));
    power.append(scrolled(staticTable(
      [{label:'TX power', num:true}, {label:'BSSID'}, {label:'SSID'}],
      DATA.txpower.map(t => [t.power + ' dBm', t.bssid, t.ssid || '—']))));
  } else {
    power.append(sect('Transmit power'));
    power.append(el('div','note',
      'No radio in this survey reports a usable transmit power. It is not '
      + 'recoverable from these beacons — the Regulatory max column is the legal '
      + 'ceiling for the channel, not a configured level. Get real values from '
      + 'the WLAN controller.'));
  }
  if (DATA.placeholders.length){
    power.append(sect('Ignored: reporting the 63 dBm placeholder', DATA.placeholders.length));
    power.append(scrolled(staticTable(
      [{label:'BSSID'}, {label:'SSID'}],
      DATA.placeholders.map(p => [p.bssid, p.ssid || '—']))));
  }
  $('sum_power').replaceChildren(power);

  $('sum_empty').hidden = true;
  $('sum_body').hidden = false;
}

async function showRaw(id){
  selected = id; render();
  document.querySelector('[data-t="t_raw"]').click();
  $('raw_body').hidden = true;
  $('raw_empty').hidden = false;
  $('raw_empty').textContent = 'Loading…';

  let r;
  try {
    r = await fetch('/api/raw?t='+TOKEN+'&path='+encodeURIComponent($('path').value.trim())+
                    '&id='+encodeURIComponent(id));
  } catch(e){ $('raw_empty').textContent = 'Server unreachable.'; return; }
  if (!r.ok){ $('raw_empty').textContent = 'Could not load: '+(await r.text()); return; }
  const d = await r.json();

  fillMeta($('raw_meta'), [
    ['SSID', d.ssid || '(hidden)'],
    ['BSSID', d.bssid, true],
    ['Channels', (d.channels || []).join(', '), true],
    ['Security', d.security],
    ['Beacon body', d.bytes + ' bytes'],
    ['Elements', String(d.count)],
  ]);

  $('raw_elements').replaceChildren(staticTable(
    [{label:'ID', num:true}, {label:'Element'}, {label:'Len', num:true},
     {label:'Value', wrap:true}],
    d.elements.map(e => [
      String(e.id),
      e.known ? e.name : el('span','rowsub', e.name),
      String(e.len),
      e.value,
    ])));

  $('raw_b64').textContent = d.base64;
  $('raw_empty').hidden = true;
  $('raw_body').hidden = false;
}

$('browse').onclick = async () => {
  $('status').textContent = 'Waiting for the file dialog…';
  const r = await fetch('/api/browse?t='+TOKEN);
  const p = (await r.text()).trim();
  if (p){ $('path').value = p; analyse(); }
  else $('status').textContent =
    'No file chosen. If no dialog appeared, paste the full path to the .esx above instead.';
};
$('go').onclick = analyse;
$('path').addEventListener('keydown', e => { if (e.key === 'Enter') analyse(); });
['f_ssid','f_bssid'].forEach(i => $(i).addEventListener('input', applyFilters));
['f_band','f_uniq'].forEach(i => $(i).addEventListener('change', applyFilters));
$('groups').addEventListener('change', e => { if (e.target.dataset.g) render(); });
document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
  b.classList.add('on'); $(b.dataset.t).classList.add('on');
});
$('csv').onclick = () => {
  if (!view.length) return;
  const cs = cols();
  const esc = s => /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s;
  const strip = h => h.replace(/<[^>]*>/g,'').replace('—','');
  const out = [cs.map(c=>c[1]).join(',')].concat(
    view.map(r => cs.map(c => esc(strip(fmt(c[0], r[c[0]])))).join(','))).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([out], {type:'text/csv'}));
  a.download = 'beacon_elements.csv'; a.click();
};
$('quit').onclick = async () => {
  await fetch('/api/quit?t='+TOKEN).catch(()=>{});
  document.body.innerHTML = '<p class="note">Stopped. You can close this tab.</p>';
};
const boot = new URLSearchParams(location.search).get('open');
if (boot){ $('path').value = boot; analyse(); }
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "EkahauBeaconViewer/1.0"

    def log_message(self, *_args):
        pass                                    # keep the console quiet

    # ------------------------------------------------------------- helpers
    def _authed(self, q):
        return q.get("t", [""])[0] == TOKEN

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        parts = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parts.query)

        if parts.path == "/":
            if not self._authed(q):
                self._send(403, "Open this page from the link the app printed.")
                return
            self._send(200, PAGE, "text/html; charset=utf-8")
            return

        if not self._authed(q):
            self._send(403, "bad token")
            return

        if parts.path == "/api/browse":
            self._send(200, native_file_picker() or "")
            return

        if parts.path == "/api/raw":
            path = survey_path(q.get("path", [""])[0])
            rid = q.get("id", [""])[0]
            if not os.path.exists(path):
                self._send(400, "file not found")
                return
            try:
                _payload, raw = decode_survey(path)
            except Exception as exc:                      # noqa: BLE001
                self._send(500, str(exc))
                return
            entry = raw.get(rid)
            if not entry:
                self._send(404, "no such access point in this survey")
                return
            m, body, ies = entry
            payload = {
                "ssid": m.get("ssid") or "",
                "bssid": m.get("mac") or "",
                "channels": m.get("channelByCenterFrequencyDefinedNarrowChannels") or [],
                "security": m.get("security") or "",
                "bytes": len(body),
                "count": len(ies),
                "elements": [
                    {"id": eid,
                     "name": DEC.IE_NAMES.get(eid, "(unrecognised)"),
                     "known": eid in DEC.IE_NAMES,
                     "len": len(v),
                     "value": DEC.describe(eid, v)}
                    for eid, v in ies
                ],
                "base64": m.get("informationElements", ""),
            }
            self._send(200, json.dumps(payload), "application/json; charset=utf-8")
            return

        if parts.path == "/api/quit":
            self._send(200, "stopping")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self._send(404, "not found")

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        parts = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parts.query)
        if not self._authed(q):
            self._send(403, "bad token")
            return
        if parts.path != "/api/analyse":
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._send(400, "bad request")
            return
        path = survey_path(req.get("path") or "")
        if not path or not os.path.exists(path):
            self._send(400, "No file at: %s" % path)
            return
        try:
            payload, _raw = decode_survey(path)
        except Exception as exc:                          # noqa: BLE001
            self._send(400, "Could not read that survey: %s" % exc)
            return
        self._send(200, json.dumps(payload), "application/json; charset=utf-8")


def main():
    args = [a for a in sys.argv[1:] if a != "--no-browser"]
    quiet = "--no-browser" in sys.argv or os.environ.get("EKAHAU_NO_BROWSER")

    initial = ""
    if args:
        opened = survey_path(args[0])
        if os.path.exists(opened):
            initial = "&open=" + urllib.parse.quote(opened)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = "http://127.0.0.1:%d/?t=%s%s" % (port, TOKEN, initial)
    print("Ekahau beacon element viewer")
    print("  serving on %s" % url)
    print("  close the browser tab and press Ctrl-C here, or click Quit in the page.")
    sys.stdout.flush()
    if not quiet:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
