/* DeepInsight - App Controller (redesigned) */
document.addEventListener('DOMContentLoaded', () => {

    // ─── State ───────────────────────────────────────────
    let currentUploadedFilename = '';
    let currentFilteredFilename = '';
    let activeFlowsData = [];
    let appChartInst = null;

    const rulesState = {
        blockedIps:     ['192.168.1.50'],
        blockedApps:    ['YOUTUBE'],
        blockedDomains: []
    };

    // App icons / color palette for cards
    const APP_META = {
        YouTube:    { icon: 'YT', color: '#FF0000', bg: '#FEE2E2' },
        Netflix:    { icon: 'NF', color: '#E50914', bg: '#FEE2E2' },
        Google:     { icon: 'GG', color: '#4285F4', bg: '#DBEAFE' },
        Facebook:   { icon: 'FB', color: '#1877F2', bg: '#DBEAFE' },
        Instagram:  { icon: 'IG', color: '#E1306C', bg: '#FCE7F3' },
        'Twitter/X':{ icon: 'X',  color: '#000000', bg: '#F3F4F6' },
        Amazon:     { icon: 'AZ', color: '#FF9900', bg: '#FEF3C7' },
        Microsoft:  { icon: 'MS', color: '#00A4EF', bg: '#E0F2FE' },
        Apple:      { icon: 'AP', color: '#555555', bg: '#F3F4F6' },
        WhatsApp:   { icon: 'WA', color: '#25D366', bg: '#DCFCE7' },
        Telegram:   { icon: 'TG', color: '#2CA5E0', bg: '#E0F2FE' },
        TikTok:     { icon: 'TT', color: '#010101', bg: '#F3F4F6' },
        Spotify:    { icon: 'SP', color: '#1DB954', bg: '#DCFCE7' },
        Zoom:       { icon: 'ZM', color: '#2D8CFF', bg: '#DBEAFE' },
        Discord:    { icon: 'DS', color: '#5865F2', bg: '#EEF2FF' },
        GitHub:     { icon: 'GH', color: '#333333', bg: '#F3F4F6' },
        Cloudflare: { icon: 'CF', color: '#F38020', bg: '#FEF3C7' },
        DNS:        { icon: 'DNS', color: '#6C63FF', bg: '#EAE8FF' },
        HTTP:       { icon: 'HTTP', color: '#10B981', bg: '#DCFCE7' },
        HTTPS:      { icon: 'HTTPS', color: '#6C63FF', bg: '#EAE8FF' },
        Unknown:    { icon: '??', color: '#9CA3AF', bg: '#F3F4F6' },
    };

    // ─── Utility ─────────────────────────────────────────
    const $ = id => document.getElementById(id);

    function showToast(msg, type = '') {
        const toast = $('toast');
        $('toast-message').textContent = msg;
        toast.className = `toast ${type} show`;
        setTimeout(() => toast.classList.remove('show'), 3500);
    }

    function formatBytes(b) {
        if (b > 1024 * 1024) return `${(b / 1048576).toFixed(1)} MB`;
        if (b > 1024) return `${(b / 1024).toFixed(1)} KB`;
        return `${b} B`;
    }

    // ─── Tab Navigation ──────────────────────────────────
    const navItems = document.querySelectorAll('.nav-item[data-tab]');
    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            switchTab(item.dataset.tab);
        });
    });

    function switchTab(name) {
        document.querySelectorAll('.nav-item[data-tab]').forEach(i =>
            i.classList.toggle('active', i.dataset.tab === name));
        document.querySelectorAll('.tab-pane').forEach(p =>
            p.classList.toggle('active', p.id === `tab-${name}`));
        if (name === 'rules') renderRulesUI();
    }

    // ─── Empty state shortcuts ───────────────────────────
    $('empty-upload-btn').addEventListener('click', () => $('pcap-file-input').click());
    $('empty-sim-btn').addEventListener('click', () => switchTab('simulator'));

    // ─── Hero / Upload ───────────────────────────────────
    $('hero-upload-btn').addEventListener('click', () => $('pcap-file-input').click());

    $('pcap-file-input').addEventListener('change', e => {
        if (e.target.files[0]) handleFile(e.target.files[0]);
    });

    // Drag-drop on whole dashboard tab
    const dashTab = $('tab-dashboard');
    dashTab.addEventListener('dragover', e => { e.preventDefault(); dashTab.style.outline = '2px dashed #6C63FF'; });
    dashTab.addEventListener('dragleave', () => { dashTab.style.outline = ''; });
    dashTab.addEventListener('drop', e => {
        e.preventDefault();
        dashTab.style.outline = '';
        if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
    });

    function handleFile(file) {
        if (!file.name.endsWith('.pcap')) {
            showToast('Only .pcap files are supported', 'error'); return;
        }
        uploadFile(file);
    }

    function uploadFile(file) {
        $('empty-state').style.display = 'none';
        $('dashboard-results').style.display = 'none';
        $('upload-progress-bar').style.display = 'block';
        $('upload-status-label').textContent = `Uploading ${file.name}…`;

        const formData = new FormData();
        formData.append('pcap', file);
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/upload', true);

        xhr.upload.addEventListener('progress', e => {
            if (e.lengthComputable) {
                const pct = Math.round(e.loaded / e.total * 100);
                $('prog-fill').style.width = pct + '%';
                $('progress-pct').textContent = pct + '%';
            }
        });

        xhr.onload = () => {
            if (xhr.status === 200) {
                const res = JSON.parse(xhr.responseText);
                currentUploadedFilename = res.filename;
                $('upload-status-label').textContent = 'Analyzing packets…';
                runAnalysis(res.filename);
            } else {
                showToast('Upload failed', 'error');
                $('upload-progress-bar').style.display = 'none';
                $('empty-state').style.display = 'block';
            }
        };

        xhr.onerror = () => {
            showToast('Network error during upload', 'error');
            $('upload-progress-bar').style.display = 'none';
            $('empty-state').style.display = 'block';
        };

        xhr.send(formData);
    }

    // ─── Analysis ────────────────────────────────────────
    function runAnalysis(filename) {
        fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename, rules: rulesState })
        })
        .then(r => { if (!r.ok) throw new Error(); return r.json(); })
        .then(data => {
            currentFilteredFilename = data.filteredFilename;
            $('upload-progress-bar').style.display = 'none';
            showResults(data);
            showToast('Analysis complete!', 'success');
        })
        .catch(() => {
            showToast('Analysis engine error', 'error');
            $('upload-progress-bar').style.display = 'none';
            $('empty-state').style.display = 'block';
        });
    }

    $('re-analyze-btn').addEventListener('click', () => {
        if (currentUploadedFilename) {
            $('upload-progress-bar').style.display = 'block';
            $('upload-status-label').textContent = 'Re-analyzing…';
            runAnalysis(currentUploadedFilename);
        }
    });

    // ─── Show Results ─────────────────────────────────────
    function showResults(data) {
        const sum = data.summary;
        $('empty-state').style.display = 'none';
        $('dashboard-results').style.display = 'block';
        $('re-analyze-btn').style.display = 'flex';

        // Stats cards
        $('stat-total-packets').textContent = sum.total_packets.toLocaleString();
        $('stat-active-flows').textContent  = sum.active_flows.toLocaleString();
        $('stat-forwarded').textContent     = sum.forwarded_packets.toLocaleString();
        $('stat-dropped').textContent       = sum.dropped_packets.toLocaleString();

        // Right panel ring
        const pct = sum.total_packets > 0
            ? Math.round(sum.dropped_packets / sum.total_packets * 100) : 0;
        const circumference = 213.6;
        const offset = circumference - (pct / 100) * circumference;
        $('block-ring').style.strokeDashoffset = offset;
        $('block-pct').textContent = pct + '% blocked';
        $('user-card-status').textContent =
            `${sum.active_flows} flows tracked. ${sum.dropped_packets} packets blocked.`;

        // App flow cards
        renderAppCards(data.app_breakdown);

        // Flow count badge
        $('flow-count-badge').textContent = `${data.flows.length} flows`;

        // Table
        activeFlowsData = data.flows;
        renderFlowsTable(data.flows);

        // Right panel chart
        renderAppChart(data.app_breakdown);

        // Right panel domains list
        renderDomainsList(data.flows);

        // Download button
        $('download-filtered-btn').onclick = () => {
            window.location.href = `/api/download/${currentFilteredFilename}`;
        };

        // Sidebar rules preview update
        renderSidebarRules();
    }

    // ─── App Cards ───────────────────────────────────────
    function renderAppCards(appBreakdown) {
        const grid = $('flow-cards-grid');
        grid.innerHTML = '';
        const top = appBreakdown.slice(0, 8);
        top.forEach(item => {
            const meta = APP_META[item.app] || APP_META['Unknown'];
            const card = document.createElement('div');
            card.className = 'flow-app-card';
            card.innerHTML = `
                <div class="fac-icon" style="background:${meta.bg}; color:${meta.color};">${meta.icon}</div>
                <div class="fac-category">${item.app_raw}</div>
                <div class="fac-name">${item.app}</div>
                <div class="fac-stat"><strong>${item.count}</strong> packets &nbsp;·&nbsp; <strong>${item.percentage}%</strong></div>
            `;
            card.addEventListener('click', () => {
                const matchedFlow = activeFlowsData.find(f => f.app === item.app);
                if (matchedFlow) openInspector(matchedFlow);
            });
            grid.appendChild(card);
        });
    }

    // ─── Chart ───────────────────────────────────────────
    function renderAppChart(appBreakdown) {
        const ctx = $('appChart').getContext('2d');
        if (appChartInst) appChartInst.destroy();
        const top = appBreakdown.slice(0, 6);
        const colors = ['#6C63FF','#00C2CB','#FF6B9D','#FF8C42','#22C55E','#F59E0B'];
        appChartInst = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: top.map(a => a.app),
                datasets: [{
                    data: top.map(a => a.count),
                    backgroundColor: colors,
                    borderRadius: 6,
                    borderSkipped: false,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#1A1A2E',
                        titleColor: '#fff',
                        bodyColor: '#ccc',
                        borderRadius: 8,
                        padding: 10,
                    }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: '#9090B0', font: { size: 10 } } },
                    y: { grid: { color: '#F0F0F8' }, ticks: { color: '#9090B0', font: { size: 10 } } }
                }
            }
        });
    }

    // ─── Domains List (right panel) ──────────────────────
    function renderDomainsList(flows) {
        const container = $('domains-list');
        container.innerHTML = '';
        const seen = new Map();
        flows.forEach(f => { if (f.sni && !seen.has(f.sni)) seen.set(f.sni, f.app); });
        if (seen.size === 0) {
            container.innerHTML = '<p class="muted-hint">No domains detected.</p>';
            return;
        }
        let count = 0;
        for (const [domain, app] of seen) {
            if (count++ >= 5) break;
            const row = document.createElement('div');
            row.className = 'domain-row';
            row.innerHTML = `<span class="domain-name">${domain}</span><span class="domain-app">${app}</span>`;
            container.appendChild(row);
        }
    }

    $('see-all-domains').addEventListener('click', () => {
        // Show all in a brief expandable form - scroll to flow table
        $('tab-dashboard').scrollTo({ top: 9999, behavior: 'smooth' });
    });

    // ─── Flows Table ─────────────────────────────────────
    function renderFlowsTable(flows) {
        const tbody = $('flows-table-body');
        tbody.innerHTML = '';
        if (!flows.length) {
            tbody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:var(--text-muted); padding:28px;">No connection flows found.</td></tr>`;
            return;
        }
        flows.forEach(flow => {
            const tr = document.createElement('tr');
            const statusClass = flow.blocked ? 'chip-blocked' : 'chip-forwarded';
            const statusLabel = flow.blocked ? 'Blocked' : 'Forwarded';
            tr.innerHTML = `
                <td style="color:var(--text-muted); font-size:11px;">${flow.time}</td>
                <td><strong>${flow.src_ip}</strong><span style="color:var(--text-muted);">:${flow.src_port}</span></td>
                <td><strong>${flow.dst_ip}</strong><span style="color:var(--text-muted);">:${flow.dst_port}</span></td>
                <td><span class="chip chip-protocol">${flow.protocol}</span></td>
                <td><span class="chip chip-app">${flow.app}</span></td>
                <td style="font-size:11.5px; color:var(--text-body); max-width:140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${flow.sni || '—'}</td>
                <td>${flow.packets}</td>
                <td>${formatBytes(flow.bytes)}</td>
                <td><span class="chip ${statusClass}">${statusLabel}</span></td>
                <td><button class="row-action-btn" title="Inspect">⊹</button></td>
            `;
            tr.addEventListener('click', () => openInspector(flow));
            tbody.appendChild(tr);
        });
    }

    // Flow search
    $('flow-search').addEventListener('input', e => {
        const q = e.target.value.toLowerCase();
        const filtered = activeFlowsData.filter(f =>
            f.src_ip.includes(q) || f.dst_ip.includes(q) ||
            String(f.src_port).includes(q) || String(f.dst_port).includes(q) ||
            f.app.toLowerCase().includes(q) ||
            (f.sni && f.sni.toLowerCase().includes(q))
        );
        renderFlowsTable(filtered);
        $('flow-count-badge').textContent = `${filtered.length} flows`;
    });

    // ─── Inspector Drawer ────────────────────────────────
    function openInspector(flow) {
        $('inspect-key').textContent    = flow.key;
        $('inspect-app').textContent    = flow.app;
        $('inspect-host').textContent   = flow.sni || 'N/A';
        $('inspect-bytes').textContent  = `${formatBytes(flow.bytes)} (${flow.packets} pkts)`;
        const sc = flow.blocked ? 'chip chip-blocked' : 'chip chip-forwarded';
        $('inspect-status').className   = sc;
        $('inspect-status').textContent = flow.blocked ? 'Blocked' : 'Forwarded';

        const tbody = $('inspect-packets-body');
        tbody.innerHTML = '';
        if (flow.packets_list && flow.packets_list.length) {
            flow.packets_list.forEach((pkt, i) => {
                const tr = document.createElement('tr');
                const dir = pkt.dir === 'OUT' ? '→' : '←';
                tr.innerHTML = `<td>${i+1}</td><td>${pkt.time.toFixed(4)}</td><td style="color:var(--color-primary);font-weight:700;">${dir}</td><td>${pkt.size}B</td><td>${pkt.payload_len}B</td>`;
                tr.addEventListener('click', () => {
                    tbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
                    tr.classList.add('selected');
                    showHex(pkt);
                });
                tbody.appendChild(tr);
            });
            tbody.querySelector('tr').click();
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:12px;">No packet details.</td></tr>';
            $('inspect-hex-content').textContent = 'No payload data.';
        }

        $('inspector-drawer').classList.add('open');
    }

    function showHex(pkt) {
        if (!pkt.hex) { $('inspect-hex-content').textContent = 'Empty payload (TCP header only).'; return; }
        const bytes = pkt.hex.split(' ');
        let out = '', ascii = '';
        for (let i = 0; i < bytes.length; i++) {
            if (i % 16 === 0 && i > 0) { out += `  |${ascii}|\n`; ascii = ''; }
            if (bytes[i] === '...') { out += '...'; break; }
            out += bytes[i] + ' ';
            const n = parseInt(bytes[i], 16);
            ascii += (n >= 32 && n < 127) ? String.fromCharCode(n) : '.';
        }
        if (ascii) out += ' '.repeat((16 - bytes.length % 16) % 16 * 3) + `  |${ascii}|`;
        $('inspect-hex-content').textContent = out;
    }

    $('close-drawer').addEventListener('click', () => $('inspector-drawer').classList.remove('open'));
    window.addEventListener('click', e => {
        const drawer = $('inspector-drawer');
        if (drawer.classList.contains('open') &&
            !drawer.contains(e.target) &&
            !e.target.closest('.flows-table tr') &&
            !e.target.closest('.flow-app-card')) {
            drawer.classList.remove('open');
        }
    });

    // ─── Rules Manager ───────────────────────────────────
    const ruleType = $('rule-type');

    ruleType.addEventListener('change', () => {
        const t = ruleType.value;
        $('rule-value-group').style.display = t === 'app' ? 'none' : 'block';
        $('rule-app-group').style.display   = t === 'app' ? 'block' : 'none';
        $('rule-value-label').textContent   = t === 'domain' ? 'Domain Substring' : 'IP Address';
        $('rule-value').placeholder         = t === 'domain' ? 'e.g. youtube.com' : '192.168.1.50';
    });

    $('add-rule-btn').addEventListener('click', () => {
        const t = ruleType.value;
        let val = '';
        if (t === 'app') {
            val = $('rule-app-select').value;
            if (rulesState.blockedApps.includes(val)) { showToast('Rule already exists', 'error'); return; }
            rulesState.blockedApps.push(val);
        } else if (t === 'ip') {
            val = $('rule-value').value.trim();
            if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) { showToast('Enter a valid IPv4 address', 'error'); return; }
            if (rulesState.blockedIps.includes(val)) { showToast('Rule already exists', 'error'); return; }
            rulesState.blockedIps.push(val);
        } else {
            val = $('rule-value').value.trim().toLowerCase();
            if (!val) { showToast('Domain cannot be empty', 'error'); return; }
            if (rulesState.blockedDomains.includes(val)) { showToast('Rule already exists', 'error'); return; }
            rulesState.blockedDomains.push(val);
        }
        $('rule-value').value = '';
        showToast('Rule added!', 'success');
        renderRulesUI();
        renderSidebarRules();
        if (currentUploadedFilename) runAnalysis(currentUploadedFilename);
    });

    function deleteRule(cat, val) {
        if (cat === 'ip') rulesState.blockedIps = rulesState.blockedIps.filter(x => x !== val);
        if (cat === 'app') rulesState.blockedApps = rulesState.blockedApps.filter(x => x !== val);
        if (cat === 'domain') rulesState.blockedDomains = rulesState.blockedDomains.filter(x => x !== val);
        showToast('Rule removed', 'success');
        renderRulesUI();
        renderSidebarRules();
        if (currentUploadedFilename) runAnalysis(currentUploadedFilename);
    }

    function renderRulesUI() {
        renderRuleList('ips-rules-list', 'ips-count', rulesState.blockedIps, 'ip');
        renderRuleList('apps-rules-list', 'apps-count', rulesState.blockedApps, 'app');
        renderRuleList('domains-rules-list', 'domains-count', rulesState.blockedDomains, 'domain');
    }

    function renderRuleList(listId, countId, items, cat) {
        const ul = $(listId);
        $(countId).textContent = items.length;
        ul.innerHTML = '';
        if (!items.length) {
            ul.innerHTML = '<li class="rule-empty">None active</li>';
            return;
        }
        items.forEach(val => {
            const li = document.createElement('li');
            li.className = 'rule-li';
            li.innerHTML = `<span>${val}</span><button class="rule-del-btn" title="Remove">&times;</button>`;
            li.querySelector('.rule-del-btn').addEventListener('click', () => deleteRule(cat, val));
            ul.appendChild(li);
        });
    }

    function renderSidebarRules() {
        const preview = $('sidebar-rules-preview');
        preview.innerHTML = '';
        rulesState.blockedIps.slice(0, 3).forEach(ip => {
            const d = document.createElement('div');
            d.className = 'sidebar-rule-pill';
            d.innerHTML = `<span>IP: ${ip}</span><span>✕</span>`;
            preview.appendChild(d);
        });
        rulesState.blockedApps.slice(0, 3).forEach(app => {
            const d = document.createElement('div');
            d.className = 'sidebar-rule-pill app-rule';
            d.innerHTML = `<span>${app}</span><span>✕</span>`;
            preview.appendChild(d);
        });
        rulesState.blockedDomains.slice(0, 2).forEach(dom => {
            const d = document.createElement('div');
            d.className = 'sidebar-rule-pill domain-rule';
            d.innerHTML = `<span>${dom}</span><span>✕</span>`;
            preview.appendChild(d);
        });
    }

    // ─── Simulator ───────────────────────────────────────
    ['sim-dns','sim-http','sim-blocked-ip'].forEach(id => {
        $(id).addEventListener('input', () => $(`${id}-val`).textContent = $(id).value);
    });

    const PRESETS = {
        standard:  { dns:15, http:5, blockedIp:5,  apps:{ youtube:4, netflix:2, google:8, facebook:3, instagram:2, twitter:2, github:4, spotify:2, zoom:2, discord:3 }},
        streaming: { dns:8,  http:1, blockedIp:2,  apps:{ youtube:20,netflix:12,google:4, facebook:1, instagram:6, twitter:1, github:2, spotify:12,zoom:1, discord:2 }},
        work:      { dns:20, http:6, blockedIp:0,  apps:{ youtube:0, netflix:0, google:15,facebook:1, instagram:1, twitter:2, github:18,spotify:1, zoom:10,discord:8 }},
        attack:    { dns:2,  http:1, blockedIp:60, apps:{ youtube:1, netflix:0, google:2, facebook:0, instagram:0, twitter:0, github:0, spotify:0, zoom:0, discord:0 }}
    };

    document.querySelectorAll('.sim-preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.sim-preset-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const p = PRESETS[btn.dataset.preset];
            $('sim-dns').value = p.dns;       $('sim-dns-val').textContent = p.dns;
            $('sim-http').value = p.http;     $('sim-http-val').textContent = p.http;
            $('sim-blocked-ip').value = p.blockedIp; $('sim-blocked-ip-val').textContent = p.blockedIp;
            document.querySelectorAll('.app-sim-input').forEach(inp =>
                inp.value = p.apps[inp.dataset.app] ?? 0);
            showToast(`Preset "${btn.textContent.trim()}" applied`, 'success');
        });
    });

    $('sim-run-btn').addEventListener('click', () => {
        showToast('Synthesizing capture…');
        const apps = {};
        document.querySelectorAll('.app-sim-input').forEach(inp => {
            apps[inp.dataset.app] = parseInt(inp.value) || 0;
        });
        fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                params: {
                    dns: parseInt($('sim-dns').value),
                    http: parseInt($('sim-http').value),
                    blocked_ip_packets: parseInt($('sim-blocked-ip').value),
                    apps
                }
            })
        })
        .then(r => { if (!r.ok) throw new Error(); return r.json(); })
        .then(data => {
            currentUploadedFilename = data.filename;
            switchTab('dashboard');
            $('empty-state').style.display = 'none';
            $('upload-progress-bar').style.display = 'block';
            $('upload-status-label').textContent = 'Analyzing synthetic capture…';
            runAnalysis(data.filename);
        })
        .catch(() => showToast('Simulation failed', 'error'));
    });

    // ─── Cleanup ─────────────────────────────────────────
    $('cleanup-btn').addEventListener('click', () => {
        if (!confirm('Delete all temporary captures and reset dashboard?')) return;
        fetch('/api/cleanup', { method: 'POST' })
        .then(r => r.json())
        .then(d => {
            showToast(d.message, 'success');
            currentUploadedFilename = '';
            $('dashboard-results').style.display = 'none';
            $('empty-state').style.display = 'block';
            $('re-analyze-btn').style.display = 'none';
            $('pcap-file-input').value = '';
        })
        .catch(() => showToast('Cleanup failed', 'error'));
    });

    // ─── Init ────────────────────────────────────────────
    renderRulesUI();
    renderSidebarRules();
});
