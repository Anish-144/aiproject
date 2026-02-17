document.addEventListener('DOMContentLoaded', () => {
    // Helper: Safe Element Retrieval
    function getEl(id) {
        return document.getElementById(id);
    }

    // Helper: Safe Fetch
    async function safeFetch(url, options = {}) {
        try {
            const res = await fetch(url, options);
            if (!res.ok) throw new Error(`Request failed: ${res.status}`);
            return await res.json();
        } catch (err) {
            console.error(`Fetch error for ${url}:`, err);
            return { error: "Network/Server Error" };
        }
    }

    // --- Main UI Elements ---
    const analyzeBtn = getEl('analyze-btn');
    const inputField = getEl('event-input');
    const resultsContainer = getEl('results-container');
    const loading = getEl('loading');
    const historyList = getEl('history-list');

    // Attack Stage Order
    const ATTACK_STAGE_ORDER = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command & Control", "Exfiltration", "Impact"
    ];

    let currentAnalysisData = null;
    let currentQuery = "";

    // --- Report Generation Logic ---
    const generateReportBtn = getEl('generate-report-btn');
    const createCaseBtn = getEl('create-case-btn');
    let lastAnalysisData = null;
    let lastQuery = "";

    if (generateReportBtn) {
        generateReportBtn.addEventListener('click', async () => {
            if (!lastAnalysisData) return;

            const data = await safeFetch('/generate_report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    analysis_data: currentAnalysisData,
                    original_query: currentQuery
                })
            });

            if (!data || data.error) {
                alert('Error generating report: ' + (data?.error || 'Unknown error'));
                return;
            }

            // Download File
            try {
                const blob = new Blob([data.report_content], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            } catch (e) {
                console.error("Download failed:", e);
            }
        });
    }

    // --- Create Case Logic ---
    if (createCaseBtn) {
        createCaseBtn.addEventListener('click', async () => {
            if (!lastAnalysisData) return;

            createCaseBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating...';

            const payload = {
                incident_summary: lastAnalysisData.attack_explanation?.substring(0, 100) + "..." || "No Summary",
                severity: lastAnalysisData.severity_rating,
                mitre_techniques: lastAnalysisData.likely_mitre_techniques,
                recommended_actions: lastAnalysisData.recommended_actions
            };

            const data = await safeFetch('/api/create-case', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (data && data.case_id) {
                alert(`Case Created: ${data.case_id}`);
                createCaseBtn.textContent = 'Case Created';
                loadCases();
            } else {
                alert('Failed to create case');
            }
            createCaseBtn.innerHTML = '<i class="fas fa-folder-plus"></i> Create Case';
        });
    }

    // --- Main Analysis Logic ---
    if (analyzeBtn && inputField) {
        analyzeBtn.addEventListener('click', async () => {
            const query = inputField.value.trim();
            if (!query) return;

            if (resultsContainer) resultsContainer.classList.add('hidden');
            if (loading) loading.classList.remove('hidden');

            const data = await safeFetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ event_description: query })
            });

            if (!data || data.error) {
                alert('Error: ' + (data?.error || 'Unknown error'));
                if (loading) loading.classList.add('hidden');
                return;
            }

            currentAnalysisData = data.analysis;
            currentQuery = query;
            updateUI(data.analysis, data.retrieved_docs);

            if (generateReportBtn) generateReportBtn.style.display = 'inline-block';
            if (createCaseBtn) createCaseBtn.style.display = 'inline-block';

            lastAnalysisData = data.analysis;
            lastQuery = query;

            addToHistory(query, data);

            if (loading) loading.classList.add('hidden');
            if (resultsContainer) resultsContainer.classList.remove('hidden');
        });
    }

    // Clear Button
    const clearBtn = getEl('clear-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            if (inputField) inputField.value = '';
            if (resultsContainer) resultsContainer.classList.add('hidden');
        });
    }

    function updateUI(analysis, docs) {
        if (!analysis) return;

        const explanationEl = getEl('attack-explanation');
        if (explanationEl) explanationEl.textContent = analysis.attack_explanation || 'N/A';

        // Tags
        const tagsContainer = getEl('mitre-tags');
        const graphContainer = getEl('mitre-graph');

        if (tagsContainer) tagsContainer.innerHTML = '';
        if (graphContainer) graphContainer.innerHTML = '';

        (analysis.likely_mitre_techniques || []).forEach(tech => {
            if (tagsContainer) {
                const span = document.createElement('span');
                span.className = 'tag';
                span.textContent = tech;
                tagsContainer.appendChild(span);
            }
            if (graphContainer) {
                const node = document.createElement('div');
                node.className = 'node';
                node.textContent = tech.replace('T', '');
                node.title = tech;
                graphContainer.appendChild(node);
            }
        });

        // Next Steps
        const nextStepsList = getEl('next-steps-list');
        if (nextStepsList) {
            nextStepsList.innerHTML = '';
            (analysis.possible_next_steps || []).forEach(step => {
                const li = document.createElement('li');
                li.textContent = step;
                nextStepsList.appendChild(li);
            });
        }

        // Evidence
        const evidenceContent = getEl('evidence-content');
        if (evidenceContent) {
            evidenceContent.innerHTML = '';
            (docs || []).forEach((doc, index) => {
                const div = document.createElement('div');
                div.className = 'evidence-item';
                div.innerHTML = `<div class="evidence-label">SOURCE FRAGMENT ${index + 1}</div><div>${doc}</div>`;
                evidenceContent.appendChild(div);
            });
        }

        renderTimeline(analysis.attack_timeline, analysis.current_attack_stage);
        updateStats(analysis);

        // Defensive Actions
        const defActionsList = getEl('defensive-actions-list');
        if (defActionsList) {
            defActionsList.innerHTML = '';
            const actions = analysis.recommended_actions || [];
            if (actions.length === 0) {
                defActionsList.innerHTML = '<li>No specific actions generated.</li>';
            } else {
                actions.forEach(action => {
                    const li = document.createElement('li');
                    li.textContent = action;
                    defActionsList.appendChild(li);
                });
            }
        }
    }

    function renderTimeline(timelineMap, currentStage) {
        const container = getEl('timeline-steps');
        if (!container) return;
        container.innerHTML = '';

        if (!timelineMap) return;

        ATTACK_STAGE_ORDER.forEach(stage => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'timeline-step';

            const isReached = timelineMap[stage] === true;
            const isCurrent = (stage === currentStage);

            if (isCurrent) stepDiv.classList.add('current');
            else if (isReached) stepDiv.classList.add('completed');

            stepDiv.innerHTML = `
                <div class="dot"></div>
                ${stage.replace(' ', '<br>')}
            `;
            container.appendChild(stepDiv);
        });
    }

    function updateStats(analysis) {
        const sevBadge = getEl('severity-badge');
        if (sevBadge) {
            sevBadge.className = 'badge';
            if (analysis.severity_rating) {
                sevBadge.classList.add(analysis.severity_rating.toLowerCase());
                sevBadge.textContent = analysis.severity_rating;
            }
        }

        const confMeter = getEl('confidence-meter');
        if (confMeter) confMeter.textContent = analysis.confidence_level || 'N/A';

        const confReason = getEl('confidence-reason');
        if (confReason) confReason.textContent = analysis.confidence_reason || 'N/A';

        const stageText = getEl('current-stage-text');
        if (stageText) stageText.textContent = analysis.current_attack_stage || 'Unknown';

        const nextStageText = getEl('next-stage-text');
        if (nextStageText) nextStageText.textContent = analysis.predicted_next_stage || 'None';
    }

    function addToHistory(query, data) {
        if (!historyList) return;
        const item = document.createElement('li');
        const time = new Date().toLocaleTimeString();
        item.textContent = `[${time}] ${query.substring(0, 30)}...`;

        item.addEventListener('click', () => {
            if (inputField) inputField.value = query;
            if (resultsContainer) resultsContainer.classList.add('hidden');
            if (loading) loading.classList.remove('hidden');

            setTimeout(() => {
                if (loading) loading.classList.add('hidden');
                if (resultsContainer) resultsContainer.classList.remove('hidden');
                updateUI(data.analysis, data.retrieved_docs);
            }, 300);
        });
        historyList.appendChild(item);
    }

    // --- Tab Navigation ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => {
                c.classList.remove('active');
                c.classList.add('hidden');
            });

            const tabId = btn.getAttribute('data-tab');
            if (btn.classList) btn.classList.add('active');
            const target = getEl(`tab-${tabId}`);
            if (target) {
                target.classList.remove('hidden');
                target.classList.add('active');
            }

            // Lazy Load Logic
            if (tabId === 'metrics') loadMetrics();
            if (tabId === 'cases') loadCases();
        });
    });

    // --- Network Analyzer Logic ---
    const netInput = getEl('network-log-input');
    const netAnalyzeBtn = getEl('analyze-network-btn');
    const netClearBtn = getEl('clear-network-btn');
    const netLoading = getEl('network-loading');
    const netResults = getEl('network-results');

    // Chat vars
    const chatInput = getEl('chat-input');
    const chatSendBtn = getEl('chat-send-btn');
    const chatHistory = getEl('chat-history');

    let currentLogContext = "";

    if (netAnalyzeBtn && netInput) {
        netAnalyzeBtn.addEventListener('click', async () => {
            const logs = netInput.value.trim();
            if (!logs) return;

            currentLogContext = logs;

            if (netResults) netResults.classList.add('hidden');
            if (netLoading) netLoading.classList.remove('hidden');

            const data = await safeFetch('/analyze_network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ log_data: logs })
            });

            if (!data || data.error) {
                alert('Error: ' + (data?.error || 'Unknown error'));
                if (netLoading) netLoading.classList.add('hidden');
                return;
            }

            updateNetworkUI(data.analysis, data.threat_intel_enrichment);

            if (netLoading) netLoading.classList.add('hidden');
            if (netResults) netResults.classList.remove('hidden');
        });
    }

    if (netClearBtn) {
        netClearBtn.addEventListener('click', () => {
            if (netInput) netInput.value = '';
            if (netResults) netResults.classList.add('hidden');
            currentLogContext = "";
            if (chatHistory) chatHistory.innerHTML = '<div class="chat-message system">Analysis complete. I am ready to answer questions about these logs.</div>';
        });
    }

    function updateNetworkUI(analysis, enrichment) {
        if (!analysis) return;

        const setTxt = (id, val) => { const el = getEl(id); if (el) el.textContent = val; };

        setTxt('net-source-ip', analysis.source_ip);
        setTxt('net-dest-ip', analysis.destination_ip);
        setTxt('net-protocol', analysis.protocol);
        setTxt('net-recommendation', analysis.recommended_action);

        const anomaliesList = getEl('net-anomalies');
        if (anomaliesList) {
            anomaliesList.innerHTML = '';
            (analysis.anomalies || []).forEach(anom => {
                const li = document.createElement('li');
                li.textContent = `• ${anom}`;
                anomaliesList.appendChild(li);
            });
        }

        const tiContainer = getEl('threat-intel-content');
        if (tiContainer) {
            tiContainer.innerHTML = '';
            if (enrichment && enrichment.length > 0) {
                enrichment.forEach(item => {
                    let color = "var(--text-primary)";
                    if (item.reputation === "Malicious") color = "var(--accent-red)";
                    if (item.reputation === "Suspicious") color = "var(--accent-orange)";

                    const div = document.createElement('div');
                    div.style.marginBottom = "10px";
                    div.style.padding = "10px";
                    div.style.background = "rgba(255,255,255,0.05)";
                    div.style.borderRadius = "4px";
                    div.innerHTML = `
                        <div style="font-weight:bold; color: var(--accent-cyan);">${item.ip || 'N/A'}</div>
                        <div style="font-size: 0.85rem;">
                            <span style="color: ${color}">[${item.reputation || 'Unknown'}]</span> 
                            ${item.country || 'N/A'} - ${item.asn || 'N/A'}
                        </div>
                    `;
                    tiContainer.appendChild(div);
                });
            } else {
                tiContainer.innerHTML = '<div style="color: var(--text-secondary); font-size: 0.9rem;">No Intelligence Data Available (Internal or N/A)</div>';
            }
        }

        if (chatHistory) chatHistory.innerHTML = '<div class="chat-message system">Analysis complete. I am ready to answer questions about these logs.</div>';

        const defActionsList = getEl('net-defensive-actions');
        if (defActionsList) {
            defActionsList.innerHTML = '';
            (analysis.recommended_actions || []).forEach(action => {
                const li = document.createElement('li');
                li.textContent = `• ${action}`;
                defActionsList.appendChild(li);
            });
        }
    }

    // --- Network Chat Logic ---
    async function sendChatMessage() {
        if (!chatInput) return;
        const query = chatInput.value.trim();
        if (!query) return;

        appendMessage(query, 'user');
        chatInput.value = '';

        const data = await safeFetch('/chat_network', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                query: query,
                log_context: currentLogContext
            })
        });

        if (data && data.response) {
            appendMessage(data.response, 'system');
        } else {
            appendMessage("Error: " + (data?.error || "Unknown error"), 'system');
        }
    }

    if (chatSendBtn) {
        chatSendBtn.addEventListener('click', sendChatMessage);
    }
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });
    }

    function appendMessage(text, type) {
        if (!chatHistory) return;
        const div = document.createElement('div');
        div.className = `chat-message ${type}`;
        div.textContent = text;
        chatHistory.appendChild(div);
        chatHistory.scrollTop = chatHistory.scrollHeight;
    }

    // --- Metrics Tab Logic ---
    let techniqueChart = null;
    let severityChart = null;
    let timelineChart = null;

    async function loadMetrics() {
        const data = await safeFetch('/api/metrics');
        if (!data || data.error) return;

        const setTxt = (id, val) => { const el = getEl(id); if (el) el.textContent = val; };
        setTxt('metric-total-incidents', data.total_incidents);
        setTxt('metric-avg-confidence', (data.avg_confidence || 0) + '%');

        renderCharts(data);
    }

    function renderCharts(data) {
        // Helper to safely get ctx
        const getCtx = (id) => {
            const canvas = getEl(id);
            return canvas ? canvas.getContext('2d') : null;
        };

        const techCtx = getCtx('techniqueChart');
        if (techCtx) {
            if (techniqueChart) techniqueChart.destroy();
            techniqueChart = new Chart(techCtx, {
                type: 'pie',
                data: {
                    labels: Object.keys(data.technique_dist || {}),
                    datasets: [{
                        data: Object.values(data.technique_dist || {}),
                        backgroundColor: ['#00f2ea', '#ff0050', '#7dff00', '#be00ff', '#ffffff']
                    }]
                },
                options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#e0e0e0' } } } }
            });
        }

        const sevCtx = getCtx('severityChart');
        if (sevCtx) {
            if (severityChart) severityChart.destroy();
            severityChart = new Chart(sevCtx, {
                type: 'bar',
                data: {
                    labels: Object.keys(data.severity_dist || {}),
                    datasets: [{
                        label: 'Incidents',
                        data: Object.values(data.severity_dist || {}),
                        backgroundColor: ['#ff0050', '#ff8c00', '#00f2ea', '#7dff00']
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { ticks: { color: '#e0e0e0' }, grid: { color: '#333' } },
                        x: { ticks: { color: '#e0e0e0' }, grid: { display: false } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        const timeCtx = getCtx('timelineChart');
        if (timeCtx) {
            if (timelineChart) timelineChart.destroy();
            const timelineData = {};
            (data.timeline || []).forEach(ts => {
                const date = ts.split("T")[0];
                timelineData[date] = (timelineData[date] || 0) + 1;
            });

            timelineChart = new Chart(timeCtx, {
                type: 'line',
                data: {
                    labels: Object.keys(timelineData),
                    datasets: [{
                        label: 'Incidents per Day',
                        data: Object.values(timelineData),
                        borderColor: '#00f2ea',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { ticks: { color: '#e0e0e0' }, grid: { color: '#333' } },
                        x: { ticks: { color: '#e0e0e0' }, grid: { display: false } }
                    },
                    plugins: { legend: { labels: { color: '#e0e0e0' } } }
                }
            });
        }
    }

    // --- Case Management Logic ---
    async function loadCases() {
        const cases = await safeFetch('/api/cases');
        if (!cases || !Array.isArray(cases)) return;

        const tbody = getEl('cases-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        cases.forEach(c => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid #333';

            let statusColor = '#e0e0e0';
            if (c.status === 'Open') statusColor = '#ff0050';
            if (c.status === 'Investigating') statusColor = '#ff8c00';
            if (c.status === 'Closed') statusColor = '#7dff00';

            tr.innerHTML = `
                <td style="padding: 12px;">${c.case_id}</td>
                <td style="padding: 12px;">${c.created_at}</td>
                <td style="padding: 12px;">${c.severity}</td>
                <td style="padding: 12px; color: ${statusColor}; font-weight: bold; cursor: pointer;" onclick="toggleStatus('${c.case_id}', '${c.status}')">
                    ${c.status} <i class="fas fa-sync-alt" style="font-size:0.8em; margin-left:5px; opacity:0.7;"></i>
                </td>
                <td style="padding: 12px;">${c.incident_summary}</td>
                <td style="padding: 12px;">
                    <button id="view-action-${c.case_id}" style="background:none; border:1px solid #555; color:#aaa; padding:5px; cursor:pointer;">View Actions</button>
                </td>
            `;
            tbody.appendChild(tr);

            // Add listener to the button we just made, safely
            const btn = document.getElementById(`view-action-${c.case_id}`);
            if (btn) {
                btn.addEventListener('click', () => {
                    alert('Actions:\n' + (c.recommended_actions || []).join('\n'));
                });
            }
        });
    }

    // Global toggle (attached to window for inline onclick)
    window.toggleStatus = async function (caseId, currentStatus) {
        let newStatus = 'Open';
        if (currentStatus === 'Open') newStatus = 'Investigating';
        else if (currentStatus === 'Investigating') newStatus = 'Closed';
        else if (currentStatus === 'Closed') newStatus = 'Open';

        await safeFetch('/api/update-case-status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id: caseId, status: newStatus })
        });
        loadCases();
    };

    // --- Live Monitoring Logic ---
    const liveMonitorBtn = getEl('live-monitor-btn');
    let monitorInterval = null;

    if (liveMonitorBtn) {
        liveMonitorBtn.addEventListener('click', () => {
            if (monitorInterval) {
                clearInterval(monitorInterval);
                monitorInterval = null;
                liveMonitorBtn.textContent = '📡 Start Live Monitoring';
                liveMonitorBtn.style.borderColor = 'var(--accent-purple)';
                liveMonitorBtn.style.color = 'var(--accent-purple)';
                liveMonitorBtn.style.background = 'transparent';
            } else {
                liveMonitorBtn.textContent = '⏹ Stop Monitoring';
                liveMonitorBtn.style.background = '#ff0050';
                liveMonitorBtn.style.color = 'white';
                liveMonitorBtn.style.borderColor = '#ff0050';

                fetchSimulatedLog();
                monitorInterval = setInterval(fetchSimulatedLog, 5000);
            }
        });
    }

    async function fetchSimulatedLog() {
        if (!netInput) return;

        const data = await safeFetch('/api/simulate-logs');
        if (!data || !data.log) return;

        netInput.value = data.log + "\n" + netInput.value;
        if (netAnalyzeBtn) netAnalyzeBtn.click();
    }
});
