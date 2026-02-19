document.addEventListener('DOMContentLoaded', () => {
    // ========== HELPERS ==========
    function getEl(id) {
        return document.getElementById(id);
    }

    async function safeFetch(url, options = {}) {
        try {
            const res = await fetch(url, options);
            if (!res.ok) throw new Error(`Request failed: ${res.status}`);
            return await res.json();
        } catch (err) {
            console.error(`Fetch error for ${url}:`, err);
            return { error: err.message || "Network/Server Error" };
        }
    }

    // ========== TAB NAVIGATION ==========
    const tabBtns = document.querySelectorAll('.soc-tab');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => {
                c.classList.remove('active');
                c.classList.add('hidden');
            });

            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            const target = getEl(`tab-${tabId}`);
            if (target) {
                target.classList.remove('hidden');
                target.classList.add('active');
            }

            if (tabId === 'cases') loadCases();
        });
    });

    // Attack Stage Order
    const ATTACK_STAGE_ORDER = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command & Control", "Exfiltration", "Impact"
    ];

    // Leaflet map instance
    let geoMap = null;

    // ================================================================
    // TAB 1 — AI LOG INTELLIGENCE AGENT
    // ================================================================
    const analyzeBtn = getEl('analyze-btn');
    const logInput = getEl('log-input');
    const clearBtn = getEl('clear-btn');
    const intelLoading = getEl('intel-loading');
    const intelResults = getEl('intel-results');
    const fileInput = getEl('log-file-input');
    const fileNameDisplay = getEl('file-name-display');

    // File input display
    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                if (fileNameDisplay) fileNameDisplay.textContent = fileInput.files[0].name;
            } else {
                if (fileNameDisplay) fileNameDisplay.textContent = '';
            }
        });
    }

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async () => {
            const hasFile = fileInput && fileInput.files.length > 0;
            const hasText = logInput && logInput.value.trim();

            if (!hasFile && !hasText) {
                alert('Please enter log text or upload a log file.');
                return;
            }

            // Show loading
            if (intelResults) intelResults.classList.add('hidden');
            if (intelLoading) intelLoading.classList.remove('hidden');
            analyzeBtn.disabled = true;

            let data;

            if (hasFile) {
                // File upload mode — use FormData
                const formData = new FormData();
                formData.append('log_file', fileInput.files[0]);
                if (hasText) formData.append('event_description', logInput.value.trim());

                try {
                    const res = await fetch('/api/log-intelligence', {
                        method: 'POST',
                        body: formData
                    });
                    data = await res.json();
                } catch (err) {
                    data = { error: err.message };
                }
            } else {
                // JSON mode (existing)
                data = await safeFetch('/api/log-intelligence', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ event_description: logInput.value.trim() })
                });
            }

            analyzeBtn.disabled = false;

            if (!data || data.error) {
                alert('Analysis Error: ' + (data?.error || 'Unknown error'));
                if (intelLoading) intelLoading.classList.add('hidden');
                return;
            }

            renderIntelResults(data);

            if (intelLoading) intelLoading.classList.add('hidden');
            if (intelResults) intelResults.classList.remove('hidden');
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            if (logInput) logInput.value = '';
            if (fileInput) fileInput.value = '';
            if (fileNameDisplay) fileNameDisplay.textContent = '';
            if (intelResults) intelResults.classList.add('hidden');
            // Clear Q&A responses
            const qaResponses = getEl('qa-responses');
            if (qaResponses) qaResponses.innerHTML = '';
        });
    }

    function renderIntelResults(data) {
        const analysis = data.analysis;
        if (!analysis) return;

        // Auto-case banner
        const banner = getEl('auto-case-banner');
        const bannerMsg = getEl('auto-case-msg');
        if (banner && bannerMsg) {
            if (data.auto_case_created) {
                bannerMsg.textContent = `🚨 High-risk threat detected — Case ${data.auto_case_id} auto-created`;
                banner.classList.remove('hidden');
            } else {
                banner.classList.add('hidden');
            }
        }

        // AI Reasoning
        const explanationEl = getEl('attack-explanation');
        if (explanationEl) explanationEl.textContent = analysis.attack_explanation || 'N/A';

        // MITRE Tags
        const tagsContainer = getEl('mitre-tags');
        if (tagsContainer) {
            tagsContainer.innerHTML = '';
            (analysis.likely_mitre_techniques || []).forEach(tech => {
                const span = document.createElement('span');
                span.className = 'tag';
                span.textContent = tech;
                tagsContainer.appendChild(span);
            });
        }

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

        // Severity Badge
        const sevBadge = getEl('severity-badge');
        if (sevBadge) {
            sevBadge.className = 'kpi-badge';
            if (analysis.severity_rating) {
                sevBadge.classList.add(analysis.severity_rating.toLowerCase());
                sevBadge.textContent = analysis.severity_rating;
            }
        }

        // Confidence
        const confMeter = getEl('confidence-meter');
        if (confMeter) confMeter.textContent = analysis.confidence_level || 'N/A';
        const confReason = getEl('confidence-reason');
        if (confReason) confReason.textContent = analysis.confidence_reason || '';

        // ML Risk Score
        const mlRisk = analysis.ml_risk_score;
        const mlRiskEl = getEl('ml-risk-score');
        if (mlRiskEl && mlRisk !== undefined) {
            mlRiskEl.textContent = mlRisk;
            if (mlRisk >= 75) mlRiskEl.style.color = '#ff0050';
            else if (mlRisk >= 50) mlRiskEl.style.color = '#ff8c00';
            else mlRiskEl.style.color = '#7dff00';
        }
        const mlBar = getEl('ml-risk-bar');
        if (mlBar && mlRisk !== undefined) mlBar.style.width = mlRisk + '%';

        // Behavior Anomaly Score
        const anomaly = analysis.behavior_anomaly_score;
        const anomalyEl = getEl('behavior-anomaly-score');
        if (anomalyEl && anomaly !== undefined) {
            anomalyEl.textContent = anomaly;
            if (anomaly >= 70) anomalyEl.style.color = '#ff0050';
            else if (anomaly >= 40) anomalyEl.style.color = '#be00ff';
            else anomalyEl.style.color = '#00f2ea';
        }
        const anomalyBar = getEl('anomaly-bar');
        if (anomalyBar && anomaly !== undefined) anomalyBar.style.width = anomaly + '%';

        // Attack Progression
        const stageText = getEl('current-stage-text');
        if (stageText) stageText.textContent = analysis.current_attack_stage || 'Unknown';
        const nextStageText = getEl('next-stage-text');
        if (nextStageText) nextStageText.textContent = analysis.predicted_next_stage || 'None';

        // Timeline
        renderTimeline(analysis.attack_timeline, analysis.current_attack_stage);

        // Geo Map
        renderGeoMap(data.geo_data || []);

        // Evidence
        const evidenceContent = getEl('evidence-content');
        if (evidenceContent) {
            evidenceContent.innerHTML = '';
            (data.retrieved_docs || []).forEach((doc, index) => {
                const div = document.createElement('div');
                div.className = 'evidence-item';
                div.innerHTML = `<div class="evidence-label">SOURCE FRAGMENT ${index + 1}</div><div>${doc}</div>`;
                evidenceContent.appendChild(div);
            });
        }

        // Clear Q&A responses for new analysis
        const qaResponses = getEl('qa-responses');
        if (qaResponses) qaResponses.innerHTML = '';
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
                <span class="stage-label">${stage}</span>
            `;
            container.appendChild(stepDiv);
        });
    }


    // ================================================================
    // IP GEO MAP (Leaflet.js)
    // ================================================================
    function renderGeoMap(geoData) {
        const mapCard = getEl('geo-map-card');
        const mapEl = getEl('geo-map');
        const countEl = getEl('geo-ip-count');

        if (!mapEl) return;

        if (!geoData || geoData.length === 0) {
            if (mapCard) mapCard.style.display = 'none';
            return;
        }

        if (mapCard) mapCard.style.display = 'block';
        if (countEl) countEl.textContent = geoData.length;

        // Destroy previous map if exists
        if (geoMap) {
            geoMap.remove();
            geoMap = null;
        }

        geoMap = L.map('geo-map', {
            scrollWheelZoom: false,
            zoomControl: true
        }).setView([20, 0], 2);

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 18
        }).addTo(geoMap);

        const bounds = [];

        geoData.forEach(g => {
            if (g.lat === undefined || g.lon === undefined) return;

            let color = '#22c55e'; // Clean = green
            if (g.risk === 'Malicious') color = '#ef4444';
            else if (g.risk === 'Suspicious') color = '#f59e0b';
            else if (g.risk === 'Unknown') color = '#8892a8';

            const marker = L.circleMarker([g.lat, g.lon], {
                radius: 8,
                fillColor: color,
                color: color,
                fillOpacity: 0.8,
                weight: 2
            }).addTo(geoMap);

            marker.bindTooltip(
                `<strong>${g.ip}</strong><br>Country: ${g.country}<br>Risk: ${g.risk}`,
                { className: 'geo-tooltip' }
            );

            bounds.push([g.lat, g.lon]);
        });

        if (bounds.length > 0) {
            geoMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
        }

        // Needed because map is in a hidden div initially — force redraw
        setTimeout(() => { if (geoMap) geoMap.invalidateSize(); }, 200);
    }


    // ================================================================
    // LOG Q&A (Investigation follow-up)
    // ================================================================
    const qaInput = getEl('qa-input');
    const qaSendBtn = getEl('qa-send-btn');

    async function sendQAQuestion() {
        if (!qaInput) return;
        const question = qaInput.value.trim();
        if (!question) return;

        appendQAItem(question, 'question');
        qaInput.value = '';
        qaSendBtn.disabled = true;

        const loadingId = appendQAItem('Analyzing...', 'loading');

        const data = await safeFetch('/api/log-qa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: question })
        });

        qaSendBtn.disabled = false;

        // Remove loading
        const loadEl = document.getElementById(loadingId);
        if (loadEl) loadEl.remove();

        if (data && data.answer) {
            appendQAItem(data.answer, 'answer');
        } else {
            appendQAItem("Error: " + (data?.error || "Unknown error"), 'error');
        }
    }

    if (qaSendBtn) qaSendBtn.addEventListener('click', sendQAQuestion);
    if (qaInput) {
        qaInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendQAQuestion();
        });
    }

    function appendQAItem(text, type) {
        const container = getEl('qa-responses');
        if (!container) return null;
        const id = 'qa-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
        const div = document.createElement('div');
        div.className = `qa-item qa-${type}`;
        div.id = id;

        const label = type === 'question' ? '🔎 Question' : type === 'answer' ? '🧠 Answer' : type === 'loading' ? '⏳' : '❌ Error';
        div.innerHTML = `<div class="qa-label">${label}</div><div class="qa-text">${text}</div>`;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return id;
    }


    // ================================================================
    // REPORT GENERATION
    // ================================================================
    const reportBtn = getEl('generate-report-btn');
    if (reportBtn) {
        reportBtn.addEventListener('click', async () => {
            reportBtn.disabled = true;
            reportBtn.textContent = '⏳ Generating...';

            try {
                const res = await fetch('/api/generate-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (!res.ok) {
                    const errData = await res.json();
                    alert('Report Error: ' + (errData.error || 'Unknown error'));
                    return;
                }

                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'CyberGuard_Investigation_Report.txt';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } catch (err) {
                alert('Report generation failed: ' + err.message);
            } finally {
                reportBtn.disabled = false;
                reportBtn.textContent = '📄 Generate Investigation Report';
            }
        });
    }


    // ================================================================
    // TAB 2 — SECURITY KNOWLEDGE CHATBOT
    // ================================================================
    const chatInput = getEl('chat-input');
    const chatSendBtn = getEl('chat-send-btn');
    const chatMessages = getEl('chat-messages');

    async function sendChatMessage() {
        if (!chatInput) return;
        const query = chatInput.value.trim();
        if (!query) return;

        appendChatMessage(query, 'user');
        chatInput.value = '';
        chatSendBtn.disabled = true;

        const typingId = appendChatMessage('Thinking...', 'system typing');

        const data = await safeFetch('/api/security-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query })
        });

        chatSendBtn.disabled = false;

        const typingEl = document.getElementById(typingId);
        if (typingEl) typingEl.remove();

        if (data && data.response) {
            appendChatMessage(data.response, 'system');
        } else {
            appendChatMessage("Error: " + (data?.error || "Unknown error"), 'system error');
        }
    }

    if (chatSendBtn) chatSendBtn.addEventListener('click', sendChatMessage);
    if (chatInput) {
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });
    }

    function appendChatMessage(text, type) {
        if (!chatMessages) return null;
        const id = 'msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);
        const div = document.createElement('div');
        div.className = `chat-message ${type}`;
        div.id = id;
        const content = document.createElement('div');
        content.className = 'msg-content';
        content.textContent = text;
        div.appendChild(content);
        chatMessages.appendChild(div);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        return id;
    }


    // ================================================================
    // TAB 3 — CASE MANAGEMENT
    // ================================================================
    async function loadCases() {
        const cases = await safeFetch('/api/cases');
        const tbody = getEl('cases-table-body');
        const noCasesMsg = getEl('no-cases-msg');

        if (!tbody) return;
        tbody.innerHTML = '';

        if (!cases || !Array.isArray(cases) || cases.length === 0) {
            if (noCasesMsg) noCasesMsg.classList.remove('hidden');
            return;
        }

        if (noCasesMsg) noCasesMsg.classList.add('hidden');

        cases.forEach(c => {
            const tr = document.createElement('tr');

            let statusColor = '#e0e0e0';
            if (c.status === 'Open') statusColor = '#ff0050';
            if (c.status === 'Investigating') statusColor = '#ff8c00';
            if (c.status === 'Closed') statusColor = '#7dff00';

            const riskScore = c.ml_risk_score !== undefined ? c.ml_risk_score : 'N/A';
            let riskColor = '#e0e0e0';
            if (typeof riskScore === 'number') {
                if (riskScore >= 75) riskColor = '#ff0050';
                else if (riskScore >= 50) riskColor = '#ff8c00';
                else riskColor = '#7dff00';
            }

            const caseId = c.case_id;
            const safeStatus = c.status || 'Open';

            tr.innerHTML = `
                <td>${caseId}</td>
                <td>${c.created_at}</td>
                <td>${c.severity}</td>
                <td style="color: ${riskColor}; font-weight: bold;">${riskScore}</td>
                <td style="color: ${statusColor}; font-weight: bold;">
                    <span class="status-toggle" data-case-id="${caseId}" data-status="${safeStatus}">
                        ${safeStatus} &#x21bb;
                    </span>
                </td>
                <td class="summary-cell">${c.incident_summary || 'N/A'}</td>
                <td>
                    <button class="btn-view-actions" data-case-id="${caseId}">View</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.status-toggle').forEach(el => {
            el.style.cursor = 'pointer';
            el.addEventListener('click', async () => {
                const caseId = el.getAttribute('data-case-id');
                const currentStatus = el.getAttribute('data-status');
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
            });
        });

        tbody.querySelectorAll('.btn-view-actions').forEach(btn => {
            btn.addEventListener('click', () => {
                const caseId = btn.getAttribute('data-case-id');
                const caseData = cases.find(cc => cc.case_id === caseId);
                if (caseData) {
                    const actions = caseData.recommended_actions || [];
                    alert('Recommended Actions:\n\n' + (actions.length > 0 ? actions.join('\n') : 'No actions recorded.'));
                }
            });
        });
    }
});
