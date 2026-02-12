document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyze-btn');
    const inputField = document.getElementById('event-input');
    const resultsContainer = document.getElementById('results-container');
    const loading = document.getElementById('loading');
    const historyList = document.getElementById('history-list');

    // Attack Stage Order (Must match Backend)
    const ATTACK_STAGE_ORDER = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command & Control",
        "Exfiltration",
        "Impact"
    ];

    let currentAnalysisData = null;
    let currentQuery = "";

    // Report Generation
    const reportBtn = document.getElementById('report-btn');
    if (reportBtn) {
        reportBtn.addEventListener('click', async () => {
            if (!currentAnalysisData) return;

            try {
                const response = await fetch('/generate_report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        analysis_data: currentAnalysisData,
                        original_query: currentQuery
                    })
                });

                const data = await response.json();
                if (data.error) {
                    alert('Error generating report: ' + data.error);
                    return;
                }

                // Download File
                const blob = new Blob([data.report_content], { type: 'text/plain' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);

            } catch (err) {
                console.error(err);
                alert('Failed to generate report.');
            }
        });
    }

    analyzeBtn.addEventListener('click', async () => {
        const query = inputField.value.trim();
        if (!query) return;

        // UI Reset
        resultsContainer.classList.add('hidden');
        loading.classList.remove('hidden');

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ event_description: query })
            });

            const data = await response.json();

            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }

            // Populate UI
            currentAnalysisData = data.analysis;
            currentQuery = query;
            updateUI(data.analysis, data.retrieved_docs);

            // Show Report Button
            if (reportBtn) reportBtn.classList.remove('hidden');

            // Add to History
            addToHistory(query, data);

        } catch (err) {
            console.error(err);
            alert('Failed to connect to the server.');
        } finally {
            loading.classList.add('hidden');
            resultsContainer.classList.remove('hidden');
        }
    });

    // Clear Button
    document.getElementById('clear-btn').addEventListener('click', () => {
        inputField.value = '';
        resultsContainer.classList.add('hidden');
    });

    function updateUI(analysis, docs) {
        // 1. Explanation
        document.getElementById('attack-explanation').textContent = analysis.attack_explanation;

        // 2. MITRE Tags & Graph
        const tagsContainer = document.getElementById('mitre-tags');
        const graphContainer = document.getElementById('mitre-graph');
        tagsContainer.innerHTML = '';
        graphContainer.innerHTML = '';

        analysis.likely_mitre_techniques.forEach(tech => {
            // Tag
            const span = document.createElement('span');
            span.className = 'tag';
            span.textContent = tech;
            tagsContainer.appendChild(span);

            // Graph Node
            const node = document.createElement('div');
            node.className = 'node';
            node.textContent = tech.replace('T', '');
            node.title = tech;
            graphContainer.appendChild(node);
        });

        // 3. Next Steps
        const nextStepsList = document.getElementById('next-steps-list');
        nextStepsList.innerHTML = '';
        analysis.possible_next_steps.forEach(step => {
            const li = document.createElement('li');
            li.textContent = step;
            nextStepsList.appendChild(li);
        });

        // 4. Evidence Transparency
        const evidenceContent = document.getElementById('evidence-content');
        evidenceContent.innerHTML = '';
        docs.forEach((doc, index) => {
            const div = document.createElement('div');
            div.className = 'evidence-item';
            div.innerHTML = `<div class="evidence-label">SOURCE FRAGMENT ${index + 1}</div><div>${doc}</div>`;
            evidenceContent.appendChild(div);
        });

        // 5. Timeline Logic
        renderTimeline(analysis.attack_timeline, analysis.current_attack_stage);

        // 6. Stats (Severity, Confidence, Progression)
        updateStats(analysis);
    }

    function renderTimeline(timelineMap, currentStage) {
        const container = document.getElementById('timeline-steps');
        container.innerHTML = '';

        ATTACK_STAGE_ORDER.forEach(stage => {
            const stepDiv = document.createElement('div');
            stepDiv.className = 'timeline-step';

            // Determine State
            const isReached = timelineMap[stage] === true;
            const isCurrent = (stage === currentStage);

            if (isCurrent) stepDiv.classList.add('current');
            else if (isReached) stepDiv.classList.add('completed');

            // HTML Structure
            stepDiv.innerHTML = `
                <div class="dot"></div>
                ${stage.replace(' ', '<br>')}
            `;

            container.appendChild(stepDiv);
        });
    }

    function updateStats(analysis) {
        // Severity
        const sevBadge = document.getElementById('severity-badge');
        sevBadge.className = 'badge'; // reset
        sevBadge.classList.add(analysis.severity_rating.toLowerCase());
        sevBadge.textContent = analysis.severity_rating;

        // Confidence
        document.getElementById('confidence-meter').textContent = analysis.confidence_level;
        document.getElementById('confidence-reason').textContent = analysis.confidence_reason;

        // Progression
        document.getElementById('current-stage-text').textContent = analysis.current_attack_stage;
        document.getElementById('next-stage-text').textContent = analysis.predicted_next_stage;
    }

    function addToHistory(query, data) {
        const item = document.createElement('li');
        const time = new Date().toLocaleTimeString();
        item.textContent = `[${time}] ${query.substring(0, 30)}...`;

        item.addEventListener('click', () => {
            inputField.value = query;
            resultsContainer.classList.add('hidden');
            loading.classList.remove('hidden');

            setTimeout(() => {
                loading.classList.add('hidden');
                resultsContainer.classList.remove('hidden');
                updateUI(data.analysis, data.retrieved_docs);
            }, 300);
        });

    }

    // --- Tab Navigation ---
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            tabContents.forEach(c => c.classList.add('hidden'));

            // Activate clicked
            const tabId = btn.getAttribute('data-tab');
            btn.classList.add('active');
            const target = document.getElementById(`tab-${tabId}`);
            target.classList.remove('hidden');
            target.classList.add('active');
        });
    });

    // --- Network Analyzer Logic ---
    const netInput = document.getElementById('network-input');
    const netAnalyzeBtn = document.getElementById('analyze-network-btn');
    const netClearBtn = document.getElementById('clear-network-btn');
    const netLoading = document.getElementById('network-loading');
    const netResults = document.getElementById('network-results');

    // Chat vars
    const chatInput = document.getElementById('chat-input');
    const chatSendBtn = document.getElementById('chat-send-btn');
    const chatHistory = document.getElementById('chat-history');

    let currentLogContext = "";

    if (netAnalyzeBtn) {
        netAnalyzeBtn.addEventListener('click', async () => {
            const logs = netInput.value.trim();
            if (!logs) return;

            currentLogContext = logs;

            // UI Reset
            netResults.classList.add('hidden');
            netLoading.classList.remove('hidden');

            try {
                const response = await fetch('/analyze_network', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ log_data: logs })
                });

                const data = await response.json();

                if (data.error) {
                    alert('Error: ' + data.error);
                    return;
                }

                updateNetworkUI(data.analysis, data.threat_intel_enrichment);

            } catch (err) {
                console.error(err);
                alert('Failed to analyze network logs.');
            } finally {
                netLoading.classList.add('hidden');
                netResults.classList.remove('hidden');
            }
        });
    }

    if (netClearBtn) {
        netClearBtn.addEventListener('click', () => {
            netInput.value = '';
            netResults.classList.add('hidden');
            currentLogContext = "";
            chatHistory.innerHTML = '<div class="chat-message system">Analysis complete. I am ready to answer questions about these logs.</div>';
        });
    }

    function updateNetworkUI(analysis, enrichment) {
        document.getElementById('net-source-ip').textContent = analysis.source_ip;
        document.getElementById('net-dest-ip').textContent = analysis.destination_ip;
        document.getElementById('net-protocol').textContent = analysis.protocol;
        document.getElementById('net-recommendation').textContent = analysis.recommended_action;

        const anomaliesList = document.getElementById('net-anomalies');
        anomaliesList.innerHTML = '';
        analysis.anomalies.forEach(anom => {
            const li = document.createElement('li');
            li.textContent = `• ${anom}`;
            anomaliesList.appendChild(li);
        });

        // Threat Intel
        const tiContainer = document.getElementById('threat-intel-content');
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
                    <div style="font-weight:bold; color: var(--accent-cyan);">${item.ip}</div>
                    <div style="font-size: 0.85rem;">
                        <span style="color: ${color}">[${item.reputation}]</span> 
                        ${item.country || 'N/A'} - ${item.asn || 'N/A'}
                    </div>
                `;
                tiContainer.appendChild(div);
            });
        } else {
            tiContainer.innerHTML = '<div style="color: var(--text-secondary); font-size: 0.9rem;">No Intelligence Data Available (Internal or N/A)</div>';
        }

        // Reset Chat
        chatHistory.innerHTML = '<div class="chat-message system">Analysis complete. I am ready to answer questions about these logs.</div>';
    }

    // --- Network Chat Logic ---
    async function sendChatMessage() {
        const query = chatInput.value.trim();
        if (!query) return;

        // Add User Message
        appendMessage(query, 'user');
        chatInput.value = '';

        try {
            const response = await fetch('/chat_network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    query: query,
                    log_context: currentLogContext
                })
            });

            const data = await response.json();

            if (data.error) {
                appendMessage("Error: " + data.error, 'system');
            } else {
                appendMessage(data.response, 'system');
            }

        } catch (err) {
            console.error(err);
            appendMessage("Failed to send message.", 'system');
        }
    }

    if (chatSendBtn) {
        chatSendBtn.addEventListener('click', sendChatMessage);
        chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });
    }

    function appendMessage(text, type) {
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
        try {
            const response = await fetch('/metrics');
            const data = await response.json();

            if (data.error) return;

            // Update Summary Stats
            document.getElementById('metric-total-incidents').textContent = data.total_incidents;
            document.getElementById('metric-avg-confidence').textContent = data.avg_confidence + '%';

            // Render Charts
            renderCharts(data);

        } catch (err) {
            console.error(err);
        }
    }

    function renderCharts(data) {
        // Technique Chart (Pie)
        const techCtx = document.getElementById('techniqueChart').getContext('2d');
        if (techniqueChart) techniqueChart.destroy();
        techniqueChart = new Chart(techCtx, {
            type: 'pie',
            data: {
                labels: Object.keys(data.technique_dist),
                datasets: [{
                    data: Object.values(data.technique_dist),
                    backgroundColor: ['#00f2ea', '#ff0050', '#7dff00', '#be00ff', '#ffffff']
                }]
            },
            options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#e0e0e0' } } } }
        });

        // Severity Chart (Bar)
        const sevCtx = document.getElementById('severityChart').getContext('2d');
        if (severityChart) severityChart.destroy();
        severityChart = new Chart(sevCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(data.severity_dist),
                datasets: [{
                    label: 'Incidents',
                    data: Object.values(data.severity_dist),
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

        // Timeline (Line)
        const timeCtx = document.getElementById('timelineChart').getContext('2d');
        if (timelineChart) timelineChart.destroy();

        // Group by Date for timeline (simple aggregation)
        const timelineData = {};
        // data.timeline is a list of ISO strings
        data.timeline.forEach(ts => {
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

    // Trigger load on tab click
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.getAttribute('data-tab') === 'metrics') {
                loadMetrics();
            }
        });
    });

});
