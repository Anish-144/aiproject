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
            updateUI(data.analysis, data.retrieved_docs);

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

        historyList.prepend(item);
    }
});
