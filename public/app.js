document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const pathInput = document.getElementById('pathInput');
    const progressContainer = document.getElementById('progressContainer');
    const dashboardArea = document.getElementById('dashboardArea');
    const logContainer = document.getElementById('logContainer');
    const filterSelect = document.getElementById('filterSelect');

    // Metrics elements
    const elSafe = document.getElementById('mSafe');
    const elSusp = document.getElementById('mSusp');
    const elRisk = document.getElementById('mRisk');
    const elTotal = document.getElementById('mTotal');

    let currentResults = [];

    scanBtn.addEventListener('click', async () => {
        const targetPath = pathInput.value.trim();
        if (!targetPath) return alert('Please enter a valid directory path.');

        // UI Reset
        scanBtn.disabled = true;
        progressContainer.classList.remove('hidden');
        dashboardArea.classList.add('hidden');
        logContainer.innerHTML = '';

        try {
            const response = await fetch(`/api/scan?path=${encodeURIComponent(targetPath)}`);
            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || 'Server error');
            }

            const data = await response.json();
            currentResults = data.results || [];
            
            updateMetrics(currentResults);
            renderLogs(currentResults);
            
            dashboardArea.classList.remove('hidden');

        } catch (err) {
            alert(`Scan failed: ${err.message}`);
        } finally {
            scanBtn.disabled = false;
            progressContainer.classList.add('hidden');
        }
    });

    filterSelect.addEventListener('change', () => {
        const val = filterSelect.value;
        if (val === 'ALL') {
            renderLogs(currentResults);
        } else if (val === 'HIGH_RISK') {
            renderLogs(currentResults.filter(r => r.classification === 'HIGH RISK'));
        } else if (val === 'SUSPICIOUS') {
            renderLogs(currentResults.filter(r => r.classification === 'SUSPICIOUS'));
        }
    });

    function updateMetrics(results) {
        let safe = 0, susp = 0, risk = 0;
        
        results.forEach(r => {
            if (r.classification === 'SAFE') safe++;
            else if (r.classification === 'SUSPICIOUS') susp++;
            else if (r.classification === 'HIGH RISK') risk++;
        });

        // Simple counter animation
        animateValue(elSafe, 0, safe, 1000);
        animateValue(elSusp, 0, susp, 1000);
        animateValue(elRisk, 0, risk, 1000);
        animateValue(elTotal, 0, results.length, 1000);
    }

    function renderLogs(results) {
        logContainer.innerHTML = '';
        
        if (results.length === 0) {
            logContainer.innerHTML = '<p style="color: #666; text-align: center; padding: 2rem;">No files matching this filter.</p>';
            return;
        }

        // Sort: High Risk first, then Suspicious, then Safe
        const sorted = [...results].sort((a, b) => b.risk_score - a.risk_score);

        sorted.forEach(fi => {
            // Determine class names
            const levelClass = fi.classification.toLowerCase().replace(' ', '_');
            
            let flagsHtml = '';
            fi.flags.forEach(f => {
                flagsHtml += `<div class="flag-item">${f.reason} [+${f.points}]</div>`;
            });

            const html = `
                <div class="file-card level-${levelClass}">
                    <div class="card-header">
                        <div>
                            <div class="filename">${escapeHtml(fi.file)}</div>
                            <div class="file-path">${escapeHtml(fi.path)}</div>
                        </div>
                        <div class="badge ${levelClass}">${fi.classification}</div>
                    </div>
                    
                    <div class="card-stats">
                        <span><strong>Size:</strong> ${fi.size_human}</span>
                        <span><strong>Entropy:</strong> ${fi.entropy} (${fi.entropy_band})</span>
                        <span><strong>Score:</strong> ${fi.risk_score}/100</span>
                    </div>

                    ${flagsHtml ? `<div class="flags-list">${flagsHtml}</div>` : ''}
                </div>
            `;
            
            logContainer.insertAdjacentHTML('beforeend', html);
        });
    }

    // Utility: XSS prevention
    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Utility: Value animation
    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
});
