class SecurityDashboard {
    constructor() {
        this.apiBase = '/api';
        this.currentScanId = null;
        this.toastTimeout = null;
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.checkScanners();
        this.showToast('Welcome to SecureCode AI! Upload code or scan a GitHub repository to get started.', 'info');
    }
    
    bindEvents() {
        // File upload
        document.getElementById('upload-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleUpload();
        });
        
        // GitHub scan
        document.getElementById('github-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleGitHubScan();
        });
        
        // Paste code scan
        document.getElementById('paste-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handlePasteScan();
        });
        
        // Refresh status
        document.getElementById('refresh-status')?.addEventListener('click', () => {
            this.checkScanners();
        });
        
        // Clear results
        document.getElementById('clear-results')?.addEventListener('click', () => {
            this.clearResults();
        });
    }
    
    async checkScanners() {
        try {
            const response = await fetch(`${this.apiBase}/scan/scanners`);
            const data = await response.json();
            this.updateScannerStatus(data);
        } catch (error) {
            console.error('Error checking scanners:', error);
        }
    }
    
    async handleUpload() {
        const formData = new FormData();
        const fileInput = document.getElementById('file-input');
        const useCustomEngine = document.getElementById('custom-engine')?.checked || true;
        const useExternalScanners = document.getElementById('external-scanners')?.checked || true;
        
        if (!fileInput.files.length) {
            this.showToast('Please select a file to upload', 'error');
            return;
        }
        
        formData.append('file', fileInput.files[0]);
        formData.append('custom_engine', useCustomEngine ? 'true' : 'false');
        formData.append('external_scanners', useExternalScanners ? 'true' : 'false');
        
        this.showLoading('Uploading and scanning...');
        
        try {
            const response = await fetch(`${this.apiBase}/scan/upload`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || `Upload failed: ${response.status}`);
            }
            
            const result = await response.json();
            this.displayResults(result);
            this.showToast('Scan completed successfully!', 'success');
        } catch (error) {
            this.showToast(`Upload failed: ${error.message}`, 'error');
            console.error('Upload error:', error);
        } finally {
            this.hideLoading();
        }
    }
    
    async handlePasteScan() {
        const codeInput = document.getElementById('code-input');
        const language = document.getElementById('code-language')?.value || 'python';
        const useCustomEngine = document.getElementById('paste-custom-engine')?.checked || true;
        const useExternalScanners = document.getElementById('paste-external-scanners')?.checked || true;
        
        if (!codeInput.value.trim()) {
            this.showToast('Please paste some code to scan', 'error');
            return;
        }
        
        this.showLoading('Scanning code...');
        
        try {
            const code = codeInput.value;
            const blob = new Blob([code], { type: 'text/plain' });
            const formData = new FormData();
            formData.append('file', blob, `code.${language}`);
            formData.append('custom_engine', useCustomEngine ? 'true' : 'false');
            formData.append('external_scanners', useExternalScanners ? 'true' : 'false');
            
            const response = await fetch(`${this.apiBase}/scan/upload`, {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || `Scan failed: ${response.status}`);
            }
            
            const result = await response.json();
            this.displayResults(result);
            this.showToast('Code scan completed successfully!', 'success');
        } catch (error) {
            this.showToast(`Scan failed: ${error.message}`, 'error');
            console.error('Paste scan error:', error);
        } finally {
            this.hideLoading();
        }
    }
    
    async handleGitHubScan() {
        const repoUrl = document.getElementById('github-url')?.value;
        const useCustomEngine = document.getElementById('github-custom-engine')?.checked || true;
        const useExternalScanners = document.getElementById('github-external-scanners')?.checked || true;
        
        if (!repoUrl) {
            this.showToast('Please enter a GitHub repository URL', 'error');
            return;
        }
        
        this.showLoading('Cloning and scanning repository...');
        
        try {
            const response = await fetch(`${this.apiBase}/github/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    repo_url: repoUrl,
                    custom_engine: useCustomEngine,
                    external_scanners: useExternalScanners
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || `Scan failed: ${response.status}`);
            }
            
            const result = await response.json();
            this.displayResults(result);
            this.showToast('GitHub repository scan completed successfully!', 'success');
        } catch (error) {
            this.showToast(`GitHub scan failed: ${error.message}`, 'error');
            console.error('GitHub scan error:', error);
        } finally {
            this.hideLoading();
        }
    }
    
    displayResults(data) {
        // Update security score
        this.updateSecurityScore(data.security_score);
        
        // Display vulnerabilities
        this.displayVulnerabilities(data.vulnerabilities || []);
        
        // Update summary
        this.updateSummary(data.summary || {});
        
        // Display recommendations
        this.displayRecommendations(data.security_score?.recommendations || []);
        
        // Store scan ID for later
        this.currentScanId = data.scan_id;
        
        // Show results section
        const resultsContainer = document.getElementById('results-container');
        if (resultsContainer) {
            resultsContainer.classList.remove('hidden');
        }
        
        // Hide empty state
        const emptyState = document.getElementById('empty-state');
        if (emptyState) {
            emptyState.classList.add('hidden');
        }
        
        // Scroll to results
        resultsContainer?.scrollIntoView({ behavior: 'smooth' });
    }
    
    clearResults() {
        const resultsContainer = document.getElementById('results-container');
        if (resultsContainer) {
            resultsContainer.classList.add('hidden');
        }
        
        const emptyState = document.getElementById('empty-state');
        if (emptyState) {
            emptyState.classList.remove('hidden');
        }
        
        document.getElementById('vulnerabilities-list').innerHTML = '';
        document.getElementById('summary-container').innerHTML = '';
        document.getElementById('recommendations').innerHTML = '';
        document.getElementById('overall-score').textContent = '--';
        document.getElementById('risk-level').textContent = '--';
        
        // Reset score circle
        const scoreCircle = document.getElementById('score-circle');
        if (scoreCircle) {
            scoreCircle.style.strokeDashoffset = '339.292';
            scoreCircle.style.stroke = '#667eea';
        }
        
        // Clear dynamic categories
        const gridContainer = document.getElementById('category-scores-grid');
        if (gridContainer) {
            const existingItems = gridContainer.querySelectorAll('.category-score-item');
            existingItems.forEach(el => el.remove());
            const msgElement = document.getElementById('no-categories-msg');
            if (msgElement) {
                msgElement.style.display = 'block';
                msgElement.textContent = 'No vulnerabilities found in any category';
            }
        }
        
        this.currentScanId = null;
        this.showToast('Results cleared', 'info');
    }
    
    updateSecurityScore(scoreData) {
        if (!scoreData) return;
        
        const overallScore = scoreData.overall || 0;
        const riskLevel = scoreData.risk_level || 'low';
        const categories = scoreData.category_scores || {};
        
        // Update score display
        document.getElementById('overall-score').textContent = Math.round(overallScore);
        document.getElementById('risk-level').textContent = riskLevel.toUpperCase();
        document.getElementById('risk-level').className = `risk-value risk-${riskLevel}`;
        
        // Update risk badge
        const riskBadge = document.getElementById('risk-badge');
        if (riskBadge) {
            riskBadge.className = `risk-badge risk-${riskLevel}`;
        }
        
        // Update score circle
        const scoreCircle = document.getElementById('score-circle');
        if (scoreCircle) {
            const circumference = 339.292;
            const offset = circumference - (Math.min(overallScore, 100) / 100) * circumference;
            scoreCircle.style.strokeDashoffset = offset;
            
            let color = '#34d399';
            if (overallScore < 40) color = '#f87171';
            else if (overallScore < 60) color = '#fbbf24';
            else if (overallScore < 80) color = '#60a5fa';
            scoreCircle.style.stroke = color;
        }
        
        // Dynamically create category score items
        const gridContainer = document.getElementById('category-scores-grid');
        if (!gridContainer) return;
        
        // Clear existing items (keep the message)
        const existingItems = gridContainer.querySelectorAll('.category-score-item');
        existingItems.forEach(el => el.remove());
        
        const msgElement = document.getElementById('no-categories-msg');
        
        // Category display names and icons
        const categoryDisplayNames = {
            'injection': 'Injection',
            'secrets': 'Secrets',
            'cryptography': 'Cryptography',
            'authentication': 'Authentication',
            'dependencies': 'Dependencies',
            'configuration': 'Configuration',
            'other': 'Other'
        };
        
        const categoryIcons = {
            'injection': '💉',
            'secrets': '🔐',
            'cryptography': '🔑',
            'authentication': '🛡️',
            'dependencies': '📦',
            'configuration': '⚙️',
            'other': '📌'
        };
        
        const categoryEntries = Object.entries(categories);
        
        if (categoryEntries.length === 0) {
            // No categories with findings
            if (msgElement) {
                msgElement.style.display = 'block';
                msgElement.textContent = '✅ No security issues detected!';
            }
            return;
        }
        
        // Hide the "no categories" message
        if (msgElement) {
            msgElement.style.display = 'none';
        }
        
        // Create category items dynamically
        for (const [category, score] of categoryEntries) {
            const displayName = categoryDisplayNames[category] || category.charAt(0).toUpperCase() + category.slice(1);
            const icon = categoryIcons[category] || '📊';
            
            const itemDiv = document.createElement('div');
            itemDiv.className = 'category-score-item';
            
            let scoreColor = '#34d399';
            if (score < 40) scoreColor = '#f87171';
            else if (score < 60) scoreColor = '#fbbf24';
            else if (score < 80) scoreColor = '#60a5fa';
            
            itemDiv.innerHTML = `
                <span class="cat-label">${icon} ${displayName}</span>
                <span class="cat-value" style="color: ${scoreColor};">${Math.round(score)}/100</span>
            `;
            
            gridContainer.appendChild(itemDiv);
        }
    }
    
    displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerabilities-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Update count
        const countElement = document.getElementById('vuln-count');
        if (countElement) {
            countElement.textContent = vulnerabilities.length;
        }
        
        if (!vulnerabilities.length) {
            container.innerHTML = `
                <div class="no-vulns">
                    <h3>🎉 No vulnerabilities found!</h3>
                    <p>Your code looks secure. Keep up the good work!</p>
                </div>
            `;
            return;
        }
        
        // Sort by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        vulnerabilities.sort((a, b) => {
            return (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99);
        });
        
        for (const vuln of vulnerabilities) {
            const div = document.createElement('div');
            div.className = `vulnerability severity-${vuln.severity || 'low'}`;
            
            const severityLabel = vuln.severity ? vuln.severity.toUpperCase() : 'UNKNOWN';
            
            div.innerHTML = `
                <div class="vuln-header-row">
                    <span class="vuln-type">${this.escapeHtml(vuln.type || 'Unknown Vulnerability')}</span>
                    <span class="vuln-severity ${vuln.severity || 'low'}">${severityLabel}</span>
                </div>
                <div class="vuln-details">
                    ${vuln.cwe_id ? `<p><strong>CWE:</strong> ${this.escapeHtml(vuln.cwe_id)}</p>` : ''}
                    ${vuln.confidence ? `<p><strong>Confidence:</strong> ${this.escapeHtml(vuln.confidence)}</p>` : ''}
                    ${vuln.file_path ? `<p><strong>File:</strong> ${this.escapeHtml(vuln.file_path)}${vuln.line_number ? ` (line ${vuln.line_number})` : ''}</p>` : ''}
                    ${vuln.explanation ? `<p><strong>Explanation:</strong> ${this.escapeHtml(vuln.explanation)}</p>` : ''}
                    ${vuln.mitigation ? `<p><strong>Mitigation:</strong> ${this.escapeHtml(vuln.mitigation)}</p>` : ''}
                    ${vuln.code_snippet ? `<pre><code>${this.escapeHtml(vuln.code_snippet)}</code></pre>` : ''}
                </div>
            `;
            
            container.appendChild(div);
        }
    }
    
    updateSummary(summary) {
        const container = document.getElementById('summary-container');
        if (!container) return;
        
        const severityCounts = summary.by_severity || {};
        const total = summary.total || 0;
        
        container.innerHTML = `
            <div class="summary-grid">
                <div class="summary-item">
                    <span class="summary-label">Total</span>
                    <span class="summary-value">${total}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Critical</span>
                    <span class="summary-value critical">${severityCounts.critical || 0}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">High</span>
                    <span class="summary-value high">${severityCounts.high || 0}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Medium</span>
                    <span class="summary-value medium">${severityCounts.medium || 0}</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Low</span>
                    <span class="summary-value low">${severityCounts.low || 0}</span>
                </div>
            </div>
        `;
    }
    
    displayRecommendations(recommendations) {
        const container = document.getElementById('recommendations');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!recommendations || !recommendations.length) {
            container.innerHTML = '<p>No recommendations available.</p>';
            return;
        }
        
        const list = document.createElement('ul');
        for (const rec of recommendations) {
            const li = document.createElement('li');
            li.textContent = rec;
            list.appendChild(li);
        }
        container.appendChild(list);
    }
    
    updateScannerStatus(scanners) {
        const container = document.getElementById('scanner-status');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (!scanners || !scanners.scanners || !scanners.scanners.length) {
            container.innerHTML = '<p class="text-muted">No scanners detected. Please install scanners.</p>';
            return;
        }
        
        for (const scanner of scanners.scanners) {
            const div = document.createElement('div');
            div.className = 'scanner-card';
            div.innerHTML = `
                <div class="scanner-icon">${this.getScannerIcon(scanner.name)}</div>
                <div class="scanner-info">
                    <div class="scanner-name">${this.escapeHtml(scanner.name)}</div>
                    <div class="scanner-version">v${this.escapeHtml(scanner.version || 'unknown')}</div>
                </div>
                <span class="scanner-status ${scanner.is_installed ? 'installed' : 'missing'}">
                    ${scanner.is_installed ? '✓' : '✗'}
                </span>
            `;
            container.appendChild(div);
        }
    }
    
    getScannerIcon(name) {
        const icons = {
            'Semgrep': '🔍',
            'Bandit': '🐍',
            'Gitleaks': '🔐',
            'Trivy': '📦'
        };
        return icons[name] || '🛡️';
    }
    
    showLoading(message) {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.querySelector('.loading-message').textContent = message;
            overlay.classList.remove('hidden');
        }
    }
    
    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.add('hidden');
        }
    }
    
    showToast(message, type = 'info') {
        const toast = document.getElementById('message-toast');
        if (!toast) {
            console.log(`[${type}] ${message}`);
            return;
        }
        
        toast.className = `toast ${type}`;
        toast.textContent = message;
        toast.classList.remove('hidden');
        
        clearTimeout(this.toastTimeout);
        this.toastTimeout = setTimeout(() => {
            toast.classList.add('hidden');
        }, 5000);
    }
    
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SecurityDashboard();
});

// Tab switching functionality
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        
        const tabName = this.dataset.tab;
        document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
        const targetTab = document.getElementById(`${tabName}-tab`);
        if (targetTab) {
            targetTab.classList.add('active');
        }
    });
});

// File upload zone drag and drop
const uploadZone = document.getElementById('upload-zone');
if (uploadZone) {
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        const fileInput = document.getElementById('file-input');
        if (fileInput) {
            fileInput.files = files;
            updateFileList(files);
        }
    });
    
    const fileInput = document.getElementById('file-input');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            updateFileList(this.files);
        });
    }
}

function updateFileList(files) {
    const container = document.getElementById('file-list');
    if (!container) return;
    
    container.innerHTML = '';
    if (files.length === 0) {
        container.innerHTML = '<span style="color: var(--text-muted); font-size: 14px;">No files selected</span>';
        return;
    }
    
    for (let file of files) {
        const tag = document.createElement('span');
        tag.className = 'file-tag';
        const sizeKB = (file.size / 1024).toFixed(1);
        const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
        const sizeDisplay = file.size > 1024 * 1024 ? `${sizeMB} MB` : `${sizeKB} KB`;
        tag.textContent = `${file.name} (${sizeDisplay})`;
        container.appendChild(tag);
    }
}