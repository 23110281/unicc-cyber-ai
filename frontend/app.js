document.addEventListener("DOMContentLoaded", () => {
    // Check auth status
    const isLoggedIn = document.cookie.includes("access_token");
    let currentRole = localStorage.getItem("userRole");

    if (isLoggedIn) {
        showView("dashboard-view");
        updateNavForRole(currentRole);
    } else {
        showView("login-view");
    }

    // Login Form
    document.getElementById("login-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const u = document.getElementById("username").value;
        const p = document.getElementById("password").value;
        const err = document.getElementById("login-error");
        err.textContent = "";

        try {
            const res = await fetch("/api/v1/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username: u, password: p })
            });

            if (res.ok) {
                const data = await res.json();
                localStorage.setItem("userRole", data.role);
                currentRole = data.role;
                showView("dashboard-view");
                updateNavForRole(currentRole);
                showToast("Login successful", "success");
            } else {
                const data = await res.json();
                err.textContent = data.detail || "Login failed";
            }
        } catch (error) {
            err.textContent = "Network error";
        }
    });

    // Logout
    document.getElementById("logout-btn").addEventListener("click", async () => {
        await fetch("/api/v1/auth/logout", { method: "POST" });
        localStorage.removeItem("userRole");
        showView("login-view");
        resetWorkflow();
    });

    // Navigation Tabs
    document.querySelectorAll(".nav-tab").forEach(tab => {
        tab.addEventListener("click", (e) => {
            document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
            e.target.classList.add("active");
            
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            const targetId = e.target.getAttribute("data-target");
            document.getElementById(targetId).classList.add("active");

            if (targetId === "audit-tab") loadAuditLogs();
            if (targetId === "admin-tab") loadConfig();
        });
    });

    // Workflow State
    let currentCorrelationId = null;
    let extractedEntities = null;

    // Step 1: Analyze & Extract
    document.getElementById("analyze-btn").addEventListener("click", async () => {
        const text = document.getElementById("report-input").value;
        if (!text.trim()) return showToast("Report text cannot be empty", "error");

        const btn = document.getElementById("analyze-btn");
        btn.textContent = "Processing...";
        btn.disabled = true;

        try {
            // First analyze to get correlation ID
            let res = await fetch("/api/v1/investigation/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ report_text: text })
            });
            let data = await res.json();
            currentCorrelationId = data.correlation_id;

            // Then extract entities
            res = await fetch("/api/v1/investigation/entities", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ report_text: text, correlation_id: currentCorrelationId })
            });

            if (res.ok) {
                const entitiesData = await res.json();
                extractedEntities = entitiesData.iocs;
                
                let html = `<strong>Extracted IOCs:</strong><ul>`;
                entitiesData.iocs.forEach(ioc => html += `<li>${ioc}</li>`);
                html += `</ul>`;
                
                document.getElementById("entities-display").innerHTML = html;
                document.getElementById("step-2").classList.remove("disabled");
                document.getElementById("threat-match-btn").disabled = false;
                showToast("Extraction complete", "success");
            } else {
                const err = await res.json();
                showToast(err.detail || "Extraction failed", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Analyze & Extract Entities";
            btn.disabled = false;
        }
    });

    // Step 2: Threat Matching
    document.getElementById("threat-match-btn").addEventListener("click", async () => {
        const btn = document.getElementById("threat-match-btn");
        btn.textContent = "Matching...";
        btn.disabled = true;

        try {
            const res = await fetch("/api/v1/investigation/threats", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ entities: extractedEntities, correlation_id: currentCorrelationId })
            });

            if (res.ok) {
                const data = await res.json();
                let html = `<strong>Threat Matches:</strong><ul>`;
                data.matches.forEach(m => html += `<li>${m.threat} (Confidence: ${m.confidence}) - ${m.mitre_tactics.join(', ')}</li>`);
                html += `</ul>`;
                
                document.getElementById("threats-display").innerHTML = html;
                document.getElementById("summarize-btn").disabled = false;
                showToast("Threat matching complete", "success");
            } else {
                showToast("Threat matching failed", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Run Threat Matching";
        }
    });

    // Step 2b: Summarize
    document.getElementById("summarize-btn").addEventListener("click", async () => {
        const btn = document.getElementById("summarize-btn");
        btn.textContent = "Synthesizing...";
        btn.disabled = true;

        const evidence = document.getElementById("report-input").value + "\n" + document.getElementById("threats-display").innerText;

        try {
            const res = await fetch("/api/v1/llm/summarize", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ evidence: evidence, correlation_id: currentCorrelationId })
            });

            if (res.ok) {
                const data = await res.json();
                let html = `<strong>Summary:</strong><p>${data.summary.replace(/\n/g, '<br>')}</p>`;
                html += `<strong>Key Points:</strong><ul>`;
                data.key_points.forEach(kp => html += `<li>${kp}</li>`);
                html += `</ul>`;
                
                document.getElementById("summary-display").innerHTML = html;
                document.getElementById("step-3").classList.remove("disabled");
                showToast("Synthesis complete", "success");
            } else {
                const err = await res.json();
                showToast(err.detail || "Synthesis failed", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.textContent = "Synthesize Summary";
            btn.disabled = false;
        }
    });

    // Step 3: Decision
    document.getElementById("submit-decision-btn").addEventListener("click", async () => {
        const decision = document.getElementById("decision-select").value;
        const notes = document.getElementById("decision-notes").value;
        const btn = document.getElementById("submit-decision-btn");
        
        btn.disabled = true;
        try {
            const res = await fetch("/api/v1/investigation/decision", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ decision, notes, correlation_id: currentCorrelationId })
            });
            if (res.ok) {
                showToast("Decision recorded successfully!", "success");
                setTimeout(resetWorkflow, 2000);
            } else {
                showToast("Failed to record decision", "error");
            }
        } catch (e) {
            showToast("Network error", "error");
        } finally {
            btn.disabled = false;
        }
    });

    // Audit Logs
    document.getElementById("refresh-audit-btn").addEventListener("click", loadAuditLogs);
    async function loadAuditLogs() {
        try {
            const res = await fetch("/api/v1/admin/audit-logs");
            if (res.ok) {
                const logs = await res.json();
                const tbody = document.querySelector("#audit-table tbody");
                tbody.innerHTML = "";
                logs.forEach(log => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.user}</td>
                        <td><span class="badge">${log.role}</span></td>
                        <td>${log.action}</td>
                        <td>${JSON.parse(log.details).llm_backend_used || '-'}</td>
                        <td>${JSON.parse(log.details).outcome}</td>
                        <td><button onclick='alert(this.getAttribute("data-details"))' data-details='${log.details.replace(/'/g, "&apos;").replace(/"/g, "&quot;")}' class="btn outline-btn small-btn">View</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        } catch (e) {
            showToast("Failed to load audit logs", "error");
        }
    }

    // Admin Config
    async function loadConfig() {
        try {
            const res = await fetch("/api/v1/admin/config");
            if (res.ok) {
                const data = await res.json();
                document.getElementById("llm-backend-select").value = data.llm_backend;
            }
        } catch (e) {
            showToast("Failed to load config", "error");
        }
    }

    document.getElementById("save-config-btn").addEventListener("click", async () => {
        const backend = document.getElementById("llm-backend-select").value;
        try {
            const res = await fetch("/api/v1/admin/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ llm_backend: backend })
            });
            if (res.ok) showToast("Configuration saved", "success");
        } catch (e) {
            showToast("Failed to save config", "error");
        }
    });

    // Helpers
    function showView(viewId) {
        document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
        document.getElementById(viewId).classList.add("active");
    }

    function updateNavForRole(role) {
        document.getElementById("user-role-badge").textContent = role;
        document.querySelectorAll(".admin-only").forEach(el => el.style.display = 'none');
        document.querySelectorAll(".auditor-only").forEach(el => el.style.display = 'none');
        
        if (role === "admin") {
            document.querySelectorAll(".admin-only").forEach(el => el.style.display = 'block');
        } else if (role === "auditor") {
            document.querySelectorAll(".auditor-only").forEach(el => el.style.display = 'block');
        }
    }

    function resetWorkflow() {
        currentCorrelationId = null;
        extractedEntities = null;
        document.getElementById("report-input").value = "";
        document.getElementById("entities-display").innerHTML = '<p class="placeholder-text">Waiting for extraction...</p>';
        document.getElementById("threats-display").innerHTML = "";
        document.getElementById("summary-display").innerHTML = '<p class="placeholder-text">Waiting for synthesis...</p>';
        document.getElementById("step-2").classList.add("disabled");
        document.getElementById("step-3").classList.add("disabled");
        document.getElementById("threat-match-btn").disabled = true;
        document.getElementById("summarize-btn").disabled = true;
    }

    function showToast(msg, type = "error") {
        const container = document.getElementById("toast-container");
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }
});
