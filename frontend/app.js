document.addEventListener("DOMContentLoaded", () => {
    // ------------------------------------------------------------------
    // Safe display helpers.
    // Anything that comes from a report or from the AI is shown as PLAIN TEXT
    // (textContent), never inserted as page code (innerHTML). A report - or an
    // AI tricked by a report - could otherwise put code into the investigator's
    // browser (this attack is called XSS).
    // ------------------------------------------------------------------
    function textElement(tag, text, className) {
        const el = document.createElement(tag);
        el.textContent = text;
        if (className) el.className = className;
        return el;
    }

    function textList(items) {
        const list = document.createElement("ul");
        items.forEach(item => list.appendChild(textElement("li", String(item))));
        return list;
    }

    function showInBox(boxId, ...children) {
        const box = document.getElementById(boxId);
        box.replaceChildren(...children);
    }

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
                
                const title = textElement("strong", "Extracted IOCs:");
                if (entitiesData.iocs.length === 0) {
                    showInBox("entities-display", title,
                        textElement("p", "No indicators (CVEs, IPs, domains, hashes) found in this report.", "placeholder-text"));
                } else {
                    showInBox("entities-display", title, textList(entitiesData.iocs));
                }
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
                // Built with textContent (not innerHTML) so text from the server is
                // always shown as plain text and can never run as code in the page.
                const box = document.getElementById("threats-display");
                box.innerHTML = "";
                const title = document.createElement("strong");
                title.textContent = "Threat Matches:";
                box.appendChild(title);

                if (data.status === "unavailable" || data.matches.length === 0) {
                    const note = document.createElement("p");
                    note.className = "placeholder-text";
                    note.textContent = data.message || "No matches found.";
                    box.appendChild(note);
                } else {
                    const list = document.createElement("ul");
                    data.matches.forEach(m => {
                        const item = document.createElement("li");
                        const tactics = (m.mitre_tactics || []).join(", ");
                        item.textContent = `${m.threat} (Confidence: ${m.confidence})` + (tactics ? ` - ${tactics}` : "");
                        list.appendChild(item);
                    });
                    box.appendChild(list);
                }
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
                // The AI's answer is shown as plain text; line breaks are kept by CSS.
                showInBox("summary-display",
                    textElement("strong", "Summary:"),
                    textElement("p", data.summary, "ai-text"),
                    textElement("strong", "Key Points:"),
                    textList(data.key_points || []));
                document.getElementById("step-3").classList.remove("disabled");
                showToast("Synthesis complete", "success");
            } else {
                const err = await res.json();
                const message = err.detail || "Synthesis failed";
                // textContent (not innerHTML) so the error text is shown as plain text
                const box = document.getElementById("summary-display");
                box.innerHTML = "";
                const title = document.createElement("strong");
                title.textContent = "Summary could not be generated:";
                const reason = document.createElement("p");
                reason.textContent = message;
                box.append(title, reason);
                document.getElementById("step-3").classList.remove("disabled");
                showToast(message, "error");
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
                // Every cell is filled with textContent (plain text), never innerHTML:
                // entries can contain text typed by anyone, e.g. a made-up username
                // from a failed login, and it must never run as code in this page.
                const cell = (text) => {
                    const td = document.createElement("td");
                    td.textContent = text;
                    return td;
                };
                logs.forEach(log => {
                    let details = {};
                    try { details = JSON.parse(log.details); } catch (e) { /* show the rest anyway */ }

                    // Stored in UTC; shown in this computer's local time, with its time zone.
                    const when = new Date(log.timestamp).toLocaleString(undefined, { timeZoneName: "short" });
                    let who = log.username || log.user;
                    if (details.attempted_username) who += ` (tried: ${details.attempted_username})`;

                    const tr = document.createElement("tr");
                    tr.appendChild(cell(when));
                    tr.appendChild(cell(who));
                    const roleCell = document.createElement("td");
                    const badge = document.createElement("span");
                    badge.className = "badge";
                    badge.textContent = log.role;
                    roleCell.appendChild(badge);
                    tr.appendChild(roleCell);
                    tr.appendChild(cell(log.action));
                    tr.appendChild(cell(details.llm_backend_used || "-"));
                    tr.appendChild(cell(details.outcome || "-"));

                    const viewCell = document.createElement("td");
                    const viewBtn = document.createElement("button");
                    viewBtn.className = "btn outline-btn small-btn";
                    viewBtn.textContent = "View";
                    viewBtn.addEventListener("click", () => alert(JSON.stringify(details, null, 2)));
                    viewCell.appendChild(viewBtn);
                    tr.appendChild(viewCell);

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
