# Team 4 (Application, Security & Deployment) - Initial Exploration Notes

## 1. Summary of Findings

**Source Reviews:**
- `README.md`: Lists various threat intelligence data sources (CVE, NVD, Shadowserver, etc.), and mentions that some require registration/API keys. It also notes that if the LLM cannot query APIs directly, static downloadable data might need to be used.
- `Capstone Kickoff Presentation.pptx`: Confirms the project's goal of creating a private, internally deployed AI-based tool for cybersecurity analysis. Emphasizes "human-in-the-loop decision-making", "clear access controls", and "system boundaries". The solution is for internal use and should enrich data, summarize reports, and identify previously observed threats.
- `Evaluation Criteria for Scenarios.xlsx`: Currently only contains a single overarching statement ("Build a production-readiness evaluation set sourced from real user tasks (not synthetic benchmarks), with ground truth examples from Public datasets"). It does not contain any specific rows detailing role definitions, audit log access, or specific grading criteria for Team 4.
- `notes.txt`: Contains a very brief, comma-separated list: `ollama, rbac, web ui,`. This suggests the key areas of focus but lacks detail.
- `llm/gateway/interface.py`: This file is currently completely empty (0 bytes).
- `Workplan (txt)`: Reinforces Team 4's responsibilities: backend APIs, investigator dashboard (explicitly *not* a generic chatbot), auth/RBAC, audit logging, and deployment configurations (API + on-premise).

## 2. Conflicts & Ambiguities

**Authentication & RBAC Intent:**
- There is a material ambiguity regarding Authentication and RBAC. The project calls for "Clear access controls" and `notes.txt` mentions `rbac`. The workplan specifically tasks us with building an "Investigator dashboard (not a generic chatbot UI)" and implementing "Authentication/RBAC".
- **The Issue:** Ollama does not natively support multi-user RBAC. While Open WebUI provides this out-of-the-box, the project strictly forbids a "generic conversational chatbot" UI, meaning we cannot just deploy Open WebUI to solve the frontend and RBAC requirements. We must build a custom investigator workflow dashboard.
- **Resulting Question:** Should we implement a custom JWT/session-based authentication system from scratch in `backend/auth/` (with a small local database/store for users and roles: investigator, admin, auditor), or is there an expectation to integrate with an existing Identity Provider (like Keycloak or a UNICC internal system)? 

**LLM Gateway Interface:**
- Because `llm/gateway/interface.py` is completely empty, there is no existing contract to consume. As per Step 7 of the instructions, I will define a minimal draft version of this interface to allow Team 4's backend to build against it.

**Evaluation Criteria:**
- The `.xlsx` file lacks specific acceptance criteria for the backend, auth, audit, or investigator workflow. We will proceed with the requirements listed in the workplan (roles: investigator, admin, auditor; immutable audit logs; dual deployment modes).

## 3. Open Questions for the Project Lead / Professor

1. **Authentication/RBAC Approach:** Given that we are building a custom dashboard (not Open WebUI) and Ollama lacks multi-user RBAC, should I implement a standard custom authentication system (e.g., JWT-based auth with a local database for users/roles) in the `backend/auth/` module, or should this integrate with a specific external Identity Provider?
2. **LLM Gateway Signature:** Since `interface.py` is currently empty, I will draft a unified interface for both Ollama and Gemini (likely a single call signature with a config to toggle the backend). Does this align with the expected division of work?

---
*Note: I will pause here for feedback on the open questions before proceeding to write implementation code.*
