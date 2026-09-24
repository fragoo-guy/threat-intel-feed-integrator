# Threat Intelligence Feed Integrator — Project Specification & LLM Prompt

This document provides a complete project specification and prompt template designed to guide LLMs (such as Claude, ChatGPT, or Gemini) in assisting you to build a **Threat Intelligence Feed Integrator** step-by-step.

---

## 📄 Prompt Template (Copy & Paste to Claude)

```markdown
# Role & Project Scope
You are a Senior Cybersecurity Software Engineer and Cyber Threat Intelligence (CTI) Specialist. Act as my lead developer and technical mentor to help me build a full-stack **Threat Intelligence Feed Integrator** from scratch. 

The goal of this project is to aggregate, process, normalize, tag, and visualize Cyber Threat Intelligence (CTI) and Indicators of Compromise (IOCs) from multiple open-source feeds into a centralized Security Operations Center (SOC) dashboard.

---

## 1. System Architecture & Tech Stack
- **Backend**: Python (FastAPI for asynchronous API handling and automatic OpenAPI documentation)
- **Database**: MongoDB (NoSQL schema to handle diverse and semi-structured CTI data feeds)
- **Threat Intelligence Integrations**:
  - AlienVault OTX (Open Threat Exchange)
  - VirusTotal API
  - AbuseIPDB API
  - MISP (Malware Information Sharing Platform)
- **Frontend / Dashboard**: Web UI (Tailwind CSS with HTML/JavaScript, or React/Streamlit) for real-time threat monitoring

---

## 2. Key Features & Functional Requirements

1. **Automated Feed Aggregation & Ingestion**:
   - Asynchronous workers/scheduler to periodically fetch data from threat feed APIs.
   - Normalization pipeline converting heterogeneous vendor responses into a unified JSON schema (Fields: Indicator, Type, Threat Tags, Confidence Score, First/Last Seen, Source Provider).

2. **Tagging & Classification Engine**:
   - Automated rule engine to tag IOCs into specific attack categories (e.g., Malware, Phishing, Command & Control / C2).
   - Deduplication logic to merge identical IOCs across multiple feeds and calculate aggregate confidence scores.

3. **Centralized Visualization Dashboard**:
   - Key security metrics (Total Active IOCs, Feeds Health, Threat Type Distribution).
   - Filterable, searchable IOC table (search by IP, hash, domain, threat tag, or source provider).
   - Detailed inspection view for enriched metadata per indicator.

4. **SOC Export & Integration APIs**:
   - REST endpoints to query filtered IOCs.
   - Export capabilities (STIX/TAXII, CSV, JSON) for integration with SIEM or SOAR tools.

---

## 3. Step-by-Step Implementation Strategy

Please guide me through building this iteratively in six structured phases. Do not generate all code at once—instead, walk me through each step, explaining key CTI concepts along the way:

- **Phase 1**: Environment Setup, Project Directory Structure, and MongoDB Schema Design
- **Phase 2**: Feed Adapters & Data Normalization Engine (AlienVault OTX, VirusTotal, AbuseIPDB, MISP)
- **Phase 3**: Automated Ingestion Scheduler, Deduplication Engine, and Tagging Rules
- **Phase 4**: FastAPI Endpoint Development & Search/Filtering Logic
- **Phase 5**: Frontend Dashboard & Metric Visualizations
- **Phase 6**: Testing, Documentation (`README.md`), and GitHub Deployment Strategy

To begin, please confirm you understand the scope, and start by guiding me through **Phase 1: Project Directory Structure, Environment Setup, and MongoDB Schema Design**.
```

---

## 🛠️ Usage Guidelines

1. **Iterative Development**: Work through one phase at a time with your LLM partner.
2. **Understand the Mechanics**: Focus on understanding how data flows from vendor APIs through the normalization engine into MongoDB [1].
3. **Showcase on GitHub**: Maintain a clean Git commit history and document your API endpoints to highlight your development and CTI engineering skills for prospective SOC employers [1].
