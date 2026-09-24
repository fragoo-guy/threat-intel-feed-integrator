# Threat Intelligence Feed Integrator

A free-tier Cyber Threat Intelligence (CTI) platform that collects indicators of compromise (IOCs) from open-source feeds, normalizes and deduplicates them, applies threat tags, stores them in MongoDB Atlas, and presents them through a FastAPI service and Streamlit SOC dashboard.

## Project Status

The project is being built in six phases. Phase 1 establishes the environment, project boundaries, and normalized MongoDB schema. See [PROGRESS.md](PROGRESS.md) for the current status.

Project decisions are kept in separate living documents: [TECH_STACK.md](TECH_STACK.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [DESIGN.md](DESIGN.md). Each phase is tested and reviewed before the next phase begins.

## Architecture

- **Feed adapters:** asynchronous `httpx` clients for AlienVault OTX, VirusTotal Public API, and AbuseIPDB.
- **Normalization:** Pydantic models convert provider-specific records into one IOC representation.
- **Storage:** MongoDB Atlas free shared tier through Motor, with a unique indicator key for deduplication.
- **Scheduling:** APScheduler runs ingestion jobs at a configurable interval.
- **API:** FastAPI exposes health, IOC search, metrics, and export endpoints.
- **Dashboard:** Streamlit consumes the API for SOC-style metrics, filtering, and IOC inspection.
- **Exports:** CSV and STIX 2.1 JSON.

MISP is deliberately optional and deferred. The project will use static public OSINT/sample fixtures for future MISP adapter tests; no hosted or self-managed MISP deployment is required.

## Free-Tier Requirements

- Python 3.11 or newer
- A MongoDB Atlas free shared cluster (512 MB)
- Free API keys for OTX, VirusTotal Public API, and AbuseIPDB
- No paid cloud service, queue, cache, or API tier is required

Provider quotas and terms vary. Configure conservative polling intervals and only use credentials for the intended provider account.

## Local Setup

1. Create and activate a virtual environment:

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install pinned dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill in the MongoDB URI and provider keys. Never commit `.env`.

4. Create a MongoDB Atlas free cluster, database user, and network access rule for your development machine. Use the generated connection string as `MONGODB_URI`.

5. Start the API after the backend phases are implemented:

   ```powershell
   uvicorn app.main:app --reload
   ```

6. Start the dashboard in a second terminal after the dashboard phase is implemented:

   ```powershell
   streamlit run dashboard/app.py
   ```

The FastAPI documentation will be available at `http://127.0.0.1:8000/docs` and the Streamlit dashboard at `http://localhost:8501`.

## Planned Layout

```text
app/
  api/          FastAPI routers and request/response handling
  config/       Environment-backed settings
  db/           MongoDB client, indexes, and repositories
  exports/      CSV and STIX 2.1 serializers
  feeds/       Provider adapters and feed response parsing
  models/       Pydantic domain and persistence schemas
  services/     Normalization, tagging, deduplication, and ingestion orchestration
dashboard/      Streamlit application
tests/
  fixtures/     Static provider and deferred MISP sample data
```

## Security and Data Handling

- API keys and database credentials belong only in `.env` or a local secret store.
- Logs must not print authorization headers, API keys, or full connection strings.
- Provider responses are untrusted input and must pass schema validation before storage.
- IOC values are security data; use access controls and retention decisions appropriate to the deployment.
