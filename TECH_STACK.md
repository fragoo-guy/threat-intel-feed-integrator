# Technology Stack

This document records the technology choices for the Threat Intelligence Feed Integrator and the reason each belongs in the project.

| Area | Choice | Role | Constraint |
|---|---|---|---|
| Language | Python 3.11+ | Shared language for API, ingestion, exports, and dashboard | Free and locally runnable |
| API | FastAPI | Async REST API, validation boundary, and OpenAPI docs | No paid service required |
| Validation | Pydantic 2 | Normalized IOC and API schemas | Rejects malformed provider data early |
| Database | MongoDB Atlas free shared tier | IOC storage, deduplication, and queries | 512 MB free tier |
| Database driver | Motor | Async MongoDB access from FastAPI and ingestion jobs | Open source |
| HTTP client | httpx | Async provider requests and timeout handling | Open source |
| Scheduler | APScheduler | Periodic feed ingestion without Celery or Redis | Runs in the application process |
| Dashboard | Streamlit | Python-only SOC dashboard | No separate JavaScript build |
| Configuration | python-dotenv | Loads local `.env` settings | Secrets remain outside Git |
| Exports | stix2 and Python CSV support | STIX 2.1 JSON and CSV output | Uses open formats |
| Testing | pytest and pytest-asyncio | Unit and async integration tests | Runs locally |

## Provider Scope

- AlienVault OTX: required feed adapter.
- VirusTotal Public API: required feed adapter, respecting the free quota of 4 requests per minute and 500 requests per day.
- AbuseIPDB: required feed adapter, respecting its free daily quota.
- MISP: deferred. Use static public OSINT/sample fixtures for tests; do not require a hosted or self-managed MISP instance.

## Operating Rules

1. Provider credentials are loaded from `.env` and never committed.
2. Every provider response is untrusted input and is validated before persistence.
3. Network calls use explicit timeouts and provider-aware rate limiting.
4. The dashboard talks to FastAPI and does not connect directly to MongoDB.
5. Free-tier limits are part of the implementation, not an afterthought.
