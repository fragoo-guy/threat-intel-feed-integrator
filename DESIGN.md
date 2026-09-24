# Product and Interaction Design

## Audience

The primary user is a SOC analyst or CTI learner who needs to scan current indicators quickly, understand why an indicator is present, and export validated data for another security tool.

## Dashboard Direction

The dashboard should feel operational and readable rather than promotional:

- A compact top area for total active IOCs, recent observations, feed health, and high-confidence counts.
- A filter row for indicator type, threat tag, provider, confidence, and last-seen window.
- A searchable IOC table for scanning many indicators without opening detail views.
- A detail view that shows normalized fields first, then source evidence and safe provider metadata.
- Clear loading, empty, rate-limit, and API-error states.
- Neutral, high-contrast colors with restrained severity accents; color must not be the only way to communicate severity.

## Workflow

1. Start with metrics and feed health.
2. Narrow the table with filters or an exact indicator search.
3. Inspect merged source evidence and timestamps.
4. Export the filtered result as CSV or STIX 2.1 JSON.

## Phase Review Gate

Each phase follows this sequence:

1. Implement only the scope of the current phase.
2. Run the narrowest useful test or validation check.
3. Record the result and any limitations in `PROGRESS.md` or the relevant topic document.
4. Ask for user review and feedback.
5. Do not begin the next phase until the current phase is accepted or its follow-up work is explicitly agreed.
