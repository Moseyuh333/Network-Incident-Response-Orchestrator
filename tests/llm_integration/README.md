# LLM Integration Test Suite

Tests the LLM-assisted analysis path end-to-end. N.I.R.O.'s detection pipeline
has two layers:

1. **Rule engine + ML anomaly detector** (always runs) — produces findings
2. **LLM-assisted agent analysis** (opt-in, costs API quota) — produces
   structured narrative, MITRE mapping, recommended actions

The `tests/security_scenarios/` suite covers layer 1. This suite covers
layer 2.

## Important: API quota

The LLM tests hit Google GenAI for real. Each scenario = 1 API call. With
25 scenarios, that's 25 calls per run. Set the `N.I.R.O.`-side config
(`LLM_MAX_TOKENS`, `LLM_TEMPERATURE`) to reasonable values and watch your
quota.

## Setup

The tests reuse the `.env` file in the project root. Make sure:

```bash
LLM_PROVIDER=google
LLM_API_KEY=<your-key>     # or GOOGLE_API_KEY
LLM_MODEL=gemini-1.5-flash # recommended — fast, cheap, reliable
```

We **don't** auto-set the model. If you keep the default
`models/gemma-4-31b-it` you may hit 503 quota errors and the test will
fall back to the rule-based path.

## Running

```bash
# Run all LLM scenarios (opt-in, costs quota)
RUN_LLM_TESTS=1 python -m tests.llm_integration.run_all

# Run specific scenarios
RUN_LLM_TESTS=1 python -m tests.llm_integration.run_all --only s02 s05

# Verify LLM provider is reachable without running scenarios (cheap)
python -m tests.llm_integration.probe
```

If `RUN_LLM_TESTS` is unset, the runner prints a one-line reminder and
exits 0 — so it's safe to add to CI without accidentally burning quota.

## What gets tested

For each security scenario, after the rule engine produces a finding we
ask the LLM agent to analyse the same context and verify:

1. **Output schema** — JSON validates against `LLMOutputSchema`
2. **Availability** — the LLM responds (or we record the fallback)
3. **Latency** — completes within the 30s budget
4. **Type agreement** — the LLM's `incident_type` matches the rule's
5. **MITRE coverage** — at least one technique is returned for known
   attack patterns
6. **Recommended actions** — non-empty, all entries have `action`/`risk`/
   `requires_human_approval`

## Layout

```
tests/llm_integration/
├── README.md             ← you are here
├── run_all.py            ← scenario runner
├── probe.py              ← cheap LLM reachability check
├── llm_runner.py         ← shared helper that calls the agent
├── scenarios/            ← thin wrappers around security_scenarios
└── results/              ← JSON reports (gitignored)
```
