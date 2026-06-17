# Security

## API Keys & Secrets

This project ships with **no** API keys in the repository.

- ``.env`` is git-ignored. Every secret (LLM keys, integration tokens)
  must live there and never be hard-coded into source files.
- The CI / audit scripts do not require any key to run; they use
  mocked LLM clients. Real keys are only needed for the opt-in
  ``RUN_LLM_TESTS=1`` runtime test suite.

## What to do if you leaked a key

1. **Rotate the key immediately** at the upstream provider (Google
   Cloud Console, TokenRouter dashboard, etc.). A leaked key that
   was committed to git history is in the clear even after the
   file is rewritten.
2. Rewrite the local git history with ``git filter-repo`` or
   ``git filter-branch`` so the secret is removed from every
   commit. (``git push --force`` is required afterwards if the
   branch was already published.)
3. Add the secret to ``.env`` only, never to source.

## Logging policy

- LLM error messages are redacted via ``app.core.redaction.redact_secrets``
  before they reach logs, the audit trail, or the API response.
- The status endpoint (``/api/status``) only reports whether the
  provider is *configured* — it never returns the key itself.
- The agent context never receives the raw API key.

## Production checklist

Before deploying:

- [ ] ``.env`` exists on the host with real keys and is readable
      only by the service user.
- [ ] ``ENABLE_REAL_RESPONSE=false`` in ``.env`` (the system
      defaults to simulated containment actions).
- [ ] The protected-IP allowlist in
      ``.pi/extensions/security-permission-gate/index.ts`` covers
      your management subnets.
- [ ] TLS is terminated upstream of FastAPI (e.g. via nginx or
      a load balancer).
