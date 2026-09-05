# Contributing

Team Relay welcomes focused bug fixes, runtime adapters, tests, documentation,
and deployment improvements.

Before opening a change:

1. Discuss protocol, authentication, permission, or persistence changes first.
2. Keep provider-specific behavior behind a runtime adapter.
3. Never weaken recipient approval or let remote input select local commands,
   credentials, MCP configuration, models, or filesystem policy.
4. Add tests for authorization failures and cross-organization isolation.
5. Run `make check` and, for concurrency-sensitive changes, `make race`.

Do not commit secrets, captured prompts, real email addresses, production URLs,
provider credentials, or private runtime event logs. By submitting a
contribution, you agree that it is licensed under Apache-2.0.
