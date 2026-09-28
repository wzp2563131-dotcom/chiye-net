# Lab Runtime Adapter Evidence

This directory is the secret-safe evidence location for the accepted `03 Runtime
Adapter Contract` lifecycle. It records evidence; it does not become a routing,
node, or generated-config source of truth.

## Repository binding

- Authoritative repository: `wzp2563131-dotcom/chiye-net`
- Repository URL: `https://github.com/wzp2563131-dotcom/chiye-net`
- Working tree: `/Users/lushinian/Documents/Codex/chiye-net`
- Base branch: `main`
- Implementation branch: `impl/lab-runtime-adapter-binding`
- Lab environment: `Lab` (logical binding only; no host mutation authorized)
- Domain Owner: `03｜Proxy & Routing`
- Execution Capability: `Codex / Work`
- Verifier: `06｜Operations & Monitoring`
- Return route: `Codex / Work → 00｜Command Center`

Exact base and implementation commits must be captured in each candidate's
evidence record after the relevant commit exists. Never infer a commit from a
branch name.

## Required evidence record

Each implementation candidate evidence record must include:

- repository identity;
- base commit and implementation commit;
- implementation branch;
- changed files and diff reference;
- test commands and complete results;
- Architecture, Runtime Adapter, Infrastructure, Security, and Operations
  contract versions used by the candidate;
- Registry version;
- evidence references and remaining blockers;
- rollback information.

Unknown versions or evidence must be written as `UNKNOWN`; `UNKNOWN` never
qualifies as PASS.

## Secret handling

Evidence must not contain plaintext secrets, credentials, private keys, tokens,
or secret-bearing generated configuration. Use redacted identifiers and
secret-safe references only.
