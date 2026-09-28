# CHIYE-NET

Repository for the CHIYE-NET personal network infrastructure.

## Authority and ownership

- Formal Work Owner: `00｜Command Center`
- Architecture Authority: `01｜Architecture & Decisions`
- Runtime Adapter Domain Owner: `03｜Proxy & Routing`
- Infrastructure Mechanics: `02｜VPS & Network`
- Security Gate: `05｜Security & Secrets`
- Operations / Independent Functional Verification: `06｜Operations & Monitoring`
- Execution Capability: `Codex / Work`

Codex is an execution capability, not the Domain Owner or Approval Authority.

## Source-of-truth boundary

The Operational Routing Policy Source of Truth remains the `03｜Proxy & Routing`
`Versioned Canonical Routing Policy`. Generated sing-box configuration is a
`Derived Artifact`; this repository does not establish a second Node, Routing,
or Config Source of Truth.

The Canonical Production Runtime is `sing-box`. The accepted control flow is:

```text
Versioned Canonical Routing Policy
→ 03 Runtime Adapter
→ Validated Candidate Config
→ Preflight
→ Confirm Backup Readiness
→ Snapshot
→ Build Candidate State
→ Offline Validate
→ Atomic / Bounded Commit
→ End-to-End Verify
→ Secret-safe Evidence
```

## Current authorization boundary

This bootstrap binds the repository, working tree, implementation branch,
logical Lab environment, and evidence path only. Runtime Adapter implementation,
privileged host mutation, secret-bearing mutation, Lab or Production failover,
Production deployment, and automatic failback are not authorized by this
bootstrap.

Evidence for the Lab Runtime Adapter is recorded under
`docs/evidence/lab-runtime-adapter/`.
