# redteam-agent

A Python harness for authorized AI and agent red-teaming. It plans probes from a
declarative attack library, mutates payloads to defeat input filters, judges each
transcript against the attack's own success criteria, adapts based on what worked,
and writes a JSON plus Markdown report mapped to OWASP.

The default target is an offline mock, so the harness is usable with no network
access and no credentials. Point it at a live endpoint only after you have written
down who approved the test and under which reference.

## Authorization gate

Live targets do not run unless three records exist:

- `authorized_by` - the human who approved the engagement
- `authorization_ref` - the ticket, SOW, or change record covering it
- the target host appears in `allowed_hosts`

The mock target needs none of this. This gate is an accountability record, not a
technical control: it cannot stop someone from acting without approval, so treat
the config file as the real artifact for that purpose.

```bash
python -m redteam_agent validate --config examples/engagement.json
```

`validate` exits `2` with the missing field when the scope is incomplete.

## Quick start

```bash
python -m redteam_agent list-attacks          # the library
python -m redteam_agent demo                  # offline run, writes reports/
python -m redteam_agent run --target mock -v  # offline run, verbose
```

A full sweep that proves every attack out against the mock:

```bash
python -m redteam_agent run --config examples/mock-wide.json
```

## Live target

```bash
export SUPPORT_AGENT_API_KEY=...   # the variable NAME is stored in config, not the secret

python -m redteam_agent run \
  --target http \
  --endpoint https://api.internal.example/v1/chat/completions \
  --allowed-host api.internal.example \
  --authorized-by "K. Huang" \
  --authorization-ref REDTEAM-2026-014 \
  --system-prompt-file ./prompt.txt
```

Three target kinds:

| Kind | What it talks to | Credentials |
|---|---|---|
| `mock` | In-process SupportAssist simulation, deterministic | none |
| `http` | Any chat-completions-shaped JSON endpoint | `api_key_env` (env var name) |
| `openai` | OpenAI-compatible API with tool calls | `api_key_env` |

Secrets are referenced by environment variable name only. The harness never reads
or stores a literal key, and `--api-key-env` is an env var name, not a value.

## How a run works

1. Untested risk categories first, then attacks with the fewest attempts.
2. Plain payload first. Evasion mutations after that: proven families for the
   category, then families not yet tried, then retries. Rotation rather than random
   sampling, so evasion coverage stays broad on a small budget.
3. Multi-turn chains run as one conversation; a chain that proves out reports the
   joined transcript.
4. Judge the transcript against the attack's own criteria plus built-in detectors.
5. On a finding, stop probing that attack. One finding per attack ID.
6. Re-probe once before reporting: same evasion, a second payload from the attack
   (or an identical replay for chains and single-payload attacks). A finding that
   fails to reproduce is marked unconfirmed and sent to manual review. Set
   `exploit_confirmation: false` in the config to skip this step.

Budget knobs: `--max-probes` (binding), `--max-turns`, `--rate-limit`,
`--payloads`, `--mutations`, `--seed`. They default to the config file's values when
omitted. The mock target disables throttling.

Two config-only settings have no CLI flags: `max_tokens` (default 512, sent on every
probe as a completion ceiling) and `exploit_confirmation` (the step-6 re-probe).

`--max-turns` is binding: a multi-turn chain counts one turn per prompt, and the run
stops with `turn budget exhausted` when the cap is reached.

### Run health, evidence, and finding gates

Four roles are borrowed from ARTEX (`docs/artex-patterns.md`), the pattern source
for the planner/worker split, retester verdicts and evidence store:

- **Frontier:** every attack is a planned *intent* (`open -> running -> done |
  exhausted | blocked | dropped`). The report's `frontier` block separates "never
  ran" from "ran and found nothing".
- **Stagnation:** `--stagnation-rounds N` (default 6) stops the run after N
  consecutive attacks that find nothing, records `stagnation detected`, and parks
  the remaining intents. This is what keeps a failing target from eating the budget.
- **Dead target breaker:** `--target-error-limit N` (default 3) stops after N
  consecutive probe errors with `target unhealthy: repeated probe errors`.
- **Guard:** probes that duplicate an already-sent attack+payload+mutation are
  blocked before they leave, every decision is audited (payload digest only), and
  replies are attributed `ok / blocked / error` so a WAF is not mistaken for a clean
  target. The report's `audit` block carries the counts.
- **Retester:** the confirmation step now returns a verdict — `reproduced`,
  `not_reproduced`, or `inconclusive`. A reproduced verdict needs an indicator or an
  actual tool call; an inconclusive retest does not flip a finding to confirmed.
- **Quality gate:** each finding gets `quality: pass | quarantine` plus reasons
  (no transcript, not reproduced, weak impact, low confidence, open manual review).
  It is advisory — findings are never deleted — and the report counts quarantined
  entries.

Evidence log (opt-in, hash-chained, no raw text):

```bash
python -m redteam_agent run --config engagement.json --evidence-dir reports/run-1
# reports/run-1/probes.jsonl   one hashed row per probe, prev-digest chain
# reports/run-1/manifest.json  rows, chain head, target, library version+sha256
```

Every row stores payload/response SHA-256 and lengths, not the text, so the log
cannot leak what the run captured. Findings carry `probe_seq` and `evidence_digest`
so a reviewer can point at the probe that produced them.

### CI gate

`--fail-on` turns findings into an exit code, so the harness can gate a pipeline:

```bash
# exit 3 as soon as a high-or-worse finding is reported; exit 0 otherwise
python -m redteam_agent run --config engagement.json --fail-on high --quiet
```

Exit codes: `0` clean, `2` scope or setup error, `3` gate hit. `--fail-on` accepts
`none` (default), `low`, `medium`, `high`, `critical`.

`--sarif` writes SARIF 2.1.0 (default `redteam.sarif`), one rule per attack and one
result per confirmed finding, with OWASP framework/category, severity, confidence,
reproduction status, and remediation in `properties`. Raw transcripts are deliberately
**excluded**: they can contain the very secrets or PII the run captured, and CI logs
are a poor place to publish those.

```yaml
# .github/workflows/redteam.yml
- run: python -m redteam_agent run --config engagement.json --sarif redteam.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: redteam.sarif
```

## Judging

Rules lead. `RuleJudge` checks the attack's `Expect` criteria (leak keywords,
forbidden tools, canary disclosure) plus category detectors: secret shapes, returned
PII, system-prompt echo, trust bait and urgency framing, citation absence, and
pathological output. A refusal suppresses benign text matches.

An LLM judge is optional and off by default (`--llm-judge`, `--judge-model`). When
enabled it can raise a rule finding's confidence, but an LLM-only finding is always
flagged `needs_manual_review` because no deterministic detector corroborated it. An
unparseable LLM reply falls back to the rules verdict.

## Mapping to OWASP

Findings carry a framework and category:

- `OWASP-LLM-2025` - categories LLM01 through LLM10
- `OWASP-AGENTIC-2026` - categories ASI01 through ASI10

The labels in `redteam_agent/taxonomy.py` are local working shorthand. Check the
official wording on the OWASP project pages before quoting a category name in a
deliverable, and update the taxonomy if the wording differs.

`agentic_class` (A0/A1/A2) is a triage hint derived from whether attacker text
reached a privileged path or executed a tool. Severity escalates one step when a
tool was invoked. Neither is a CVSS or AIVSS score, and the report says so.

## Reports

`reports/redteam-<UTC stamp>.json` (schema `redteam-agent/report/v1`) and the
matching `.md`. Both contain:

- engagement record: approver, reference, target, model, kind
- run record: probes, turns, errors, elapsed, stop reason, budget, seed
- severity counts and a coverage matrix per category, with the mutations that worked
- optional SARIF 2.1.0 for code-scanning consumers (no transcripts in it)
- attack library identity: `LIBRARY_VERSION` plus the attacking file's SHA-256
- frontier and audit summaries, plus the evidence manifest path when enabled
- findings sorted by severity, each with evidence, indicators, reproduction status
  (`yes`, `no`, `not attempted`, and which technique reproduced it), reproduction
  verdict and evidence digest, quality-gate status, remediation, and a reproduction
  command
- limitations, including that rule-based judging needs manual confirmation

## Attack library

Fourteen attacks across twelve categories. Each declares its own payloads, mutation
target, expected impact, and success criteria, so adding a control means adding a
dataclass entry, not editing the judge. `tests/test_run.py` fails if any attack
cannot be proven out against the mock with a wide budget; an attack that cannot
demonstrate risk on a deliberately vulnerable target is not ready to ship.

## Surface scans: web, Windows, macOS, Linux

The model suite is one surface. The same read-only contract extends to the
application and the endpoint:

```bash
# web application: passive headers/TLS/cookies/CORS, exposed artifacts, bounded
# parameter reflection and open-redirect probes; never a state-changing method
python -m redteam_agent scan-web --url https://app.example/   --authorized-by "security-owner" --authorization-ref "TICKET-42"

# Windows endpoint: local PowerShell reads only (Get-/query/show)
python -m redteam_agent audit-host --os windows

# macOS or Linux endpoint over SSH: read-only commands, policy-checked per command
python -m redteam_agent audit-host --os macos --ssh user@host
python -m redteam_agent audit-host --os linux --ssh user@host
```

Each scan writes `surface-<kind>-<target>-<stamp>.json` (SARIF-friendly severity
and category fields) and a Markdown report under `reports/`, which is gitignored.

### Agentic check selection (ReAct)

`redteam_agent/react.py` is a think-act-observe loop with a catalog of read-only
actions. It fingerprints the target first, turns the fingerprint into live
hypotheses, then lets the reasoner choose the next check family from what the
previous observation returned. Two reasoners exist: a deterministic
hypothesis-scoring rule reasoner (always available) and an OpenAI-compatible
model reasoner whose replies are validated against the catalog and the policy
(`--planner-endpoint`, `--planner-model`); a rejected reply falls back to rules.

### Adaptive payloads

`redteam_agent/payload_lab.py` reads each reply and picks the next payload family:
declared evasion transforms first, then delimiter/authority/translation framing,
then compound variants. A digest set guarantees the lab does not resend a payload,
and it stops at the configured variant count.

### Read-only policy

`redteam_agent/policy.py` enforces the non-destructive contract:

- host commands must match a read-only allowlist (`Get-*`, `grep`, `lsof`, `ss`,
  `systemctl is-active`, `fsw ... --get`, `dscl . -read`, ...) and are refused if
  they match a destructive pattern or redirect output to a file;
- web requests must be GET/HEAD/OPTIONS on non-destructive paths, with redirects
  refused so credentials never follow a Location header;
- a model probe whose prize is a mutating tool call is refused by default
  (`--allow-state-changing` opts in, after sandboxing the target's tool scope).
  The offline mock is exempt because it returns canned text and cannot change
  anything.

## PAUSED: live validation

The Linux endpoint audit and the macOS/Windows/web live scans were run against
local and self-owned machines; their reports are intentionally not committed.
The Linux ReAct loop currently stops after the platform check and is being
revisited before the next release.

## Tests

```bash
python -m pytest tests -q
```

`tests/test_agentic.py` covers the ARTEX-derived roles: frontier lifecycle, guard
dedupe/attribution, evidence hash-chain tampering, retester verdicts, quality
gates, stagnation stop, dead-target breaker, and report redaction.

Covers the authorization gate, config merging (CLI flags must not clobber file
values), the mutation families, judge detectors, LLM-only findings, memory dedupe
and severity escalation, agent planning, the full mock sweep, and report generation.

## Limits

- Rule-based judging produces false positives; confirm every finding by hand.
- Findings hold only for the model, version, and system prompt actually tested.
- Probe counts measure coverage sent, not depth of reasoning.
- The mock is a fixture, not a benchmark. Passing against it does not prove a live
  target is safe. It proves the harness can demonstrate the risk it claims.
- The quality gate is advisory metadata. A quarantined finding may still be real,
  and a passed one may still be wrong; review by hand.
- Attack library breadth, not exhaustive coverage of either framework.
- A replay confirms the detector is deterministic; a variant-payload confirmation
  shows the evasion is not tied to one prompt. Neither proves exploitability
  against a production target on its own.

## Safety

This tool is for testing agents you control, or ones you have written authorization
to test. It sends adversarial text to a model and may cause state-changing tool
calls on a live target. Keep `stop_on_critical` on for the first run against a
production-adjacent endpoint, and start with a read-only tool scope.
