# Benchmarks this harness can integrate

Research date: 2026-11-03. Every ID, year, size and license below was read from the
benchmark's own arXiv record, GitHub metadata/README, or dataset card at that date;
nothing here is remembered from training data. Access to paywalled venues was not attempted,
so numbers are what the project publishes, not what a venue abstract says.

The harness currently has **no committed benchmark**. It has a fixture-based test suite
(mock target, 105 tests) and ad-hoc live smoke runs. This document lists the real
benchmarks worth integrating, the metric each one gives us, and the exact seam in the
code where it attaches.

---

## 1. What a benchmark has to do here

The harness produces `Attack` objects (payload, expected behavior, framework category)
against a `TargetClient`, and `SurfaceFinding` objects against an endpoint. A benchmark is
useful only if it supplies one of:

1. **a payload bank** the harness can turn into `Attack` entries;
2. **an oracle** that decides whether a finding or a reply is correct, so we can report
   precision/recall, not just counts;
3. **a benign control set** that measures false positives, so a judge that flags
   everything does not score 100%;
4. **an environment + ground truth** for agentic/web targets whose state the benchmark
   owns and grades.

Without (2) or (3) a "benchmark" is only a payload set. Two of the biggest publicly
marketed suites fail exactly this test when used naively: HarmBench supplies a certified
judge but no benign controls (false positives are not measured), and
OWASP Benchmark supplies both positives and negatives but no exploit oracle.
Integration has to supply the missing side.

---

## 2. Model and agent safety benchmarks

### 2.1 Chat-model harm benchmarks

| Benchmark | Year | Size (verified) | Oracle | License | What it gives the harness |
|---|---|---|---|---|---|
| HarmBench (`2402.04249`) | 2024 | 1,214 rows in `harmbench_behaviors_text_test.csv`, 315 in the val file (including contextual variants); 7 attack methods in 1.0 | Certified classifier `cais/HarmBench-Llama-2-13b-cls` | MIT | Sensitivity on harmful behaviors, a judge we can calibrate against |
| JailbreakBench (`2404.01318`) | 2024 | 100 behaviors, evolving jailbreak artifacts, leaderboard | Standardized threat model + scoring functions; HarmBench-compatible behaviors | MIT | Comparable attack success rate across models; artifacts to replay |
| StrongREJECT (`2402.10260`) | 2024 | Curated forbidden prompts (small subset loader), 6 harm categories | Rubric-based response scorer trained to agree with human judges | MIT (`alexandrasouly/strongreject`) | A quality-weighted success score instead of a binary "any refusal" |
| XSTest (`2308.01263`) | 2023 | 250 safe prompts in 10 types, 200 unsafe contrasts | Labeled safe/unsafe | CC-BY-4.0 | **False-positive and over-refusal controls** |
| CyberSecEval 1 (`2312.04724`) | 2023 | Insecure-code generation and cyberattack compliance sets | Automated test-case pipeline | Repo `meta-llama/PurpleLlama`, no asserted SPDX id | Code-assistant and exploit-helpfulness coverage |
| CyberSecEval 2 (`2404.13161`) | 2024 | Prompt injection, interpreter abuse, False Refusal Rate sets | Own metrics, including FRR | Same repo | FRR measurement aligned with the paper's definition |

HarmBench is the closest match to the current model suite, but it measures one side only.
Two HarmBench facts shape integration: the judge is a specific 13B Llama-2 classifier, not
a general model, so a different judge invalidates comparability; and the CSV rows repeat
behaviors with different `ContextString` values, so deduplicating by `BehaviorID` changes
the denominator. The harness should keep `BehaviorID` and report both raw-row and unique-behavior
scores.

JailbreakBench is the better first target for a Harness benchmark loop because the leaderboard
fixes system prompts, chat templates and scoring, which is exactly the coupling the harness
currently leaves to the operator.

XSTest is the cheapest high-value integration: 250 labeled safe prompts become the specificity
half of a two-sided benchmark, and turning our existing `controls.py` into an XSTest adapter
needs no new judge.

### 2.2 Agentic security benchmarks

| Benchmark | Year | Size (verified) | Oracle | License | Fit |
|---|---|---|---|---|---|
| AgentDojo (`2406.13352`) | 2024 | 97 tasks, 629 security test cases, 4 domains | Utility + attack success on owned environment | MIT | Best agentic target: measures both halves, extends with new attacks |
| AgentHarm (`2410.09024`) | 2024 | Paper: 110 behaviors (440 augmented), 11 harm categories. Released set: 44 test + 8 validation base behaviors (176 + 32 augmented) | Refusal + capability-retention after jailbreak | MIT plus a clause restricting use to improving AI safety/security | Multi-step agent harm; needs an agent-environment adapter |
| InjecAgent (`2403.02691`) | 2024 | 1,054 test cases, 17 user tools, 62 attacker tools | Direct-harm and data-exfiltration labels | MIT | Indirect prompt injection through tool results |
| Agent Security Bench (`2410.02644`) | 2024 | 10 scenarios, 400+ tools, 27 attack/defense methods, 7 metrics | Own metrics; highest reported ASR 84.30% | MIT | Broad attack taxonomy; heavy install footprint |
| SafeAgentBench (`2412.13178`) | 2024 | 750 tasks, 10 hazards, SafeAgentEnv with 17 actions | Execution + semantic safety labels | Dataset CC-BY-4.0; repo has no declared license | Embodied safety planning; outside read-only host scope |
| Ajar (`2609.26900`) | 2026 | attaches to AgentDojo and reuses its tasks/tool schemas | Open-privilege measurement as a third axis | MIT | Measures excessive permission, not attack success |
| Know Your Agent (`2607.19837`) | 2026 | recon-driven agent pentesting framework | Benchmark suite + black-box profiles | Project release | Reconnaissance-driven payload generation |

AgentDojo is the single benchmark that could validate the ReAct planner properly: it grades
benign utility, attack success and, via Ajar, open privilege. Our `Reactor` has no environment
concept today; integration means a benchmark-owned `Environment` object that exposes tool calls
and returns observations, with our reasoner driving it.

AgentHarm and InjecAgent both need the target to accept tool schemas and multi-turn state.
The current `TargetClient` abstraction is chat-only. The honest options are (a) add an
`AgentTarget` adapter whose `run_task()` delegates to the benchmark's environment, or
(b) declare agentic benchmarks out of scope until the planner is wired in. Option (a) is the
only one that lets the read-only policy still apply, because the benchmark environment can be
wrapped in a sandbox; the target agent's tool calls are then policy-checked per call.

### 2.3 Agentic offensive capability benchmarks

These grade an agent that *exploits* a target. They conflict with the read-only guarantee and
must not be run against a real machine.

| Benchmark | Year | Size (verified) | Oracle | License | Constraints |
|---|---|---|---|---|---|
| Cybench (`2408.08926`) | 2024 | 40 professional CTF tasks from 4 competitions, with subtasks | Flags solved, per-task environments | Apache-2.0 (`andyzorigin/cybench`) | Docker per task; exploit steps |
| CyberGym (`2506.02548`) | 2025 | 1,507 real-world vulns across 188 projects | PoC reproduces the vuln | Apache-2.0 | PoC generation, codebase per task |
| CyberGym-E2E (`2606.04460`) | 2026 | 920 vulns across 139 OSS projects | Discovery, PoC, patch generation | Separate implementation repo, license not verified | Long-running, multi-stage |
| AutoPenBench (`2410.03225`) | 2024 | 33 increasing-difficulty tasks | Milestones + success rate | MIT | 8 machines; pentest actions |
| CVE-Bench (`2503.17332`) | 2025 | 40 critical CVEs, zero-day and one-day variants | Application-side state checks (DB read, RCE marker, admin login, outbound GET) | Apache-2.0 | Docker + Inspect; reference exploits on request |

The right role for these is a **lab mode**: disposable containers, no host network route,
explicit `--lab-authorization`, results never committed, and a separate report class that
does not claim read-only. Running Cybench or CVE-Bench under the read-only flag would be a
lie in the report, and the policy would block the exploit anyway.

---

## 3. Web application ground truth

| Benchmark | Year | Size (verified) | Ground truth | License | Fit |
|---|---|---|---|---|---|
| OWASP Benchmark for Java v1.2 | Latest release v1.2, test suite maintained since 2016 | Slightly less than 3,000 test cases; per-class counts published (e.g., 2,708 command injection) | `expectedresults.csv`: every case labeled true/false positive with CWE | App GPL-2.0, BenchmarkUtils GPL-3.0 | Precision/recall for `scan-web` |
| OWASP Benchmark for Python v0.1 | 2026 page | Per-class counts published (e.g., 168 path traversal) | Same expected-results format | Same project | Python-native variant |
| OWASP Juice Shop | Current (2026-10-30 repo) | Challenge-based, no fixed count asserted here | Challenge completion state | MIT | Endpoint exploration + challenge oracle |
| DVWA | Current (2026-10-18 repo) | Module-based | Low difficulty, modules | GPL-3.0 | Manual/exploitative; weak oracle |
| WebGoat | Current (2026-11-02 repo) | Lesson + flag based | Lesson completion | No asserted license | Teaching oracle, not reproducible |

OWASP Benchmark is the **only** web benchmark here with a per-test-case oracle that supports
precision/recall. Its categories overlap only partially with `scan-web`'s current checks:
headers, cookies, redirects and weak hashing map cleanly; SQL injection, XSS and path
traversal need parameterized GET probes that the policy allows but the scanner does not emit
today. Integration should start by mapping `WEB.*` check IDs onto expected-results rows,
reports precision only for mapped classes, and explicitly lists unmapped recall gaps.

Two operational constraints: the OWASP benchmark must be downloaded, not vendored, because
the app and utilities are GPL; and each test case is a servlet URL, so the adapter needs the
running app plus `expectedresults.csv`, not the source tree.

Juice Shop is a better *exploration* target than a *measurement* target: it gives a rich path
surface and a completion oracle, but it does not give per-request ground truth, so it belongs
in smoke tests and in ReAct path-discovery evaluation rather than in precision/recall.

---

## 4. Endpoint compliance baselines

| Baseline | What it produces | License | Use |
|---|---|---|---|
| Lynis | Hardening index, warnings, suggestions per check, text/JSON-ish report | GPL-3.0 | Agreement on Linux/macOS checks; CI-style regression |
| OpenSCAP + ComplianceAsCode content | Scanner + SCAP/OVAL content (NIST 800-53, CIS variants where published) | LGPL-2.1 (scanner), content project has its own license | Machine-readable ARF/XML results; agreement on control outcomes |
| CIS Benchmarks / CIS-CAT Lite | Authoritative control text, free Lite evaluator for some platforms | Content under CIS terms; tool terms | Source of truth for what a Windows/macOS/Linux check *should* assert |

Our Windows/macOS/Linux auditors implement a narrow CIS subset. The benchmarks should be used
as an **oracle for agreement**, not as a leaderboard: run Lynis or OpenSCAP next to our auditor
on the same host, map only the checks that overlap, and report agreement, false findings and
missed controls. A hardening index delta is not comparable across tools and should not be
reported as one.

Windows has no free CIS evaluator equivalent; CIS-CAT Lite is limited and its redistribution
terms are not open. The integration for Windows is therefore control-text mapping plus a
reviewed manual checklist, not an automated oracle. Claiming a Windows "score" would
overstate what the auditor knows.

---

## 5. Scanner comparators and meta-standards

| Tool/standard | Role | License | Fit |
|---|---|---|---|
| Garak | LLM vulnerability scanner with probe + detector modules | Apache-2.0 | Compare detections on the same payloads; import its probe catalogs |
| Promptfoo | Red-team/eval runner with attack plugins and assertions | MIT | Comparator for assertions; no need to import |
| Agentic Benchmark Checklist (`2507.02825`) | Best-practice checklist for building agentic benchmarks | Paper 2025 | Acceptance checklist before we publish any harness score |
| Purple Llama CyberSecEval | Repo containing CyberSecEval 1/2 | No asserted SPDX id on repo | Source of prompt-injection and FRR test sets; check per-file terms |

Garak is the most useful comparator because its probe/detector split mirrors ours: same
target, same probes, different detection thresholds. Running it beside the harness turns
"our judge says 12 findings" into "12 findings, 7 shared with Garak, 5 harness-only." That is
the kind of number a security team can argue with.

---

## 6. Where each benchmark attaches in the code

```
redteam_agent/
  attacks.py        Attack, Expect, LIBRARY_VERSION   <- payload banks (HarmBench/JBB)
  controls.py       control_attack()                   <- XSTest, CyberSecEval FRR sets
  targets.py        HttpTarget, OpenAITarget, OllamaTarget, AgentTarget (missing)
  judges.py         judge_rule(), judge_llm()          <- HarmBench classifier, StrongREJECT rubric
  policy.py         check_attack_effect()              <- lab-mode gate, state-changing probe gate
  react.py          Reactor, ActionCatalog             <- AgentDojo/Ajar environment actions
  surface/model.py  SurfaceScan, SurfaceFinding        <- OWASP expectedresults join
  surface/webapp.py WebSession checks                  <- OWASP/Juice Shop targets
  surface/linux.py, macos.py, windows.py               <- Lynis/OpenSCAP agreement
  report.py         Markdown/JSON                      <- metric sections
```

Proposed package:

```
benchmarks/
  registry.py        BenchmarkSpec(id, version, license, url, checksum, scorer)
  fetch.py           download-on-demand, checksum, never vendor GPL/CIS content
  banks/             harmbench.py, jailbreakbench.py, xstest.py, cyberseceval.py
  agents/            agentdojo.py, agentharm.py, injecagent.py, asb.py
  web/               owasp_benchmark.py, juice_shop.py
  hosts/             lynis.py, openscap.py
  laboratory/        cybench.py, cybergym.py, cve_bench.py, autopenbench.py
  scorers.py         sensitivity, specificity, asr, utility, frr, precision/recall, agreement
  runner.py          bench(...) -> BenchResult (json + markdown), cost accounting
```

Key rule: a benchmark adapter must be able to answer "what is the denominator?" If it cannot,
it is not a benchmark.

### 6.1 Payload-bank adapters

```python
# banks/harmbench.py
def to_attacks(rows, behaviors):
    for row in rows:
        yield Attack(
            id=f"HB.{row.behavior_id}",
            prompt=row.behavior,
            expect=Expect.HARMFUL,          # classifier decides, not the regex judge
            framework="HARMBENCH",
            category=row.semantic_category,
            judge="harmbench-classifier",   # new field on Attack
        )
```

This requires one addition to `Attack`: an `oracle` name that routes scoring to a pluggable
judge instead of `judge_rule()`. Without it, HarmBench rows will be judged by the wrong
detector and the score will be meaningless.

### 6.2 Control adapters

```python
# controls.py
def xstest_controls(rows):
    return [control_attack(
        prompt=row.prompt,
        expected=row.label,       # "safe" -> must comply; "unsafe" -> must refuse
        framework="XSTEST",
        category=row.prompt_type,
    ) for row in rows]
```

`control_attack()` already exists; the adapter is a row loader. XSTest's 250 safe prompts
become "must not be judged harmful" controls, which directly measures the false-positive rate
the current suite cannot compute.

### 6.3 Agent environment adapter

```python
class AgentTarget(Protocol):
    def run_task(self, task_id: str, tools: list[dict], checker) -> TaskResult: ...
    def policy_checked(self, tool_call) -> bool: ...
```

AgentDojo/Ajar/InjecAgent plug in here. The checker belongs to the benchmark; the policy check
belongs to us, per tool call. Utility and attack success stay in the benchmark's report, mapped
into our report schema without rewriting numbers.

### 6.4 Web oracle

```python
# web/owasp_benchmark.py
def score(scan: SurfaceScan, expected: dict[str, bool], mapping: dict[str, str]) -> dict:
    mapped = [f for f in scan.findings if f.check_id in mapping]
    tp = sum(mapping[f.check_id] and expected[f.target] for f in mapped)
    fp = sum(not expected[f.target] for f in mapped)
    ...
```

Requires our findings to carry a test-case identifier. `SurfaceFinding` has `check_id` and
`target`; the `target` URL of a benchmark servlet is the join key once the scanner is driven
per URL rather than per site.

### 6.5 Host agreement

```python
# hosts/lynis.py
def agreement(our: SurfaceScan, lynis: LynisReport) -> dict:
    # map only overlapping checks; never compare hardening index
```

Lynis exposes a hardening index; comparing it to our severity counts is the single most
common way this integration would go wrong.

---

## 7. Metrics and reporting changes

| Metric | Formula | Which benchmarks | Guardrail |
|---|---|---|---|
| Sensitivity | attacks answered / attacks sent | HarmBench, JBB, CyberSecEval | Report unique `BehaviorID` count, not rows |
| Specificity | safe controls not flagged / safe controls | XSTest, CyberSecEval FRR | A judge that flags everything scores 0 here |
| False-positive rate | flagged safe / all safe | XSTest | Same denominator as specificity, mirrored |
| ASR | benchmark-defined | JBB, AgentDojo | Do not redefine; import the benchmark's number |
| Utility under attack | tasks completed / tasks | AgentDojo | Never merge with ASR |
| Open privilege | unneeded allowed calls / total | Ajar | Third axis, not folded into ASR |
| Precision / recall | TP/(TP+FP), TP/(TP+FN) | OWASP Benchmark | Mapped classes only; list unmapped recalls |
| Agreement | matched findings / union | Lynis/OpenSCAP | Never "hardening score" |
| Comparator overlap | shared findings / harness findings | Garak | Run same payloads, same target, same budget |
| Cost | prompt + completion tokens, wall time, attempts | all | Per benchmark, per run, not merged |

Two reporting rules:

1. **Denominator disclosure.** Every score carries the exact denominator and the benchmark
   version pinned by commit or dataset revision. A number without a denominator is not a
   benchmark result.
2. **No composite score.** Sensitivity and specificity stay separate; a single index hides
   exactly the failure mode (over-refusal) the user cares about.

---

## 8. The read-only conflict, stated plainly

| Benchmark class | State change? | Allowed today | Required mode |
|---|---|---|---|
| HarmBench/JBB/StrongREJECT/XSTest prompts | no (model replies only) | yes | normal |
| AgentDojo/Ajar/InjecAgent (sandboxed tools) | sandboxed only | after `AgentTarget` + per-call policy | sandbox |
| OWASP Benchmark/Juice Shop (GET-only probing) | no writes if GET only | yes | normal |
| Cybench/CyberGym/CVE-Bench/AutoPenBench | yes, exploitation | **no** | `--lab`, disposable containers |
| Lynis/OpenSCAP | read-only audit (Lynis writes a log file) | read mode, log to temp | read mode |

`PolicyEngine` already refuses redirects, output redirection and destructive commands. Lab
mode does not relax that policy; it runs the exploit benchmark in containers where even a
successful exploit hits a disposable environment, and the report carries
`mode: laboratory` so nobody mistakes the result for a safe live scan.

---

## 9. Phased plan

### Phase 0 - measurement skeleton (small)
Write `benchmarks/registry.py`, `fetch.py`, `scorers.py`, `runner.py`, and a
`bench` CLI subcommand. No benchmarks yet; this phase defines `BenchResult` with denominator
and pinned version fields, plus token/latency accounting. Acceptance: running `bench` with no
registered benchmark fails loudly, not silently.

### Phase 1 - two-sided model benchmark (medium)
1. XSTest safe/unsafe controls (controls.py adapter).
2. JailbreakBench behaviors through a `judge` field on `Attack`.
3. HarmBench classifier judge through a configurable endpoint (13B, likely Mac mini MLX or a
   hosted model; a local 26B is not required).
4. Report: sensitivity, specificity, FPR, cost, per-category breakdown.

Acceptance: the same run produces both numbers, and a deliberately over-flagging judge scores
specificity near zero while the real judge does not.

### Phase 2 - web precision/recall (medium)
OWASP Benchmark Java v1.2 as a Docker target, `expectedresults.csv` as oracle, `scan-web`
driven per servlet URL, mapped only for headers/cookies/redirects/weak hashing. Report
precision, recall per mapped class, and the explicit unmapped list (SQLi, XSS, path traversal).
Acceptance: no claim of recall for classes the scanner cannot emit.

### Phase 3 - agentic security (large)
`AgentTarget` adapter, AgentDojo first (97 tasks/629 cases), Ajar third axis, then InjecAgent
and AgentHarm if the environment adapters hold up. Acceptance: utility and ASR reported
separately, and open privilege as a third axis.

### Phase 4 - comparator + host agreement (medium)
Garak overlap on Phase 1 payloads; Lynis/OpenSCAP agreement on Linux and macOS. Windows stays
manual control mapping with no score. Acceptance: overlap and agreement numbers exist, and
neither is reported as a single index.

### Phase 5 - laboratory mode (large, optional)
Cybench, CyberGym, CVE-Bench, AutoPenBench behind `--lab` with disposable containers, explicit
authorization, and a report class that cannot be confused with a live scan. Acceptance: lab
report says `mode: laboratory` and never appears in the normal run list.

---

## 10. Risks

- **Judge dependence.** HarmBench's score depends on `cais/HarmBench-Llama-2-13b-cls`; a
  different judge is a different benchmark. Keep the judge name in the manifest.
- **Dataset licenses.** HarmBench/JBB/StrongREJECT MIT; XSTest CC-BY-4.0; AgentHarm is MIT
  plus a clause that restricts use to improving AI safety and security; SafeAgentBench dataset CC-BY-4.0; OWASP app and utils GPL; WebGoat has no
  asserted license; CIS content is not redistributable. Fetch, do not vendor.
- **Denominator drift.** HarmBench rows duplicate behaviors via contexts; JBB artifacts evolve.
  Pin versions and report unique-behavior denominators.
- **Contamination.** These sets are public and likely memorized by strong models; a score
  measures model familiarity too. It is not a clean estimate of real-world resistance.
- **Lab-mode leakage.** Exploit benchmarks need isolation. A container with host networking
  turns a benchmark into an incident.
- **Scope inflation.** A Windows auditor with six checks does not earn a CIS "score." Report
  coverage, not compliance.

---

## 11. Recommendation

Integrate, in this order:

1. **XSTest** - specificity controls, near-zero new code.
2. **JailbreakBench + HarmBench judge** - sensitivity with a certified oracle. Two-sided
   benchmark.
3. **OWASP Benchmark Java v1.2** - precision/recall for the web scanner, with explicit mapping.
4. **AgentDojo + Ajar** - agentic utility, ASR and open privilege; the only way to test the
   ReAct planner honestly.
5. **Garak overlap and Lynis agreement** - comparators that keep the numbers honest.
6. **Lab mode** - Cybench/CyberGym/CVE-Bench, clearly separated.

Skip for now: SafeAgentBench (embodied, outside scope), ASB (heavy install, overlapping with
AgentDojo), WebGoat/DVWA (weak oracle), CIS-CAT (license and coverage), OSWorld (capability,
not security).

Do not ship a composite "red-team score" in any of these integrations.

---

## Sources

- HarmBench: https://arxiv.org/abs/2402.04249 (2024), https://github.com/centerforaisafety/HarmBench (MIT)
- JailbreakBench: https://arxiv.org/abs/2404.01318 (2024), https://github.com/JailbreakBench/jailbreakbench (MIT)
- StrongREJECT: https://arxiv.org/abs/2402.10260 (2024), https://github.com/alexandrasouly/strongreject (MIT)
- XSTest: https://arxiv.org/abs/2308.01263 (2023), https://github.com/paul-rottger/xstest (CC-BY-4.0)
- CyberSecEval: https://arxiv.org/abs/2312.04724 (2023); CyberSecEval 2: https://arxiv.org/abs/2404.13161 (2024)
- AgentDojo: https://arxiv.org/abs/2406.13352 (2024), https://github.com/ethz-spylab/agentdojo (MIT)
- AgentHarm: https://arxiv.org/abs/2410.09024 (2024), https://huggingface.co/datasets/ai-safety-institute/AgentHarm (MIT plus a safety/security-only clause)
- InjecAgent: https://arxiv.org/abs/2403.02691 (2024), https://github.com/uiuc-kang-lab/InjecAgent (MIT)
- Agent Security Bench: https://arxiv.org/abs/2410.02644 (2024), https://github.com/agiresearch/ASB (MIT)
- SafeAgentBench: https://arxiv.org/abs/2412.13178 (2024), https://huggingface.co/datasets/safeagentbench/SafeAgentBench (CC-BY-4.0)
- Cybench: https://arxiv.org/abs/2408.08926 (2024), https://github.com/andyzorigin/cybench (Apache-2.0)
- CyberGym: https://arxiv.org/abs/2506.02548 (2025), https://github.com/sunblaze-ucb/cybergym (Apache-2.0)
- CyberGym-E2E: https://arxiv.org/abs/2606.04460 (2026)
- AutoPenBench: https://arxiv.org/abs/2410.03225 (2024), https://github.com/lucagioacchini/auto-pen-bench (MIT)
- CVE-Bench: https://arxiv.org/abs/2503.17332 (2025), https://github.com/uiuc-kang-lab/cve-bench (Apache-2.0)
- Ajar: https://arxiv.org/abs/2609.26900 (2026), https://github.com/reSHARMA/Ajar (MIT)
- Know Your Agent: https://arxiv.org/abs/2607.19837 (2026)
- OWASP Benchmark: https://owasp.org/www-project-benchmark, https://github.com/OWASP-Benchmark/BenchmarkJava (GPL-2.0), https://github.com/OWASP-Benchmark/BenchmarkUtils (GPL-3.0)
- Juice Shop: https://github.com/juice-shop/juice-shop (MIT)
- DVWA: https://github.com/digininja/DVWA (GPL-3.0); WebGoat: https://github.com/WebGoat/WebGoat (no asserted SPDX id)
- Lynis: https://github.com/CISOfy/lynis (GPL-3.0); OpenSCAP: https://github.com/OpenSCAP/openscap (LGPL-2.1)
- Garak: https://github.com/NVIDIA/garak (Apache-2.0); Promptfoo: https://github.com/promptfoo/promptfoo (MIT)
- Agentic Benchmark Checklist: https://arxiv.org/abs/2507.02825 (2025)
