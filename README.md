# TracerLoom

A log-native intrusion detection pipeline built against the
[AIT Log Dataset V2.1](https://zenodo.org/records/5789064) (AIT-LDSv2),
demonstrating dataset discovery, sparse ground-truth handling,
multi-format log normalization, heuristic detection, attack-chain
correlation, and honest evaluation methodology in one small, tested
codebase.

> Landauer, M., Skopik, F., Wurzenberger, M. (2022). *AIT Log Dataset
> V2.1: A New Dataset for Evaluation of Line-based Intrusion Detection
> Methods*. AIT Austrian Institute of Technology.
> [https://zenodo.org/records/5789064](https://zenodo.org/records/5789064)

## Why this exists

Most portfolio detection projects either fabricate their own logs or
report accuracy numbers without explaining the ground truth those
numbers are measured against. TracerLoom instead runs against a real
published dataset with a real (if sparse) labeled subset, and reports
metrics with explicit caveats about what those numbers can and cannot
claim.

## Setup

### Toolchain

TracerLoom targets Python 3.12. The environment is managed with
[micromamba](https://mamba.readthedocs.io/en/latest/user_guide/micromamba.html)
rather than a system Python install, so the exact interpreter version
is reproducible regardless of what's already on the host.

```bash
# one-time: create a project-local environment pinned to Python 3.12
micromamba create -y -p ./.venv -c conda-forge python=3.12

# install the project + dev tooling into that environment
micromamba run -p ./.venv pip install -e '.[dev]'

# run anything inside the environment via `micromamba run -p ./.venv <cmd>`,
# or activate it directly:
micromamba activate ./.venv
```

`pyproject.toml` remains the single source of truth for the package's
own dependencies (Typer, PyArrow, DuckDB, PyYAML, Pydantic) and its dev
tooling (`pytest`, `ruff`, `mypy`), exposed both as a PEP 735
`[dependency-groups]` table and as a pip-installable `dev` extra so
`pip install -e '.[dev]'` works inside the micromamba environment
without needing `uv`.

*(Earlier iterations of this project used `uv venv` / `uv python
install` for environment management. That was swapped for micromamba
mid-build for consistency with the rest of the toolchain on this
machine -- the package/dependency metadata in `pyproject.toml` did not
change, only how the interpreter and virtual environment are created.)*

### Dataset

Download and unzip the AIT-LDSv2 `russellmitchell` scenario
(`*_no-pcaps` variant is sufficient; the pcaps are not used) and point
`--dataset-root` at it, or place it at `./russellmitchell_no-pcaps`
relative to the repo root (the default). The dataset directory is
gitignored and must never be committed.

### Quality gates

```bash
micromamba run -p ./.venv ruff format .
micromamba run -p ./.venv ruff check .
micromamba run -p ./.venv mypy src tests
micromamba run -p ./.venv pytest -q
```

## CLI reference

```
tracerloom inspect   [--dataset-root PATH] [--config PATH]
tracerloom ingest    [--dataset-root PATH] [--output-root PATH] [--config PATH]
tracerloom detect    [--output-root PATH] [--config PATH]
tracerloom evaluate  [--output-root PATH] [--config PATH]
tracerloom report    [--output-root PATH] [--config PATH]
tracerloom run       [--dataset-root PATH] [--output-root PATH] [--config PATH]
```

`inspect` validates and summarizes the dataset without ingesting
anything. `ingest`, `detect`, `evaluate`, and `report` are separable
phases that hand off state via small JSON files under `--output-root`
(`ingest_meta.json`, `ground_truth.json`, `alerts.json`, `chains.json`,
`reports/evaluation.{json,md}`) plus partitioned Parquet under
`--output-root/parquet` and a dead-letter log under
`--output-root/dead-letter/dead_letters.jsonl`. `run` performs all
phases in one process and is what the example output below was
produced with. `--config` points at a YAML file like
`config/example.yaml`; CLI flags always override it.

```bash
micromamba run -p ./.venv tracerloom run \
  --dataset-root /path/to/russellmitchell_no-pcaps \
  --output-root .tracerloom-output
```

## Example output (real dataset run)

Captured from an actual `tracerloom run` against the
`russellmitchell_no-pcaps` scenario on this machine (values are exact,
not illustrative):

```
dataset: processed_russellmitchell_scenario
events: 614720, dead-lettered: 27775352
alerts: 1979, attack chains: 1
precision=0.01 attack_step_recall=0.64
reports written to .tracerloom-output/reports
```

Excerpt from the generated Markdown report:

```
## Ingestion
- Total normalized events: 614720
- Total dead-lettered lines: 27775352
- Parser success rate: 2.2%
- Total ground-truth label records: 61862
- Event-level label coverage: 99.8%

## Detection
- Total alerts: 1979
- Alerts matched to ground truth: 14
- Precision (matched / total): 0.7%
- Attack-step recall: 63.6%
- Alert aggregation ratio (evidence / alert): 38.74
```

Two things are worth explaining rather than hiding:

- **Parser success rate looks low (2.2%) because the denominator
  includes every line under `gather/**/logs/`, not just the 7 source
  types that actually have a labels/ counterpart.** The dataset ships
  Suricata `eve.json` traffic logs, mail server logs, and many other
  ancillary log types with no ground truth at all; TracerLoom
  deliberately only implements parsers for the log sources that are
  actually labeled in this dataset (see "Parser coverage" below), so
  everything else is honestly dead-lettered rather than silently
  dropped or half-parsed.
- **Precision is 0.7% and is explicitly reported as a lower bound**,
  not a real false-positive rate -- see Limitations below. Attack-step
  recall (63.6% of distinct labeled attack-step categories have at
  least one matching alert) is the more informative number here given
  how sparse the labels are.

## Parser coverage

One parser per log source that has a `labels/` counterpart in this
dataset:

| Source type | Format | Detects |
| --- | --- | --- |
| `auth` | Debian/Ubuntu `auth.log` syslog | su/sudo/ssh auth events |
| `dns` | dnsmasq syslog | DNS query/forward/reply |
| `vpn` | OpenVPN server log | session start/reset, identity verification |
| `web_access` | Apache combined log | HTTP requests |
| `web_error` | Apache error log | HTTP errors |
| `audit` | Linux auditd | PAM sessions, service start/stop, syscalls |
| `monitoring_cpu` | Metricbeat `system.cpu` JSON | per-host CPU utilization samples |

Everything else under `gather/**/logs/` (Suricata, mail server logs,
other syslog facilities, config snapshots outside `logs/`, etc.) has
no registered parser and is dead-lettered with reason `"no parser
registered for this source type"` -- ingestion continues past it.

## Detectors

Each detector reads only `NormalizedEvent` -- never labels,
`attacks.log`, `rules/`, or attack timing:

1. **High-rate web scanning** -- request volume, unique-path count, and
   404 ratio per (host, source IP).
2. **Webshell-like command activity** -- command-style query
   parameters, shell metacharacters, or scripts served from
   upload/temp paths (heuristic, not an exact URL match).
3. **Web-service-originated user switch** -- a successful `su`/session
   where the initiating account matches known web-service identities
   (`www-data`, `apache`, `nginx`, ...).
4. **Privileged command / sensitive file access** -- sudo commands or
   audit events referencing `/etc/shadow`, `.ssh/`, private keys, etc.
5. **DNS exfiltration** -- label length, Shannon entropy, unique
   subdomain count, and query frequency per source IP.
6. **Sustained abnormal CPU load** -- consecutive high-utilization CPU
   samples per host, consistent with offline password cracking.
7. **VPN identity anomaly** -- deviation from a subject's own
   previously observed source IPs, not an absolute allowlist.

## Correlation

`CorrelationEngine` maps each detector to one of five kill-chain
stages (reconnaissance, initial_access, privilege_escalation,
command_execution, exfiltration) and chains alerts sharing a host (or
principal/source-IP) within a sliding time window into
`AttackChainAlert`s once at least two distinct stages appear. See
`ARCHITECTURE.md` for the full mapping.

## Limitations

- **Sparse, incomplete labels.** Only 7 of ~500 log files in this
  dataset have any labeled lines at all, and even within labeled
  files most benign lines are unlabeled by design (AIT-LDSv2 labels
  attack-relevant lines, not a complete per-line classification).
  Precision computed against these labels is a **lower bound**: an
  alert with no labeled evidence event may still be a true positive
  that the dataset simply never labeled.
- **Single-dataset scope.** Every metric in this project is specific
  to one AIT-LDSv2 scenario (`russellmitchell`). None of it is a claim
  about general detection efficacy against other environments, other
  attack styles, or production traffic.
- **Heuristic thresholds.** Detector thresholds (request-count minimums,
  entropy cutoffs, CPU percentage/duration, VPN baseline window size)
  are engineering judgment calibrated by inspecting this dataset's
  shape, not derived from a labeled training split. They are
  reasonable defaults, not tuned optima.
- **Detection latency is an approximation, not a streaming metric.**
  Because this is a batch pipeline, "detection latency" is computed as
  `alert.first_seen - matched_evidence_event.timestamp`, where
  `alert.first_seen` is the earliest timestamp among an alert's
  *own* evidence events. For detectors that aggregate many events into
  one alert (e.g. web scanning), this can be zero or even negative
  when the matched, labeled event occurs after other, earlier,
  unlabeled evidence in the same alert -- it is not a wall-clock
  "time until a human would have been paged" in a live system.
- **Two known unparsed variants, both unlabeled.** `other_vhosts_access.log`
  uses Apache's vhost-prefixed combined-log format (`%v:%p ...`)
  rather than the plain combined format, and one host's `error.log.2`
  uses an older Apache error-log layout; neither file has a `labels/`
  counterpart in this dataset, so they are left as documented
  dead-letter cases rather than special-cased.
- **Correlation is a heuristic time-window/shared-key grouping, not a
  full attack graph.** It will miss multi-stage chains that pivot
  through an entity type the correlation key doesn't capture (e.g. a
  chain that moves from a source IP to a completely different host
  with no shared host/principal/IP linking them).

## Future real log ingestion

`sources/base.py::EventSource` is a two-method Protocol
(`list_files`, `read_lines`) that `sources/local_files.py` implements
today by walking `gather/` on disk. Nothing downstream -- parsers,
normalization, detectors, correlation, evaluation -- depends on that
concrete implementation; they all depend only on `NormalizedEvent`,
`SourceFile`, and `RawLine`. Future adapters (a directory watcher, a
JSONL stream over a socket, GCP Cloud Logging, BigQuery, Splunk) only
need to implement the same two methods against their own backing
store; `tests/test_event_source_protocol.py` proves this by running
the full ingest-and-detect path against a synthetic in-memory
`EventSource` that never touches the filesystem. See
`ARCHITECTURE.md` for the full design.

## Repository layout

```
src/tracerloom/     the package (see ARCHITECTURE.md for module map)
tests/               unit, integration, and one end-to-end test, plus
                      tests/fixtures/ synthetic (non-dataset) fixtures
config/example.yaml   example CLI configuration
ARCHITECTURE.md        design, data flow, future-adapter story
```
