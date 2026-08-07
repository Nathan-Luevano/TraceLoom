# TracerLoom

A detection-engineering pipeline that discovers AIT logs, joins sparse
ground truth, normalizes heterogeneous events into one schema, runs
explainable heuristic detectors, correlates attack stages, and reports
honestly caveated evaluation metrics.

Built against the
[AIT Log Dataset V2.1](https://zenodo.org/records/5789064) (AIT-LDSv2):

> Landauer, M., Skopik, F., Wurzenberger, M. (2022). *AIT Log Dataset
> V2.1: A New Dataset for Evaluation of Line-based Intrusion Detection
> Methods*. AIT Austrian Institute of Technology.
> https://zenodo.org/records/5789064

## Setup

```bash
micromamba create -y -p ./.venv -c conda-forge python=3.12
micromamba run -p ./.venv pip install -e '.[dev]'
```

`pyproject.toml` is the single source of truth for dependencies and dev
tooling (`pytest`, `ruff`, `mypy`); micromamba only manages the
interpreter and virtual environment.

Download the AIT-LDSv2 `russellmitchell` scenario (`*_no-pcaps` variant
is sufficient) and pass `--dataset-root`, or place it at
`./russellmitchell_no-pcaps`. The dataset directory is gitignored and
must never be committed.

```bash
micromamba run -p ./.venv ruff format .
micromamba run -p ./.venv ruff check .
micromamba run -p ./.venv mypy src tests
micromamba run -p ./.venv pytest -q
```

## CLI

```
tracerloom inspect   [--dataset-root PATH] [--config PATH]
tracerloom ingest    [--dataset-root PATH] [--output-root PATH] [--config PATH]
tracerloom detect    [--output-root PATH] [--config PATH]
tracerloom evaluate  [--output-root PATH] [--config PATH]
tracerloom report    [--output-root PATH] [--config PATH]
tracerloom run       [--dataset-root PATH] [--output-root PATH] [--config PATH]
```

`inspect` validates the dataset without ingesting. `ingest` / `detect` /
`evaluate` / `report` are separable phases that hand off state as JSON
under `--output-root`, alongside partitioned Parquet and a dead-letter
log. `run` does all phases in one process:

```bash
micromamba run -p ./.venv tracerloom run \
  --dataset-root /path/to/russellmitchell_no-pcaps \
  --output-root .tracerloom-output
```

`--config` points at a YAML file such as `config/example.yaml`; CLI
flags override it.

## Example output

Captured from a real `tracerloom run` against `russellmitchell_no-pcaps`:

```
dataset: processed_russellmitchell_scenario
events: 614720, dead-lettered: 27775352
alerts: 1979, attack chains: 1
precision=0.01 attack_step_recall=0.64
```

```
## Ingestion
- Total normalized events: 614720
- Parser success rate: 2.2%
- Event-level label coverage: 99.8%

## Detection
- Total alerts: 1979
- Alerts matched to ground truth: 14
- Precision (matched / total): 0.7%
- Attack-step recall: 63.6%
- Alert aggregation ratio (evidence / alert): 38.74
```

The low parser success rate is expected, not a bug: the denominator
includes every line under `gather/**/logs/`, including Suricata, mail,
and other log types this dataset never labels. TracerLoom only parses
the 7 source types that have ground truth, and honestly dead-letters
the rest. Precision (0.7%) is a **lower bound**, not a real
false-positive rate — see [Limitations](#limitations).

## Parser coverage

| Source | Format | Detects |
| --- | --- | --- |
| `auth` | Debian/Ubuntu `auth.log` | su/sudo/ssh auth events |
| `dns` | dnsmasq syslog | DNS query/forward/reply |
| `vpn` | OpenVPN server log | session start/reset, identity verification |
| `web_access` | Apache combined log | HTTP requests |
| `web_error` | Apache error log | HTTP errors |
| `audit` | Linux auditd | PAM sessions, service start/stop, syscalls |
| `monitoring_cpu` | Metricbeat `system.cpu` JSON | per-host CPU samples |

Everything else is dead-lettered with reason `"no parser registered
for this source type"` — ingestion continues past it.

## Detectors

Each reads only `NormalizedEvent` — never labels, `attacks.log`,
`rules/`, or attack timing:

1. **High-rate web scanning** — request volume, unique-path count, and
   404 ratio per (host, source IP).
2. **Webshell-like command activity** — command-style query
   parameters, shell metacharacters, or scripts served from
   upload/temp paths.
3. **Web-service-originated user switch** — a successful `su`/session
   initiated by a known web-service identity.
4. **Privileged command / sensitive file access** — sudo commands or
   audit events touching `/etc/shadow`, `.ssh/`, private keys, etc.
5. **DNS exfiltration** — label length, Shannon entropy, unique
   subdomain count, and query frequency per source IP.
6. **Sustained abnormal CPU load** — consecutive high-utilization
   samples per host, consistent with offline password cracking.
7. **VPN identity anomaly** — deviation from a subject's own
   previously observed source IPs, not an absolute allowlist.

`CorrelationEngine` maps each detector to a kill-chain stage
(reconnaissance, initial access, privilege escalation, command
execution, exfiltration) and chains alerts sharing a host, principal,
or source IP within a sliding window into `AttackChainAlert`s. Full
design in `ARCHITECTURE.md`.

## Limitations

- **Sparse labels.** Only 7 of ~500 log files carry any labels, and
  most benign lines in labeled files are unlabeled by design.
  Precision is therefore a lower bound — an unmatched alert may still
  be a true positive the dataset never labeled.
- **Single-dataset scope.** Every metric here is specific to the
  `russellmitchell` scenario. None of it generalizes to other
  environments or production traffic.
- **Heuristic thresholds.** Calibrated by inspecting this dataset's
  shape, not tuned against a labeled training split.
- **Detection latency is approximate.** Computed as
  `alert.first_seen - matched_evidence_event.timestamp` in a batch
  pipeline, not a live "time to page" metric.
- **Two unparsed, unlabeled log variants**: `other_vhosts_access.log`
  (Apache's vhost-prefixed format) and one host's older `error.log.2`
  layout. Left as documented dead-letter cases.
- **Correlation is heuristic**, not a full attack graph — it misses
  chains that pivot through an entity type outside host/principal/IP.

## Future real log ingestion

`EventSource` (`sources/base.py`) is a two-method Protocol
(`list_files`, `read_lines`). `LocalFileEventSource` is the only
implementation today; nothing downstream — parsers, normalization,
detectors, correlation, evaluation — depends on it directly, only on
`NormalizedEvent`, `SourceFile`, and `RawLine`. A directory watcher,
JSONL socket stream, GCP Cloud Logging, BigQuery, or Splunk adapter
only needs to implement the same two methods.
`tests/test_event_source_protocol.py` proves this by running the full
ingest-and-detect path against a synthetic in-memory `EventSource`.

## Repository layout

```
src/tracerloom/       package source (see ARCHITECTURE.md for module map)
tests/                 unit, integration, one end-to-end test
tests/fixtures/         synthetic, non-dataset fixtures
config/example.yaml     example CLI configuration
ARCHITECTURE.md          design, data flow, future-adapter story
```
