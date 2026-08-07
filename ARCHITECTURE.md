# TracerLoom Architecture

TracerLoom is a batch detection pipeline over the AIT Log Dataset V2.1
(AIT-LDSv2). It ingests raw host logs, normalizes them into one fixed
event schema, runs heuristic detectors and a correlation engine over
that schema, and evaluates the result against the dataset's sparse
ground-truth labels -- without ever letting labels leak into detection.

## Data flow

```
gather/<host>/logs/**          labels/<host>/logs/**
        |                              |
        v                              v
  LocalFileEventSource  <----  label loader (labels/loader.py)
        |                              |
        |  (raw_path, line_number, content)  joined BEFORE parsing
        v                              |
  ingest/pipeline.py  --------->  GroundTruthEvent table (separate)
        |
        v  (per-line parser lookup by relative path)
  parsing/registry.py -> parsing/parsers/*.py
        |
        v
  NormalizedEvent (events/model.py) --or--> DeadLetter (parsing/base.py)
        |
        v
  storage/parquet_store.py (partitioned: dataset/source_type/date)
        |
        v
  detection/rules/*.py (Detector Protocol, reads NormalizedEvent only)
        |
        v
  Alert (detection/alert.py)
        |
        v
  correlation/engine.py -> AttackChainAlert
        |
        v
  evaluation/metrics.py (joins Alert.evidence_event_ids against the
                          separate GroundTruthEvent table by event_id)
        |
        v
  reporting/{json_report,markdown_report}.py
```

## Why labels are joined before parsing

`labels/*.jsonl` records reference a 1-based line number in the
*original* raw file. If normalization filtered, reordered, or otherwise
transformed lines before the label join happened, those line numbers
would silently point at the wrong content. `ingest/pipeline.py` reads
every raw line through the same enumeration used for label lookup, and
only afterwards hands the line to a parser -- so the label join is
correct independent of whether that particular line parses, is
malformed, or belongs to a source with no registered parser at all.
Lines whose labels never resolve to a real line during ingestion are
still emitted as `GroundTruthEvent` records with `event_id=None`
(`tests/test_ingest_pipeline.py::test_orphaned_out_of_range_label_does_not_crash_and_has_no_event`
covers this as an off-by-one/out-of-range regression case).

## Why ground truth is a separate table

`NormalizedEvent` (`events/model.py`) has a fixed schema with no label
or rule-id field anywhere in it -- `tests/test_events_model.py::test_normalized_event_schema_has_no_label_fields`
enforces this by construction. `GroundTruthEvent` (`ingest/pipeline.py`)
is a distinct dataclass produced by the same ingestion pass but never
merged into the Parquet-backed normalized event store, and detectors
(`detection/base.py::Detector`) only ever receive
`Sequence[NormalizedEvent]`. The evaluation engine is the only code
that is allowed to see both tables at once, and it only reads them --
it never writes label information back into the normalized store.

## event_id and idempotency

`compute_event_id(raw_path, raw_line, raw_content)` (`events/model.py`)
is a truncated SHA-256 of those three inputs. Because it depends only
on content that is stable across reruns (not on wall-clock time or
process-local counters), re-running `tracerloom ingest` against an
unchanged dataset produces byte-identical event IDs, and
`storage/parquet_store.write_events` rewrites the partitioned output
directory from scratch each run so reruns are idempotent rather than
append-only.

## Detection interface

`detection/base.py::Detector` is a two-member Protocol: a `rule_id`
string and `detect(events: Sequence[NormalizedEvent]) -> list[Alert]`.
Every concrete detector under `detection/rules/` is a small,
single-purpose class implementing that Protocol and nothing else --
no detector imports the dataset's `rules/`, `attacks.log`, or the
label loader. `tests/test_event_source_protocol.py` proves the
inverse property for ingestion: an entirely different `EventSource`
implementation (an in-memory fake, not `LocalFileEventSource`) can
feed the same parser registry and the same detectors and produce the
same kind of alerts, because nothing downstream of `NormalizedEvent`
depends on how the events were sourced.

## Correlation engine

`correlation/engine.py::CorrelationEngine` maps each detector's
`rule_id` to one of five kill-chain stages (`correlation/stages.py`:
reconnaissance, initial_access, privilege_escalation,
command_execution, exfiltration), groups alerts by a correlation key
(host, falling back to principal, falling back to source IP), and
chains alerts within a sliding time window into an `AttackChainAlert`
once at least two distinct stages appear for the same key. This is
intentionally a heuristic, not a full graph-based correlation engine --
see the Limitations section of the README for what that trades away.

## Evaluation engine

`evaluation/metrics.py::compute_evaluation_report` is the only place
in the codebase that reads both `NormalizedEvent`/`Alert` and
`GroundTruthEvent` at the same time. It matches alerts to ground truth
by intersecting `Alert.evidence_event_ids` with the set of event IDs
that carry at least one label, and reports every metric requested by
the project brief (event-level label coverage, attack-step recall,
alert-to-ground-truth matches, precision with an explicit
lower-bound caveat, detection latency, unmatched-alerts-per-10k,
attack-chain coverage, alert aggregation ratio, parser success rate,
and breakdowns by source and by label). Detectors never call into this
module, and this module never calls into detectors -- the dependency
is one-directional.

## Future real-time ingestion: EventSource

`sources/base.py::EventSource` is a two-method Protocol:
`list_files() -> Iterable[SourceFile]` and
`read_lines(source_file) -> Iterator[RawLine]`. `sources/local_files.py`
is the only implementation shipped today, walking `gather/` on disk.
Everything downstream of `EventSource` -- the parser registry, the
normalization pipeline, every detector, the correlation engine, and
the evaluation engine -- depends only on `NormalizedEvent`,
`SourceFile`, and `RawLine`, never on `Path` or local-filesystem
concepts directly.

A future adapter (directory watch, a JSONL stream over a socket, GCP
Logging, BigQuery, Splunk) only needs to implement `list_files` /
`read_lines` against whatever backing store it wraps -- e.g. a GCP
Logging adapter would page through `ListLogEntries` results and yield
one `RawLine` per entry, with `SourceFile.raw_path` set to a stable
log-name-based identifier instead of a filesystem path. No change
would be required to `ingest/pipeline.py`, any parser, any detector,
the correlation engine, or the evaluation engine, because none of them
import `sources.local_files` -- they only import the `EventSource`
Protocol and `NormalizedEvent`. `tests/test_event_source_protocol.py`
exists specifically to keep this property from silently regressing.

## Module layout

```
src/tracerloom/
  config.py            configurable dataset/output roots
  logging_setup.py      structured JSON logging
  orchestration.py       glues phases together for the CLI
  serialization.py       JSON round-trip for CLI hand-off between phases
  discovery/             dataset.yaml + gather/ + labels/ validation
  labels/                sparse JSONL ground-truth loader
  sources/                EventSource Protocol + local-files adapter
  parsing/                per-source-type LineParser implementations
  events/                 NormalizedEvent schema + event_id hashing
  ingest/                 label-join + parse orchestration
  storage/                partitioned Parquet read/write
  detection/              Detector Protocol, Alert model, 7 rules
  correlation/            kill-chain stage mapping + time-window engine
  evaluation/             ground-truth-aware metrics
  reporting/              JSON + Markdown rendering
  cli/                    Typer entry point
```

[!WARNING]
This architecture document is AI-generated and may nkt be 100% accurate.