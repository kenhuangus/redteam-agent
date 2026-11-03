"""Append-only evidence log with a hash chain and a run manifest.

ARTEX keeps every tool result in an evidence store and binds findings to the
traffic records that produced them (`evidence/store.go`, `docs/
vulnerability-traffic-evidence.md`). The harness equivalent is one JSONL row
per probe plus a manifest that seals the chain:

* every row carries the digest of the previous row, so deleting or editing a
  row breaks verification;
* rows hold payload/response *hashes* and counts, never raw text, so the log
  itself cannot leak the data the engagement captured;
* findings store the row digest and sequence number, which is what lets a
  reviewer prove a finding came from a probe that actually ran.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


def sha256_hex(blob: bytes | str) -> str:
    if isinstance(blob, str):
        blob = blob.encode("utf-8", "replace")
    return hashlib.sha256(blob).hexdigest()


def _canonical(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class EvidenceStore:
    """One directory per run: ``probes.jsonl`` plus ``manifest.json``."""

    def __init__(self, directory: str | Path, meta: dict[str, Any] | None = None) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "probes.jsonl"
        self.manifest_path = self.dir / "manifest.json"
        self.meta = dict(meta or {})
        self.rows = 0
        self.head = ""
        self._resume()

    def _resume(self) -> None:
        """Re-open an existing chain instead of truncating a prior run."""
        if not self.path.exists():
            return
        last = ""
        count = 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    count += 1
                    try:
                        last = json.loads(line).get("digest", "")
                    except json.JSONDecodeError:
                        last = ""
        self.rows = count
        self.head = last

    # -- write ----------------------------------------------------------
    def record(self, **fields: Any) -> str:
        """Append one probe row; returns its digest (also stored on the finding)."""
        row = {k: v for k, v in fields.items() if v is not None}
        self.rows += 1
        row["seq"] = self.rows
        row["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        row["prev"] = self.head
        row["digest"] = sha256_hex(_canonical(row))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        self.head = row["digest"]
        return str(row["digest"])

    # -- seal -----------------------------------------------------------
    def seal(self, **extra: Any) -> Path:
        manifest = {
            "schema": "redteam-agent/evidence/v1",
            "created_at": self.meta.get("created_at", ""),
            "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "probes": self.rows,
            "chain_head": self.head,
            "probes_path": self.path.name,
            **self.meta,
            **extra,
        }
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return self.manifest_path

    def summary(self) -> dict[str, Any]:
        return {
            "probes_path": str(self.path),
            "manifest_path": str(self.manifest_path),
            "rows": self.rows,
            "chain_head": self.head,
        }

    # -- verify ---------------------------------------------------------
    @staticmethod
    def verify(path: str | Path) -> dict[str, Any]:
        """Walk the chain: the first row whose ``prev`` or ``digest`` is wrong wins."""
        rows = 0
        prev = ""
        bad_at: int | None = None
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                rows += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    bad_at = rows
                    break
                claimed = row.pop("digest", "")
                body = row.get("prev", "")
                if body != prev or sha256_hex(_canonical(row)) != claimed:
                    bad_at = rows
                    break
                prev = claimed
        return {"ok": bad_at is None, "rows": rows, "broken_at": bad_at, "chain_head": prev}
