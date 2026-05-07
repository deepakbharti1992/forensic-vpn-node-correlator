"""
Forensic CSV/Excel exporter with per-row SHA-256 integrity hashing.
"""
from __future__ import annotations

import csv
import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pandas as pd

from pairing_engine import CorrelatedPair

log = logging.getLogger(__name__)

COLUMNS = [
    "timestamp", "entry_node", "exit_node", "mobile_local_ip",
    "vpn_provider", "protocol", "port", "server_location",
    "subnet_match", "correlation_confidence", "entry_method",
    "exit_method", "file_hash",
]


class CsvExporter:
    def __init__(self, output_dir: str = ".") -> None:
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        ts_tag = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._csv_path = self._dir / f"vnc_session_{ts_tag}.csv"
        self._log_path = self._dir / f"vnc_session_{ts_tag}.log"
        self._pairs: List[dict] = []
        self._init_csv()
        self._init_log()

    # ------------------------------------------------------------------ public

    def append(self, pair: CorrelatedPair) -> None:
        row = pair.to_dict()
        row["file_hash"] = self._row_hash(row)
        self._pairs.append(row)
        self._write_csv_row(row)
        self._write_log(f"PAIR {row['entry_node']} <-> {row['exit_node']} conf={row['correlation_confidence']}%")

    def export_excel(self) -> Path:
        if not self._pairs:
            return self._csv_path
        xlsx = self._csv_path.with_suffix(".xlsx")
        df = pd.DataFrame(self._pairs, columns=COLUMNS)
        with pd.ExcelWriter(xlsx, engine="openpyxl") as writer:
            df.to_excel(writer, sheet_name="VNC_Pairs", index=False)
            # Format sheet
            ws = writer.sheets["VNC_Pairs"]
            for col in ws.columns:
                max_len = max(len(str(c.value or "")) for c in col) + 2
                ws.column_dimensions[col[0].column_letter].width = min(max_len, 40)
        log.info("Excel exported: %s", xlsx)
        return xlsx

    def write_log_event(self, msg: str) -> None:
        self._write_log(msg)

    @property
    def csv_path(self) -> Path:
        return self._csv_path

    @property
    def pair_count(self) -> int:
        return len(self._pairs)

    # ----------------------------------------------------------------- private

    def _init_csv(self) -> None:
        with open(self._csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()

    def _init_log(self) -> None:
        with open(self._log_path, "w", encoding="utf-8") as f:
            f.write(f"# VNC Session Log — {datetime.now(tz=timezone.utc).isoformat()}\n")

    def _write_csv_row(self, row: dict) -> None:
        with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writerow(row)

    def _write_log(self, msg: str) -> None:
        ts = datetime.now(tz=timezone.utc).isoformat()
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(f"{ts} {msg}\n")

    @staticmethod
    def _row_hash(row: dict) -> str:
        raw = "".join(str(row.get(k, "")) for k in ["timestamp", "entry_node", "exit_node", "mobile_local_ip"])
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"SHA256:{digest}"
