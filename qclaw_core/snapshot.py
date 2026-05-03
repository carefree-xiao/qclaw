"""
qclaw_core.snapshot - Pre-execution filesystem snapshots for rollback.
"""
import json
import os
import time
import shutil
from dataclasses import dataclass, asdict
from typing import Optional, List


SNAPSHOT_DIR = "data/snapshots"


@dataclass
class SnapshotMeta:
    snapshot_id: str
    trace_id: str
    target_paths: List[str]
    created_at: float
    restored: bool = False
    file_count: int = 0
    total_size_bytes: int = 0


class SnapshotManager:
    def __init__(self, snapshot_dir: str = SNAPSHOT_DIR):
        self.snapshot_dir = snapshot_dir
        os.makedirs(snapshot_dir, exist_ok=True)

    def create(self, trace_id: str, target_paths: List[str], mock: bool = True) -> Optional[SnapshotMeta]:
        timestamp = time.time()
        snapshot_id = f"snap_{trace_id}_{int(timestamp * 1000)}"

        meta = SnapshotMeta(
            snapshot_id=snapshot_id,
            trace_id=trace_id,
            target_paths=target_paths,
            created_at=timestamp,
        )

        meta_path = os.path.join(self.snapshot_dir, f"{snapshot_id}.json")
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(asdict(meta), f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            return None

        if not mock:
            backup_dir = os.path.join(self.snapshot_dir, snapshot_id)
            os.makedirs(backup_dir, exist_ok=True)
            total_files = 0
            total_size = 0

            for path in target_paths:
                if os.path.exists(path):
                    try:
                        dest = os.path.join(backup_dir, os.path.basename(path))
                        if os.path.isdir(path):
                            shutil.copytree(path, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(path, dest)
                        for root, dirs, files in os.walk(dest):
                            for f_name in files:
                                fp = os.path.join(root, f_name)
                                total_files += 1
                                total_size += os.path.getsize(fp)
                    except Exception:
                        pass

            meta.file_count = total_files
            meta.total_size_bytes = total_size
            meta_dict = asdict(meta)
            meta_dict["backup_dir"] = backup_dir
            meta_dict["backup_exists"] = True
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_dict, f, ensure_ascii=False, indent=2)

        return meta

    def restore(self, snapshot_id: str) -> bool:
        meta_path = os.path.join(self.snapshot_dir, f"{snapshot_id}.json")
        if not os.path.exists(meta_path):
            return False

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta_data = json.load(f)
        except Exception:
            return False

        backup_dir = os.path.join(self.snapshot_dir, snapshot_id)
        if not os.path.exists(backup_dir):
            meta_data["restored"] = True
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta_data, f, ensure_ascii=False, indent=2)
            return True

        target_paths = meta_data.get("target_paths", [])
        for path in target_paths:
            src = os.path.join(backup_dir, os.path.basename(path))
            if os.path.exists(src):
                try:
                    if os.path.isdir(src):
                        if os.path.exists(path):
                            shutil.rmtree(path, ignore_errors=True)
                        shutil.copytree(src, path)
                    else:
                        shutil.copy2(src, path)
                except Exception:
                    return False

        meta_data["restored"] = True
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, ensure_ascii=False, indent=2)
        return True

    def cleanup(self, max_age_hours: int = 24) -> int:
        now = time.time()
        max_age_sec = max_age_hours * 3600
        cleaned = 0

        for fname in os.listdir(self.snapshot_dir):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(self.snapshot_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if now - meta.get("created_at", 0) > max_age_sec:
                    os.remove(fpath)
                    snap_id = meta.get("snapshot_id", "")
                    backup_dir = os.path.join(self.snapshot_dir, snap_id)
                    if os.path.exists(backup_dir):
                        shutil.rmtree(backup_dir, ignore_errors=True)
                    cleaned += 1
            except Exception:
                pass

        return cleaned
