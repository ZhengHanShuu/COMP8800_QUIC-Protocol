import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RotationPolicy:
    # rotate every N seconds (0 disables)
    rotate_interval_s: float = 30.0
    # random jitter (0..jitter_s) added to interval
    jitter_s: float = 3.0
    # minimum seconds between rotations (anti-churn)
    min_gap_s: float = 10.0


class JsonlLogger:
    def __init__(self, path: str):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    def log(self, event: Dict[str, Any]) -> None:
        event["ts"] = time.time()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


class CidLifecycleManager:
    """
    CID Lifecycle Manager (CLM)

    Goal:
      - Trigger rotations on a timer (time + jitter)
      - Emit structured logs for analysis
      - Attempt to rotate local connection IDs using aioquic internals (best-effort)
    """

    def __init__(self, policy: RotationPolicy, log_path: str, role: str):
        self.policy = policy
        self.log = JsonlLogger(log_path)
        self.role = role
        self._next_deadline = self._compute_next_deadline(time.time())
        self._last_rotate = 0.0

    def _compute_next_deadline(self, now: float) -> float:
        if self.policy.rotate_interval_s <= 0:
            return float("inf")
        # deterministic-ish jitter based on fractional time part
        frac = now - int(now)
        jitter = frac * self.policy.jitter_s
        return now + self.policy.rotate_interval_s + jitter

    def maybe_rotate(self, quic_connection: Any, reason: str = "timer") -> None:
        now = time.time()

        if now < self._next_deadline:
            return
        if (now - self._last_rotate) < self.policy.min_gap_s:
            self._next_deadline = self._compute_next_deadline(now)
            return

        ok, detail = self._try_rotate_local_cid(quic_connection)

        self.log.log(
            {
                "event": "rotate_ok" if ok else "rotate_failed",
                "role": self.role,
                "reason": reason,
                "detail": detail,
            }
        )

        self._last_rotate = now
        self._next_deadline = self._compute_next_deadline(now)

    def _try_rotate_local_cid(self, quic: Any) -> (bool, Dict[str, Any]):
        detail: Dict[str, Any] = {"strategy": None, "found": [], "note": ""}

        def _hex(x: Optional[bytes]) -> Optional[str]:
            return x.hex() if isinstance(x, (bytes, bytearray)) else None

        candidates = [
            "_local_cid_manager",
            "_cid_manager",
            "_connection_id_manager",
            "_local_connection_id_manager",
        ]
        for name in candidates:
            if hasattr(quic, name):
                detail["found"].append(name)

        # Strategy A: mgr.rotate()
        for name in candidates:
            mgr = getattr(quic, name, None)
            if mgr is None:
                continue
            if hasattr(mgr, "rotate") and callable(getattr(mgr, "rotate")):
                detail["strategy"] = f"{name}.rotate()"
                try:
                    mgr.rotate()
                    return True, detail
                except Exception as e:
                    detail["note"] = f"rotate() raised: {type(e).__name__}: {e}"

        # Strategy B: mgr.issue_connection_id() / mgr.issue() / mgr.new()
        for name in candidates:
            mgr = getattr(quic, name, None)
            if mgr is None:
                continue

            for fn_name in ("issue_connection_id", "issue", "new"):
                if hasattr(mgr, fn_name) and callable(getattr(mgr, fn_name)):
                    detail["strategy"] = f"{name}.{fn_name}()"
                    try:
                        issued = getattr(mgr, fn_name)()
                        detail["issued"] = str(issued)
                        return True, detail
                    except Exception as e:
                        detail["note"] = f"{fn_name} raised: {type(e).__name__}: {e}"

        # Strategy C: direct API attempts
        for fn_name in ("change_connection_id", "rotate_connection_id", "request_connection_id"):
            if hasattr(quic, fn_name) and callable(getattr(quic, fn_name)):
                detail["strategy"] = f"quic.{fn_name}()"
                try:
                    getattr(quic, fn_name)()
                    return True, detail
                except Exception as e:
                    detail["note"] = f"{fn_name} raised: {type(e).__name__}: {e}"

        # last: dump some debug fields
        for name in ("_local_cid", "_original_destination_connection_id", "_host_cid"):
            if hasattr(quic, name):
                v = getattr(quic, name, None)
                detail[name] = _hex(v) if isinstance(v, (bytes, bytearray)) else str(v)

        detail["note"] = detail["note"] or (
            "No known CID manager API found on this aioquic version."
        )
        return False, detail
