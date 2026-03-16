import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RotationPolicy:
    # "baseline" disables all CLM-triggered rotations
    cid_policy: str = "clm"  # baseline | clm

    # Time-based rotation
    cid_time_interval_s: float = 30.0

    # J is a fraction, so effective lifetime is:
    # T_eff = T * (1 + delta), delta in [-J, +J]
    cid_jitter_fraction: float = 0.0

    # Volume-based trigger; 0 disables
    cid_byte_threshold: int = 0

    # Grace period before retiring old CID; 0 means immediate retire
    cid_grace_period_s: float = 0.0

    # Anti-churn guard
    min_gap_s: float = 1.0

    # Optional deterministic seed for reproducible experiments
    random_seed: Optional[int] = None


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


@dataclass
class RetiringCid:
    cid_obj: Any
    cid_hex: Optional[str]
    sequence_number: Optional[int]
    retire_at: float
    reason: str
    path_id: Optional[str] = None


class CidLifecycleManager:
    """
    CID Lifecycle Manager (CLM)

    Features:
      - baseline / clm mode
      - time-based rotation with jitter fraction
      - path-change trigger
      - volume-based trigger
      - grace-period retirement
      - structured JSONL logs

    Notes:
      - Uses aioquic internals for deferred CID retirement when grace_period > 0.
      - Falls back to public change_connection_id() if deferred retirement is unavailable.
    """

    def __init__(self, policy: RotationPolicy, log_path: str, role: str):
        self.policy = policy
        self.log = JsonlLogger(log_path)
        self.role = role

        self._rng = random.Random(policy.random_seed)

        self._initialized = False
        self._allocation_started_at = 0.0
        self._allocation_deadline = float("inf")
        self._allocation_bytes_base = 0
        self._last_rotate = 0.0

        self._current_path_id: Optional[str] = None
        self._current_cid_hex: Optional[str] = None

        self._retiring: List[RetiringCid] = []

    # ---------- Public API ----------

    def tick(self, protocol: Any) -> None:
        """
        Called periodically by client/server protocol ticker.
        """
        quic = protocol._quic
        now = time.time()

        self._initialize_if_needed(quic, now)
        self._poll_retirements(protocol, now)

        if self.policy.cid_policy == "baseline":
            return

        # 1) Detect path changes first
        observed_path_id = self._get_current_path_id(quic)
        observed_path_validated = self._is_current_path_validated(quic)

        if (
            observed_path_id is not None
            and self._current_path_id is not None
            and observed_path_id != self._current_path_id
            and observed_path_validated
        ):
            old_path = self._current_path_id
            self._current_path_id = observed_path_id
            self.on_path_validated(
                protocol,
                path_id=observed_path_id,
                old_path_id=old_path,
            )
            return

        if observed_path_id is not None:
            self._current_path_id = observed_path_id

        # 2) Volume-based trigger
        if self.policy.cid_byte_threshold > 0:
            sent_since_allocation = self._bytes_sent_since_allocation(quic)
            if sent_since_allocation >= self.policy.cid_byte_threshold:
                self._rotate_now(
                    protocol,
                    reason="volume",
                    extra={
                        "bytes_since_allocation": sent_since_allocation,
                        "byte_threshold": self.policy.cid_byte_threshold,
                    },
                )
                return

        # 3) Time-based trigger
        if now >= self._allocation_deadline:
            self._rotate_now(
                protocol,
                reason="timer",
                extra={
                    "deadline": self._allocation_deadline,
                    "elapsed": now - self._allocation_started_at,
                },
            )

    def on_path_validated(
        self,
        protocol: Any,
        path_id: str,
        old_path_id: Optional[str] = None,
    ) -> None:
        """
        Path-change trigger. Called when a validated new path is observed.
        """
        if self.policy.cid_policy != "clm":
            return

        self._rotate_now(
            protocol,
            reason="path_change",
            extra={
                "path_id": path_id,
                "old_path_id": old_path_id,
            },
        )

    def force_rotate(self, protocol: Any, reason: str = "manual") -> None:
        """
        Manual rotation for demos / CLI.
        """
        self._initialize_if_needed(protocol._quic, time.time())
        self._rotate_now(protocol, reason=reason, extra={})

    # ---------- Internal helpers ----------

    def _initialize_if_needed(self, quic: Any, now: float) -> None:
        if self._initialized:
            return

        self._allocation_started_at = now
        self._allocation_deadline = self._compute_deadline(now)
        self._allocation_bytes_base = self._get_total_bytes_sent(quic)
        self._current_path_id = self._get_current_path_id(quic)
        self._current_cid_hex = self._get_active_cid_hex(quic)
        self._initialized = True

        self.log.log(
            {
                "event": "clm_initialized",
                "role": self.role,
                "policy": self.policy.cid_policy,
                "detail": {
                    "cid_time_interval_s": self.policy.cid_time_interval_s,
                    "cid_jitter_fraction": self.policy.cid_jitter_fraction,
                    "cid_byte_threshold": self.policy.cid_byte_threshold,
                    "cid_grace_period_s": self.policy.cid_grace_period_s,
                    "min_gap_s": self.policy.min_gap_s,
                    "current_path_id": self._current_path_id,
                    "current_cid_hex": self._current_cid_hex,
                    "allocation_deadline": self._allocation_deadline,
                },
            }
        )

    def _compute_deadline(self, now: float) -> float:
        if self.policy.cid_time_interval_s <= 0:
            return float("inf")

        jitter_fraction = max(0.0, self.policy.cid_jitter_fraction)
        delta = self._rng.uniform(-jitter_fraction, jitter_fraction)
        effective_lifetime = self.policy.cid_time_interval_s * (1.0 + delta)

        # never schedule negative / zero lifetime
        effective_lifetime = max(0.001, effective_lifetime)

        self.log.log(
            {
                "event": "deadline_scheduled",
                "role": self.role,
                "detail": {
                    "base_interval_s": self.policy.cid_time_interval_s,
                    "delta": delta,
                    "effective_lifetime_s": effective_lifetime,
                },
            }
        )
        return now + effective_lifetime

    def _rotate_now(self, protocol: Any, reason: str, extra: Dict[str, Any]) -> None:
        quic = protocol._quic
        now = time.time()

        if self.policy.cid_policy == "baseline":
            return

        if (now - self._last_rotate) < self.policy.min_gap_s:
            self.log.log(
                {
                    "event": "rotate_skipped",
                    "role": self.role,
                    "reason": reason,
                    "detail": {
                        "note": "min_gap_guard",
                        "min_gap_s": self.policy.min_gap_s,
                        "since_last_rotate_s": now - self._last_rotate,
                        **extra,
                    },
                }
            )
            return

        old_cid_hex = self._get_active_cid_hex(quic)
        old_path_id = self._get_current_path_id(quic)
        bytes_since_allocation = self._bytes_sent_since_allocation(quic)

        ok, detail = self._try_rotate_with_grace(quic, reason=reason, path_id=old_path_id)
        if ok:
            try:
                protocol.transmit()
            except Exception:
                pass

            self._last_rotate = now
            self._allocation_started_at = now
            self._allocation_deadline = self._compute_deadline(now)
            self._allocation_bytes_base = self._get_total_bytes_sent(quic)
            self._current_path_id = self._get_current_path_id(quic)
            self._current_cid_hex = self._get_active_cid_hex(quic)

            self.log.log(
                {
                    "event": "rotate_ok",
                    "role": self.role,
                    "reason": reason,
                    "detail": {
                        "old_cid_hex": old_cid_hex,
                        "new_cid_hex": self._current_cid_hex,
                        "path_id": self._current_path_id,
                        "bytes_since_allocation": bytes_since_allocation,
                        **detail,
                        **extra,
                    },
                }
            )
        else:
            self.log.log(
                {
                    "event": "rotate_failed",
                    "role": self.role,
                    "reason": reason,
                    "detail": {
                        "old_cid_hex": old_cid_hex,
                        "path_id": old_path_id,
                        "bytes_since_allocation": bytes_since_allocation,
                        **detail,
                        **extra,
                    },
                }
            )

    def _try_rotate_with_grace(
        self,
        quic: Any,
        reason: str,
        path_id: Optional[str],
    ) -> tuple[bool, Dict[str, Any]]:
        """
        Preferred path:
          - if grace period > 0 and aioquic internals are present:
              old = _peer_cid
              _consume_peer_cid()
              later call _retire_peer_cid(old)
          - else:
              public change_connection_id()
        """
        detail: Dict[str, Any] = {
            "strategy": None,
            "grace_period_s": self.policy.cid_grace_period_s,
        }

        # Internal deferred retirement path
        if (
            self.policy.cid_grace_period_s > 0
            and hasattr(quic, "_peer_cid")
            and hasattr(quic, "_peer_cid_available")
            and hasattr(quic, "_consume_peer_cid")
            and hasattr(quic, "_retire_peer_cid")
        ):
            try:
                if not getattr(quic, "_peer_cid_available"):
                    return False, {
                        "strategy": "deferred_internal",
                        "note": "No spare peer CID available for rotation.",
                    }

                old_peer_cid = quic._peer_cid
                old_hex = self._safe_hex(getattr(old_peer_cid, "cid", None))
                old_seq = getattr(old_peer_cid, "sequence_number", None)

                quic._consume_peer_cid()
                new_peer_cid = quic._peer_cid
                new_hex = self._safe_hex(getattr(new_peer_cid, "cid", None))
                new_seq = getattr(new_peer_cid, "sequence_number", None)

                retire_at = time.time() + self.policy.cid_grace_period_s
                self._retiring.append(
                    RetiringCid(
                        cid_obj=old_peer_cid,
                        cid_hex=old_hex,
                        sequence_number=old_seq,
                        retire_at=retire_at,
                        reason=reason,
                        path_id=path_id,
                    )
                )

                detail.update(
                    {
                        "strategy": "deferred_internal",
                        "old_sequence_number": old_seq,
                        "new_sequence_number": new_seq,
                        "old_cid_hex": old_hex,
                        "new_cid_hex": new_hex,
                        "retire_at": retire_at,
                    }
                )
                return True, detail
            except Exception as e:
                return False, {
                    "strategy": "deferred_internal",
                    "note": f"{type(e).__name__}: {e}",
                }

        # Immediate internal/public path
        if hasattr(quic, "change_connection_id") and callable(getattr(quic, "change_connection_id")):
            try:
                detail["strategy"] = "public_change_connection_id"
                quic.change_connection_id()
                detail["note"] = "Previous CID retired immediately by aioquic."
                return True, detail
            except Exception as e:
                return False, {
                    "strategy": "public_change_connection_id",
                    "note": f"{type(e).__name__}: {e}",
                }

        return False, {
            "strategy": "none",
            "note": "No supported CID rotation API found.",
        }

    def _poll_retirements(self, protocol: Any, now: float) -> None:
        quic = protocol._quic
        if not self._retiring:
            return

        remaining: List[RetiringCid] = []
        for item in self._retiring:
            if now < item.retire_at:
                remaining.append(item)
                continue

            ok = False
            note = ""
            try:
                if hasattr(quic, "_retire_peer_cid"):
                    quic._retire_peer_cid(item.cid_obj)
                    protocol.transmit()
                    ok = True
                else:
                    note = "Internal _retire_peer_cid unavailable."
            except Exception as e:
                note = f"{type(e).__name__}: {e}"

            self.log.log(
                {
                    "event": "retire_connection_id_emitted" if ok else "retire_connection_id_failed",
                    "role": self.role,
                    "reason": item.reason,
                    "detail": {
                        "cid_hex": item.cid_hex,
                        "sequence_number": item.sequence_number,
                        "path_id": item.path_id,
                        "grace_period_s": self.policy.cid_grace_period_s,
                        "retire_at": item.retire_at,
                        "note": note,
                    },
                }
            )

        self._retiring = remaining

    def _get_total_bytes_sent(self, quic: Any) -> int:
        paths = getattr(quic, "_network_paths", []) or []
        total = 0
        for p in paths:
            total += int(getattr(p, "bytes_sent", 0) or 0)
        return total

    def _bytes_sent_since_allocation(self, quic: Any) -> int:
        return self._get_total_bytes_sent(quic) - self._allocation_bytes_base

    def _get_current_path_id(self, quic: Any) -> Optional[str]:
        paths = getattr(quic, "_network_paths", None)
        if not paths:
            return None

        p = paths[0]
        addr = getattr(p, "addr", None)
        if addr is None:
            return None

        return str(addr)

    def _is_current_path_validated(self, quic: Any) -> bool:
        paths = getattr(quic, "_network_paths", None)
        if not paths:
            return False
        p = paths[0]
        return bool(getattr(p, "is_validated", False))

    def _get_active_cid_hex(self, quic: Any) -> Optional[str]:
        # Best current outbound peer CID
        peer_cid = getattr(quic, "_peer_cid", None)
        if peer_cid is not None and hasattr(peer_cid, "cid"):
            return self._safe_hex(peer_cid.cid)

        # Fallback host CID
        host_cid = getattr(quic, "host_cid", None)
        if host_cid is not None:
            return self._safe_hex(host_cid)

        return None

    @staticmethod
    def _safe_hex(x: Any) -> Optional[str]:
        if isinstance(x, (bytes, bytearray)):
            return x.hex()
        return None