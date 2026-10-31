from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import re
from threading import RLock
from typing import Any, Callable, Dict, Mapping, Optional, Set, Tuple

from .models import (
    AuthorityGrants,
    AuthorityVerifier,
    DeviceIdentity,
    EnforcementDecision,
    EnforcementResult,
    LimitMode,
    OperationsState,
    OperationsProjection,
    RouterMode,
    RevokeInstruction,
    SecurityProjection,
    SupportState,
    TrafficDirection,
    TrafficEntitlement,
    UserClass,
)


class LabUserAccessEnforcer:
    """Lab-only in-memory implementation of the public enforcement seams."""

    ENTITLEMENT_SCHEMA_VERSION = "user-access-entitlement-v0.1"
    REGISTRY_SCHEMA_VERSION = "device-registry-v0.1"
    LEASE_SCHEMA_VERSION = "device-lease-v0.1"
    BANDWIDTH_PROFILE_VERSION = "aggregate-shaping-v0.1"
    ROUTER_ADR_VERSION = "router-entitlement-v0.1"
    EVIDENCE_REQUIRED_FIELDS = frozenset(
        {
            "status",
            "base_commit",
            "implementation_commit",
            "branch",
            "changed_files",
            "diff_reference",
            "test_commands",
            "full_test_results",
            "contract_versions",
            "policy_schema_versions",
            "router_adr_version",
            "security_evidence",
            "operations_evidence",
            "known_limitations",
            "rollback_information",
        }
    )
    SENSITIVE_EVIDENCE_KEYS = frozenset(
        {
            "password",
            "token",
            "private_key",
            "secret",
            "secret_value",
            "credential",
            "api_key",
            "access_token",
            "auth_token",
            "refresh_token",
            "client_secret",
            "aws_access_key_id",
            "google_api_key",
            "slack_token",
            "subscription_url",
            "real_user_identity",
            "real_device_identity",
            "production_entitlement",
        }
    )

    def __init__(
        self,
        *,
        environment: str,
        trusted_issuer: str,
        trusted_identity_issuer: str,
        policy_id: str,
        policy_version: str,
        authority_verifier: AuthorityVerifier,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._environment = environment
        self._trusted_issuer = trusted_issuer
        self._trusted_identity_issuer = trusted_identity_issuer
        self._policy_id = policy_id
        self._policy_version = policy_version
        self._authority_verifier = authority_verifier
        self._clock = clock
        self._entitlements: Dict[str, TrafficEntitlement] = {}
        self._active_entitlements: Dict[str, str] = {}
        self._registered: Dict[str, Set[str]] = {}
        self._tombstones: Dict[str, Set[str]] = {}
        self._device_identity_versions: Dict[Tuple[str, str], int] = {}
        self._device_identities: Dict[Tuple[str, str], DeviceIdentity] = {}
        self._revoke_versions: Dict[Tuple[str, str], int] = {}
        self._consumed_revoke_ids: Set[str] = set()
        self._registry_versions: Dict[str, int] = {}
        self._active_leases: Dict[str, Set[str]] = {}
        self._lease_versions: Dict[str, int] = {}
        self._bandwidth_windows: Dict[
            Tuple[str, TrafficDirection], Tuple[str, Dict[str, int]]
        ] = {}
        self._lost_bandwidth_state: Set[str] = set()
        self._evidence_records: list[Dict[str, Any]] = []
        self._lock = RLock()

    def install_entitlement(self, entitlement: TrafficEntitlement) -> EnforcementResult:
        with self._lock:
            # Own the immutable reference snapshot used for validation/storage.
            entitlement = replace(entitlement)
            return self._bind_result(
                self._install_entitlement(entitlement),
                action="APPLY_POLICY",
                entitlement=entitlement,
                user_id=entitlement.user_id,
            )

    def _install_entitlement(self, entitlement: TrafficEntitlement) -> EnforcementResult:
        with self._lock:
            before = self._state_summary(entitlement.user_id)
            stored = self._entitlements.get(entitlement.entitlement_id)
            if stored is not None and stored != entitlement:
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "ENTITLEMENT_ID_IMMUTABLE_CONFLICT",
                )
        reason = self._validate_entitlement(entitlement)
        if reason is not None:
            return EnforcementResult(EnforcementDecision.DENY, False, reason)
        with self._lock:
            stored = self._entitlements.get(entitlement.entitlement_id)
            if stored is not None:
                if self._active_entitlements.get(entitlement.user_id) != entitlement.entitlement_id:
                    return EnforcementResult(
                        EnforcementDecision.DENY,
                        False,
                        "ENTITLEMENT_SUPERSEDED",
                        evidence_refs=entitlement.evidence_refs,
                    )
                return EnforcementResult(
                    EnforcementDecision.ALLOW,
                    False,
                    "ENTITLEMENT_ALREADY_ACTIVE",
                    evidence_refs=entitlement.evidence_refs,
                )
            current_id = self._active_entitlements.get(entitlement.user_id)
            if current_id is not None:
                current = self._entitlements[current_id]
                if self._version_key(entitlement.entitlement_version) <= self._version_key(
                    current.entitlement_version
                ):
                    return EnforcementResult(
                        EnforcementDecision.DENY,
                        False,
                        "ENTITLEMENT_VERSION_OLDER",
                        evidence_refs=entitlement.evidence_refs,
                    )
            devices = self._registered.get(entitlement.user_id, set())
            registered_limit = entitlement.max_registered_devices
            if (
                registered_limit.mode is LimitMode.LIMITED
                and len(devices) > int(registered_limit.value)
            ):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "POLICY_TRANSITION_REGISTRY_CONFLICT",
                    self._registry_versions.get(entitlement.user_id, 0),
                    evidence_refs=entitlement.evidence_refs,
                )
            active_devices = self._active_leases.get(entitlement.user_id, set())
            concurrent_limit = entitlement.max_concurrent_devices
            if (
                concurrent_limit.mode is LimitMode.LIMITED
                and len(active_devices) > int(concurrent_limit.value)
            ):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "POLICY_TRANSITION_LEASE_CONFLICT",
                    self._registry_versions.get(entitlement.user_id, 0),
                    self._lease_versions.get(entitlement.user_id, 0),
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            changed = current_id != entitlement.entitlement_id
            self._entitlements[entitlement.entitlement_id] = entitlement
            self._active_entitlements[entitlement.user_id] = entitlement.entitlement_id
            return EnforcementResult(
                EnforcementDecision.ALLOW,
                changed,
                "ENTITLEMENT_INSTALLED" if changed else "ENTITLEMENT_ALREADY_ACTIVE",
                self._registry_versions.get(entitlement.user_id, 0),
                before=before,
                after=self._state_summary(entitlement.user_id),
                evidence_refs=entitlement.evidence_refs,
            )

    def register_device(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        device_identity: Optional[DeviceIdentity] = None,
        expected_registry_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            result = self._register_device(
                entitlement_id,
                user_id,
                device_id,
                device_identity=device_identity,
                expected_registry_version=expected_registry_version,
            )
            return self._bind_result(
                result,
                action="REGISTER_DEVICE",
                entitlement_id=entitlement_id,
                user_id=user_id,
                device_id=device_id,
            )

    def _register_device(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        device_identity: Optional[DeviceIdentity] = None,
        expected_registry_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            before = self._state_summary(user_id)
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            if error is not None:
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    error,
                    self._registry_versions.get(user_id, 0),
                )
            assert entitlement is not None
            devices = self._registered.setdefault(user_id, set())
            version = self._registry_versions.get(user_id, 0)
            if not user_id or not device_id:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "IDENTIFIER_INVALID", version
                )
            identity_error = self._validate_device_identity(
                device_identity, user_id=user_id, device_id=device_id
            )
            if identity_error is not None:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, identity_error, version
                )
            if device_id in devices:
                return EnforcementResult(
                    EnforcementDecision.ALLOW,
                    False,
                    "DEVICE_ALREADY_REGISTERED",
                    version,
                    evidence_refs=entitlement.evidence_refs,
                )
            if device_id in self._tombstones.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "DEVICE_TOMBSTONED", version,
                    evidence_refs=entitlement.evidence_refs,
                )
            if expected_registry_version is not None and expected_registry_version != version:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "REGISTRY_VERSION_CONFLICT", version,
                    evidence_refs=entitlement.evidence_refs,
                )
            limit = entitlement.max_registered_devices
            if limit.mode is LimitMode.LIMITED and len(devices) >= int(limit.value):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "REGISTERED_DEVICE_LIMIT_REACHED",
                    version,
                    evidence_refs=entitlement.evidence_refs,
                )
            devices.add(device_id)
            assert device_identity is not None
            self._device_identity_versions[(user_id, device_id)] = device_identity.version
            self._device_identities[(user_id, device_id)] = device_identity
            version += 1
            self._registry_versions[user_id] = version
            return EnforcementResult(
                EnforcementDecision.ALLOW,
                True,
                "DEVICE_REGISTERED",
                version,
                before=before,
                after=self._state_summary(user_id),
                evidence_refs=entitlement.evidence_refs,
            )

    def revoke_device(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        revoke_instruction: Optional[RevokeInstruction] = None,
        expected_registry_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            if revoke_instruction is not None:
                revoke_instruction = replace(revoke_instruction)
            result = self._revoke_device(
                entitlement_id,
                user_id,
                device_id,
                revoke_instruction=revoke_instruction,
                expected_registry_version=expected_registry_version,
            )
            return self._bind_result(
                result,
                action="REVOKE_DEVICE",
                entitlement_id=entitlement_id,
                user_id=user_id,
                device_id=device_id,
            )

    def _revoke_device(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        revoke_instruction: Optional[RevokeInstruction] = None,
        expected_registry_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            before = self._state_summary(user_id)
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            version = self._registry_versions.get(user_id, 0)
            if error is not None:
                return EnforcementResult(EnforcementDecision.DENY, False, error, version)
            assert entitlement is not None
            if (
                revoke_instruction is not None
                and revoke_instruction.instruction_id in self._consumed_revoke_ids
            ):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "REVOKE_INSTRUCTION_REPLAY", version
                )
            revoke_error = self._validate_revoke_instruction(
                revoke_instruction, user_id=user_id, device_id=device_id
            )
            if revoke_error is not None:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, revoke_error, version
                )
            tombstones = self._tombstones.setdefault(user_id, set())
            assert revoke_instruction is not None
            if expected_registry_version is not None and expected_registry_version != version:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "REGISTRY_VERSION_CONFLICT", version,
                    evidence_refs=revoke_instruction.evidence_refs,
                )
            devices = self._registered.setdefault(user_id, set())
            if device_id not in devices:
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "DEVICE_NOT_REGISTERED", version,
                    evidence_refs=revoke_instruction.evidence_refs,
                )
            devices.remove(device_id)
            tombstones.add(device_id)
            self._consumed_revoke_ids.add(revoke_instruction.instruction_id)
            self._revoke_versions[(user_id, device_id)] = revoke_instruction.version
            version += 1
            self._registry_versions[user_id] = version
            active_devices = self._active_leases.setdefault(user_id, set())
            if device_id in active_devices:
                active_devices.remove(device_id)
                self._lease_versions[user_id] = self._lease_versions.get(user_id, 0) + 1
            return EnforcementResult(
                EnforcementDecision.ALLOW,
                True,
                "DEVICE_REVOKED",
                version,
                self._lease_versions.get(user_id, 0),
                len(active_devices),
                before=before,
                after=self._state_summary(user_id),
                evidence_refs=revoke_instruction.evidence_refs,
            )

    def acquire_device_lease(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        expected_lease_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            result = self._acquire_device_lease(
                entitlement_id,
                user_id,
                device_id,
                expected_lease_version=expected_lease_version,
            )
            return self._bind_result(
                result,
                action="ACQUIRE_LEASE",
                entitlement_id=entitlement_id,
                user_id=user_id,
                device_id=device_id,
            )

    def _acquire_device_lease(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        *,
        expected_lease_version: Optional[int] = None,
    ) -> EnforcementResult:
        with self._lock:
            before = self._state_summary(user_id)
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            registry_version = self._registry_versions.get(user_id, 0)
            lease_version = self._lease_versions.get(user_id, 0)
            active_devices = self._active_leases.setdefault(user_id, set())
            if error is not None:
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    error,
                    registry_version,
                    lease_version,
                    len(active_devices),
                )
            assert entitlement is not None
            if device_id in self._tombstones.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "DEVICE_TOMBSTONED",
                    registry_version,
                    lease_version,
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            if device_id in active_devices:
                return EnforcementResult(
                    EnforcementDecision.ALLOW,
                    False,
                    "DEVICE_LEASE_ALREADY_ACTIVE",
                    registry_version,
                    lease_version,
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            if expected_lease_version is not None and expected_lease_version != lease_version:
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "LEASE_VERSION_CONFLICT",
                    registry_version,
                    lease_version,
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            limit = entitlement.max_concurrent_devices
            if limit.mode is LimitMode.LIMITED and len(active_devices) >= int(limit.value):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "CONCURRENT_DEVICE_LIMIT_REACHED",
                    registry_version,
                    lease_version,
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            if device_id not in self._registered.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "DEVICE_NOT_REGISTERED",
                    registry_version,
                    lease_version,
                    len(active_devices),
                    evidence_refs=entitlement.evidence_refs,
                )
            active_devices.add(device_id)
            lease_version += 1
            self._lease_versions[user_id] = lease_version
            return EnforcementResult(
                EnforcementDecision.ALLOW,
                True,
                "DEVICE_LEASE_ACQUIRED",
                registry_version,
                lease_version,
                len(active_devices),
                before=before,
                after=self._state_summary(user_id),
                evidence_refs=entitlement.evidence_refs,
            )

    def registered_devices(self, user_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._registered.get(user_id, set())))

    def active_devices(self, user_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active_leases.get(user_id, set())))

    def _state_summary(self, user_id: str) -> Dict[str, Any]:
        active_id = self._active_entitlements.get(user_id)
        active = self._entitlements.get(active_id) if active_id is not None else None
        return {
            "registered_devices": len(self._registered.get(user_id, set())),
            "active_leases": len(self._active_leases.get(user_id, set())),
            "registry_version": self._registry_versions.get(user_id, 0),
            "lease_set_version": self._lease_versions.get(user_id, 0),
            "active_entitlement_id": active_id,
            "active_entitlement_version": (
                active.entitlement_version if active is not None else None
            ),
        }

    def mark_bandwidth_state_lost(self, user_id: str) -> None:
        with self._lock:
            self._lost_bandwidth_state.add(user_id)
            for key in tuple(self._bandwidth_windows):
                if key[0] == user_id:
                    del self._bandwidth_windows[key]

    def account_traffic(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        direction: TrafficDirection,
        *,
        window_id: str,
        bytes_in_window: int,
        source_ip: Optional[str] = None,
    ) -> EnforcementResult:
        with self._lock:
            result = self._account_traffic(
                entitlement_id,
                user_id,
                device_id,
                direction,
                window_id=window_id,
                bytes_in_window=bytes_in_window,
                source_ip=source_ip,
            )
            return self._bind_result(
                result,
                action="APPLY_RATE",
                entitlement_id=entitlement_id,
                user_id=user_id,
                device_id=device_id,
            )

    def _account_traffic(
        self,
        entitlement_id: str,
        user_id: str,
        device_id: str,
        direction: TrafficDirection,
        *,
        window_id: str,
        bytes_in_window: int,
        source_ip: Optional[str] = None,
    ) -> EnforcementResult:
        del source_ip  # Network location is observational, never an authority key.
        with self._lock:
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            if error is not None:
                return EnforcementResult(EnforcementDecision.DENY, False, error)
            assert entitlement is not None
            if device_id in self._tombstones.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "DEVICE_TOMBSTONED",
                    evidence_refs=entitlement.evidence_refs,
                )
            if device_id not in self._registered.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "DEVICE_NOT_REGISTERED",
                    evidence_refs=entitlement.evidence_refs,
                )
            if device_id not in self._active_leases.get(user_id, set()):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "DEVICE_LEASE_REQUIRED",
                    evidence_refs=entitlement.evidence_refs,
                )
            if not isinstance(direction, TrafficDirection):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "BANDWIDTH_DIRECTION_INVALID",
                    evidence_refs=entitlement.evidence_refs,
                )
            if (
                not window_id
                or not isinstance(bytes_in_window, int)
                or isinstance(bytes_in_window, bool)
                or bytes_in_window < 0
            ):
                return EnforcementResult(
                    EnforcementDecision.DENY, False, "BANDWIDTH_SAMPLE_INVALID",
                    evidence_refs=entitlement.evidence_refs,
                )
            limit = (
                entitlement.aggregate_downlink
                if direction is TrafficDirection.DOWNLINK
                else entitlement.aggregate_uplink
            )
            authoritative_window_id = str(int(self._clock().timestamp()))
            common = {
                "accounting_scope": "PER_USER_AGGREGATE",
                "algorithm": "FIXED_WINDOW_AGGREGATE_V1",
                "window_seconds": 1,
                "measurement_point": "LAB_USER_TRAFFIC_ACCOUNTING_SEAM",
                "bandwidth_profile_version": entitlement.bandwidth_profile_version,
                "authoritative_window_id": authoritative_window_id,
            }
            ceiling = (
                int(limit.bytes_per_second)
                if limit.mode is LimitMode.LIMITED
                else None
            )

            def audit_state(
                aggregate_before: Optional[int],
                device_before: Optional[int],
                aggregate_after: Optional[int],
                device_after: Optional[int],
            ) -> tuple[Dict[str, Any], Dict[str, Any]]:
                base = {
                    "direction": direction.value,
                    "authoritative_window_id": authoritative_window_id,
                    "limit_bytes_per_second": ceiling,
                    "bandwidth_profile_version": entitlement.bandwidth_profile_version,
                }
                before_state = {
                    **base,
                    "aggregate_bytes_before": aggregate_before,
                    "aggregate_bytes_after": aggregate_before,
                    "device_bytes_before": device_before,
                    "device_bytes_after": device_before,
                }
                after_state = {
                    **base,
                    "aggregate_bytes_before": aggregate_before,
                    "aggregate_bytes_after": aggregate_after,
                    "device_bytes_before": device_before,
                    "device_bytes_after": device_after,
                }
                return before_state, after_state

            if limit.mode is LimitMode.UNLIMITED:
                before_state, after_state = audit_state(0, 0, 0, 0)
                return EnforcementResult(
                    EnforcementDecision.ALLOW,
                    False,
                    "BANDWIDTH_UNLIMITED",
                    aggregate_bytes_in_window=bytes_in_window,
                    before=before_state,
                    after=after_state,
                    **common,
                    evidence_refs=entitlement.evidence_refs,
                )
            if user_id in self._lost_bandwidth_state:
                before_state, after_state = audit_state(None, None, None, None)
                return EnforcementResult(
                    EnforcementDecision.UNKNOWN,
                    False,
                    "BANDWIDTH_STATE_UNAVAILABLE",
                    limit_bytes_per_second=limit.bytes_per_second,
                    burst_bytes=limit.bytes_per_second,
                    before=before_state,
                    after=after_state,
                    **common,
                    evidence_refs=entitlement.evidence_refs,
                )
            key = (user_id, direction)
            current_window, per_device = self._bandwidth_windows.get(
                key, (authoritative_window_id, {})
            )
            if current_window != authoritative_window_id:
                current_window, per_device = authoritative_window_id, {}
            previous = per_device.get(device_id)
            device_before = previous if previous is not None else 0
            aggregate_before = sum(per_device.values())
            if previous is not None and bytes_in_window < previous:
                before_state, after_state = audit_state(
                    aggregate_before,
                    device_before,
                    aggregate_before,
                    device_before,
                )
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "BANDWIDTH_SAMPLE_REGRESSION",
                    aggregate_bytes_in_window=aggregate_before,
                    limit_bytes_per_second=ceiling,
                    burst_bytes=ceiling,
                    before=before_state,
                    after=after_state,
                    **common,
                    evidence_refs=entitlement.evidence_refs,
                )
            per_device[device_id] = bytes_in_window
            self._bandwidth_windows[key] = (current_window, per_device)
            aggregate = sum(per_device.values())
            before_state, after_state = audit_state(
                aggregate_before,
                device_before,
                aggregate,
                bytes_in_window,
            )
            assert ceiling is not None
            shaped = aggregate > ceiling
            return EnforcementResult(
                EnforcementDecision.SHAPE if shaped else EnforcementDecision.ALLOW,
                previous != bytes_in_window,
                "AGGREGATE_RATE_LIMIT_APPLIED" if shaped else "BANDWIDTH_WITHIN_LIMIT",
                aggregate_bytes_in_window=aggregate,
                limit_bytes_per_second=ceiling,
                burst_bytes=ceiling,
                before=before_state,
                after=after_state,
                **common,
                evidence_refs=entitlement.evidence_refs,
            )

    def evaluate_router_access(
        self,
        entitlement_id: str,
        user_id: str,
        router_mode: RouterMode,
        *,
        downstream_device_id: Optional[str] = None,
        downstream_device_count: Optional[int],
        downstream_identity_authoritative: bool,
        downstream_accounting_authoritative: bool,
        router_id: str,
    ) -> EnforcementResult:
        with self._lock:
            result = self._evaluate_router_access(
                entitlement_id,
                user_id,
                router_mode,
                downstream_device_id=downstream_device_id,
                downstream_device_count=downstream_device_count,
                downstream_identity_authoritative=downstream_identity_authoritative,
                downstream_accounting_authoritative=downstream_accounting_authoritative,
                router_id=router_id,
            )
            # Router evaluation is read-only. Bind all state fields to one
            # observation while still holding the evaluation lock.
            state = self._state_summary(user_id)
            result = replace(
                result,
                registry_version=state["registry_version"],
                lease_version=state["lease_set_version"],
                lease_set_version=state["lease_set_version"],
                active_device_count=state["active_leases"],
                before=dict(state),
                after=dict(state),
            )
            return self._bind_result(
                result,
                action="APPLY_POLICY",
                entitlement_id=entitlement_id,
                user_id=user_id,
                device_id=downstream_device_id,
            )

    def _evaluate_router_access(
        self,
        entitlement_id: str,
        user_id: str,
        router_mode: RouterMode,
        *,
        downstream_device_id: Optional[str] = None,
        downstream_device_count: Optional[int],
        downstream_identity_authoritative: bool,
        downstream_accounting_authoritative: bool,
        router_id: str,
    ) -> EnforcementResult:
        del router_id  # Router identity is intentionally not a Device identity.
        with self._lock:
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            if error is not None:
                state = (
                    OperationsState.STALE
                    if error == "ENTITLEMENT_STALE"
                    else OperationsState.UNKNOWN
                )
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    error,
                    support_state=SupportState.UNKNOWN,
                    operations_state=state,
                    operations_reason_code=error,
                )
            assert entitlement is not None
            if not isinstance(router_mode, RouterMode):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "ROUTER_MODE_INVALID",
                    support_state=SupportState.UNKNOWN,
                    operations_state=OperationsState.FAIL,
                    operations_reason_code="ENT.ROUTER.MODE_INVALID",
                    traffic_role=entitlement.user_class,
                    evidence_refs=entitlement.evidence_refs,
                )
            if router_mode is RouterMode.INDIVIDUAL_DEVICE:
                if (
                    not downstream_identity_authoritative
                    or not downstream_accounting_authoritative
                    or downstream_device_count != 1
                    or downstream_device_id not in self._registered.get(user_id, set())
                    or downstream_device_id not in self._active_leases.get(user_id, set())
                ):
                    return EnforcementResult(
                        EnforcementDecision.DENY,
                        False,
                        "INDIVIDUAL_DEVICE_AUTHORITY_MISSING",
                        support_state=SupportState.SUPPORTED,
                        operations_state=OperationsState.FAIL,
                        operations_reason_code="ENT.DEVICE.AUTHORITY_MISSING",
                        traffic_role=entitlement.user_class,
                        evidence_refs=entitlement.evidence_refs,
                    )
                return EnforcementResult(
                    EnforcementDecision.ALLOW,
                    False,
                    "INDIVIDUAL_DEVICE_AUTHORIZED",
                    support_state=SupportState.SUPPORTED,
                    operations_state=OperationsState.PASS,
                    traffic_role=entitlement.user_class,
                    evidence_refs=entitlement.evidence_refs,
                )
            if entitlement.user_class is UserClass.STANDARD_USER:
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "STANDARD_SHARED_ROUTER_UNSUPPORTED",
                    support_state=SupportState.UNSUPPORTED,
                    operations_state=OperationsState.UNSUPPORTED_ENTITLEMENT_STATE,
                    operations_reason_code="ENT.ROUTER.STANDARD_SHARED_UNSUPPORTED",
                    traffic_role=entitlement.user_class,
                    evidence_refs=entitlement.evidence_refs,
                )
            limits = (
                entitlement.max_registered_devices,
                entitlement.max_concurrent_devices,
                entitlement.aggregate_downlink,
                entitlement.aggregate_uplink,
            )
            if not all(limit.mode is LimitMode.UNLIMITED for limit in limits):
                return EnforcementResult(
                    EnforcementDecision.DENY,
                    False,
                    "SHARED_ROUTER_REQUIRES_EXPLICIT_UNLIMITED",
                    support_state=SupportState.UNKNOWN,
                    operations_state=OperationsState.FAIL,
                    operations_reason_code="ENT.ROUTER.UNLIMITED_REQUIRED",
                    traffic_role=entitlement.user_class,
                    evidence_refs=entitlement.evidence_refs,
                )
            return EnforcementResult(
                EnforcementDecision.ALLOW,
                False,
                "UNLIMITED_SHARED_ROUTER_AUTHORIZED",
                support_state=SupportState.SUPPORTED,
                operations_state=OperationsState.PASS,
                traffic_role=entitlement.user_class,
                evidence_refs=entitlement.evidence_refs,
            )

    def project_security(
        self,
        entitlement_id: str,
        user_id: str,
        authority: AuthorityGrants,
        *,
        client_claimed_role: Optional[UserClass] = None,
    ) -> SecurityProjection:
        del client_claimed_role  # Client role claims are never authoritative.
        with self._lock:
            entitlement, error = self._require_entitlement(entitlement_id, user_id)
            if error is not None:
                return SecurityProjection(
                    EnforcementDecision.DENY,
                    error,
                    None,
                    None,
                    None,
                    False,
                    False,
                    False,
                    False,
                )
            assert entitlement is not None
            return SecurityProjection(
                EnforcementDecision.ALLOW,
                "SECURITY_AXES_PROJECTED",
                entitlement.user_class,
                entitlement.aggregate_downlink,
                entitlement.aggregate_uplink,
                authority.admin_permission,
                authority.secret_access,
                authority.privileged_execution,
                authority.production_mutation_authority,
            )

    def project_operations(self, result: EnforcementResult) -> OperationsProjection:
        if result.operations_state is not None:
            return OperationsProjection(
                result.operations_state,
                result.operations_reason_code or result.reason_code,
            )
        if result.decision is EnforcementDecision.UNKNOWN:
            return OperationsProjection(OperationsState.UNKNOWN, result.reason_code)
        if any(
            marker in result.reason_code
            for marker in ("STALE", "EXPIRED", "SUPERSEDED")
        ):
            return OperationsProjection(OperationsState.STALE, result.reason_code)
        if result.decision in (EnforcementDecision.ALLOW, EnforcementDecision.SHAPE):
            return OperationsProjection(OperationsState.PASS, result.reason_code)
        return OperationsProjection(OperationsState.FAIL, result.reason_code)

    def record_evidence(self, record: Mapping[str, Any]) -> EnforcementResult:
        if not isinstance(record, Mapping) or not self.EVIDENCE_REQUIRED_FIELDS.issubset(
            record.keys()
        ):
            return EnforcementResult(
                EnforcementDecision.DENY, False, "EVIDENCE_MALFORMED"
            )
        if not self._evidence_shape_is_valid(record):
            return EnforcementResult(
                EnforcementDecision.DENY, False, "EVIDENCE_MALFORMED"
            )
        if self._contains_sensitive_evidence(record):
            return EnforcementResult(
                EnforcementDecision.DENY,
                False,
                "EVIDENCE_SENSITIVE_DATA_REJECTED",
            )
        operations_state = record["operations_evidence"].get("state")
        if record["status"] == "PASS" and operations_state != OperationsState.PASS.value:
            return EnforcementResult(
                EnforcementDecision.DENY, False, "EVIDENCE_STATE_NOT_PASS"
            )
        with self._lock:
            self._evidence_records.append(deepcopy(dict(record)))
        return EnforcementResult(
            EnforcementDecision.ALLOW, True, "EVIDENCE_RECORDED"
        )

    def evidence_record_count(self) -> int:
        with self._lock:
            return len(self._evidence_records)

    def _bind_result(
        self,
        result: EnforcementResult,
        *,
        action: str,
        user_id: str,
        device_id: Optional[str] = None,
        entitlement_id: Optional[str] = None,
        entitlement: Optional[TrafficEntitlement] = None,
    ) -> EnforcementResult:
        """Attach the complete, Secret-safe result contract to every enforcement action."""
        with self._lock:
            bound = entitlement
            if bound is None and entitlement_id is not None:
                bound = self._entitlements.get(entitlement_id)
            observed = self._clock()
            current = self._state_summary(user_id)
            # The enclosing public operation holds this same lock through the
            # transition and result binding.  Use that authoritative snapshot
            # rather than branch-specific result defaults or stale values.
            registry_version = current["registry_version"]
            lease_version = current["lease_set_version"]
            before = dict(result.before) if result.before else current
            after = dict(result.after) if result.after else current
            # Only the path that actually validated this operation may attach
            # refs. Stored existence is not proof of current authority/context.
            refs = result.evidence_refs
            active_id = self._active_entitlements.get(user_id)
            authority_failure = result.reason_code in {
                "ENTITLEMENT_ID_IMMUTABLE_CONFLICT",
                "ENTITLEMENT_AUTHORITY_INVALID",
                "DEVICE_AUTHORITY_INVALID",
                "DEVICE_AUTHORITY_MISSING",
                "REVOKE_AUTHORITY_INVALID",
                "REVOKE_AUTHORITY_MISSING",
            }
            if authority_failure or not self._public_refs_are_safe(refs):
                refs = ()
            authority_bound = (
                bound is not None
                and active_id == bound.entitlement_id
                and bound.user_id == user_id
                and bool(refs)
                and not authority_failure
            )
            retry_safe = (
                result.decision is EnforcementDecision.ALLOW
                and not result.changed
                and result.reason_code
                in {
                    "ENTITLEMENT_ALREADY_ACTIVE",
                    "DEVICE_ALREADY_REGISTERED",
                    "DEVICE_LEASE_ALREADY_ACTIVE",
                }
            )
            return replace(
                result,
                registry_version=registry_version,
                lease_version=lease_version,
                active_device_count=current["active_leases"],
                observed_at=observed,
                effective_at=bound.effective_at if bound is not None else observed,
                user_id=user_id,
                device_id=device_id,
                environment=self._environment,
                action=action,
                entitlement_id=(bound.entitlement_id if bound is not None else entitlement_id),
                entitlement_version=(bound.entitlement_version if bound is not None else None),
                policy_version=(
                    bound.policy_version if bound is not None else self._policy_version
                ),
                enforcement_version=f"registry:{registry_version};lease:{lease_version}",
                before=before,
                after=after,
                verification={
                    "reason_code": result.reason_code,
                    "authority_bound": authority_bound,
                },
                evidence_refs=tuple(refs),
                safe_to_retry=retry_safe,
                lease_set_version=lease_version,
            )

    def _evidence_shape_is_valid(self, record: Mapping[str, Any]) -> bool:
        sha_pattern = re.compile(r"[0-9a-f]{40}")
        if record.get("status") not in {"PASS", "FAIL", "UNKNOWN", "STALE"}:
            return False
        if not all(
            isinstance(record.get(field), str)
            and sha_pattern.fullmatch(str(record[field])) is not None
            for field in ("base_commit", "implementation_commit")
        ):
            return False
        string_fields = ("branch", "diff_reference", "router_adr_version", "rollback_information")
        if not all(isinstance(record.get(field), str) and record[field] for field in string_fields):
            return False
        if not self._is_string_list(record.get("changed_files"), allow_empty=False):
            return False
        if not self._is_string_list(record.get("test_commands"), allow_empty=False):
            return False
        if not self._is_string_list(record.get("known_limitations"), allow_empty=True):
            return False
        results = record.get("full_test_results")
        if not isinstance(results, Mapping) or not {"passed", "failed"}.issubset(results):
            return False
        if not all(
            isinstance(results.get(field), int)
            and not isinstance(results.get(field), bool)
            and results[field] >= 0
            for field in ("passed", "failed")
        ):
            return False
        for field in (
            "contract_versions",
            "policy_schema_versions",
            "security_evidence",
            "operations_evidence",
        ):
            if not isinstance(record.get(field), Mapping) or not record[field]:
                return False
        operations_state = record["operations_evidence"].get("state")
        if not isinstance(operations_state, str) or operations_state not in {
            state.value for state in OperationsState
        }:
            return False
        return True

    @staticmethod
    def _is_string_list(value: Any, *, allow_empty: bool) -> bool:
        return (
            isinstance(value, list)
            and (allow_empty or bool(value))
            and all(isinstance(item, str) and bool(item) for item in value)
        )

    def _contains_sensitive_evidence(self, value: Any) -> bool:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                normalized = str(key).lower().replace("-", "_")
                if normalized in self.SENSITIVE_EVIDENCE_KEYS:
                    return True
                if self._contains_sensitive_evidence(nested):
                    return True
            return False
        if isinstance(value, (list, tuple)):
            return any(self._contains_sensitive_evidence(item) for item in value)
        if isinstance(value, str):
            if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
                return True
            if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", value):
                return True
            if re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", value):
                return True
            if re.search(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b", value):
                return True
            if re.search(r"\bAKIA[0-9A-Z]{16}\b", value):
                return True
            if re.search(r"\bAIza[0-9A-Za-z_-]{35}\b", value):
                return True
            if re.search(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", value):
                return True
            if re.search(r"https?://[^/\s:@]+:[^/\s@]+@", value):
                return True
            if re.search(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", value):
                return True
        return False

    @staticmethod
    def _version_key(value: str) -> tuple[tuple[int, Any], ...]:
        """Compare opaque-looking versions deterministically without numeric sentinels."""
        return tuple(
            (0, int(part)) if part.isdigit() else (1, part.lower())
            for part in re.findall(r"\d+|[A-Za-z]+", str(value))
        )

    def _validate_device_identity(
        self,
        identity: Optional[DeviceIdentity],
        *,
        user_id: str,
        device_id: str,
    ) -> Optional[str]:
        if identity is None:
            return "DEVICE_AUTHORITY_MISSING"
        if identity.user_id != user_id:
            return "DEVICE_USER_MISMATCH"
        if identity.device_id != device_id:
            return "DEVICE_ID_MISMATCH"
        if identity.identity_issuer != self._trusted_identity_issuer:
            return "DEVICE_ISSUER_MISMATCH"
        if identity.environment != self._environment:
            return "DEVICE_ENVIRONMENT_MISMATCH"
        if identity.registration_state != "REGISTERED":
            return "DEVICE_REGISTRATION_STATE_INVALID"
        if (
            not identity.proof_ref
            or type(identity.version) is not int
            or identity.version < 1
        ):
            return "DEVICE_PROOF_INVALID"
        try:
            verified = self._authority_verifier.verify_device_identity(identity)
        except Exception:
            verified = False
        if verified is not True:
            return "DEVICE_AUTHORITY_INVALID"
        previous = self._device_identity_versions.get((user_id, device_id), 0)
        if identity.version < previous:
            return "DEVICE_IDENTITY_VERSION_OLDER"
        stored = self._device_identities.get((user_id, device_id))
        if stored is not None and stored.version == identity.version and stored != identity:
            return "DEVICE_IDENTITY_VERSION_CONFLICT"
        return None

    def _validate_revoke_instruction(
        self,
        instruction: Optional[RevokeInstruction],
        *,
        user_id: str,
        device_id: str,
    ) -> Optional[str]:
        if instruction is None:
            return "REVOKE_AUTHORITY_MISSING"
        if instruction.user_id != user_id:
            return "REVOKE_USER_MISMATCH"
        if instruction.device_id != device_id:
            return "REVOKE_DEVICE_MISMATCH"
        if instruction.issuer != self._trusted_issuer:
            return "REVOKE_ISSUER_MISMATCH"
        if instruction.identity_issuer != self._trusted_identity_issuer:
            return "REVOKE_IDENTITY_ISSUER_MISMATCH"
        if instruction.environment != self._environment:
            return "REVOKE_ENVIRONMENT_MISMATCH"
        if not isinstance(instruction.effective_at, datetime):
            return "REVOKE_INSTRUCTION_INVALID"
        if (
            not instruction.instruction_id
            or not instruction.reason
            or not instruction.integrity_ref
            or type(instruction.evidence_refs) is not tuple
            or not instruction.evidence_refs
            or not all(type(item) is str and item for item in instruction.evidence_refs)
            or type(instruction.version) is not int
            or instruction.version < 1
            or instruction.effective_at.tzinfo is None
            or instruction.effective_at.utcoffset() is None
            or instruction.effective_at > self._clock()
        ):
            return "REVOKE_INSTRUCTION_INVALID"
        try:
            verified = self._authority_verifier.verify_revoke_instruction(instruction)
        except Exception:
            verified = False
        if verified is not True:
            return "REVOKE_AUTHORITY_INVALID"
        if not self._public_refs_are_safe(instruction.evidence_refs):
            return "REVOKE_INSTRUCTION_INVALID"
        previous = self._revoke_versions.get((user_id, device_id), 0)
        if instruction.version <= previous:
            return "REVOKE_VERSION_OLDER"
        return None

    def _require_entitlement(
        self, entitlement_id: str, user_id: str
    ) -> tuple[Optional[TrafficEntitlement], Optional[str]]:
        entitlement = self._entitlements.get(entitlement_id)
        if entitlement is None:
            return None, "ENTITLEMENT_MISSING"
        if entitlement.user_id != user_id:
            return None, "ENTITLEMENT_USER_MISMATCH"
        if self._active_entitlements.get(user_id) != entitlement_id:
            return None, "ENTITLEMENT_SUPERSEDED"
        reason = self._validate_entitlement(entitlement)
        if reason is not None:
            return None, reason
        return entitlement, None

    def _validate_entitlement(self, entitlement: TrafficEntitlement) -> Optional[str]:
        if not isinstance(entitlement.user_class, UserClass):
            return "ENTITLEMENT_ROLE_UNSUPPORTED"
        if entitlement.issuer != self._trusted_issuer:
            return "ENTITLEMENT_ISSUER_MISMATCH"
        if entitlement.identity_issuer != self._trusted_identity_issuer:
            return "ENTITLEMENT_IDENTITY_ISSUER_MISMATCH"
        if entitlement.environment != self._environment:
            return "ENTITLEMENT_ENVIRONMENT_MISMATCH"
        if entitlement.schema_version != self.ENTITLEMENT_SCHEMA_VERSION:
            return "ENTITLEMENT_VERSION_UNSUPPORTED"
        if entitlement.policy_version != self._policy_version:
            return "ENTITLEMENT_STALE"
        if entitlement.policy_id != self._policy_id:
            return "ENTITLEMENT_POLICY_MISMATCH"
        if (
            type(entitlement.entitlement_version) is not str
            or not entitlement.entitlement_version
        ):
            return "ENTITLEMENT_VERSION_INVALID"
        if (
            not entitlement.entitlement_id
            or not entitlement.user_id
            or not entitlement.integrity_ref
            or type(entitlement.evidence_refs) is not tuple
            or not entitlement.evidence_refs
            or not all(type(item) is str and item for item in entitlement.evidence_refs)
        ):
            return "ENTITLEMENT_INTEGRITY_INVALID"
        if entitlement.registry_schema_version != self.REGISTRY_SCHEMA_VERSION:
            return "REGISTRY_VERSION_UNSUPPORTED"
        if entitlement.lease_schema_version != self.LEASE_SCHEMA_VERSION:
            return "LEASE_VERSION_UNSUPPORTED"
        if entitlement.bandwidth_profile_version != self.BANDWIDTH_PROFILE_VERSION:
            return "BANDWIDTH_PROFILE_UNSUPPORTED"
        if entitlement.router_adr_version != self.ROUTER_ADR_VERSION:
            return "ROUTER_ADR_UNSUPPORTED"
        limits = (
            entitlement.max_registered_devices,
            entitlement.max_concurrent_devices,
            entitlement.aggregate_downlink,
            entitlement.aggregate_uplink,
        )
        if entitlement.user_class is UserClass.STANDARD_USER:
            expected = (2, 2, 5_000_000, 5_000_000)
            if any(limit.mode is not LimitMode.LIMITED for limit in limits) or tuple(
                int(limit.value) for limit in limits
            ) != expected:
                return "ENTITLEMENT_PROFILE_INVALID"
        elif not all(limit.mode is LimitMode.UNLIMITED for limit in limits):
            return "ENTITLEMENT_PROFILE_INVALID"
        if not all(
            isinstance(value, datetime)
            for value in (
                entitlement.issued_at,
                entitlement.effective_at,
                entitlement.expires_at,
            )
        ):
            return "ENTITLEMENT_TIME_INVALID"
        if (
            entitlement.issued_at.tzinfo is None
            or entitlement.issued_at.utcoffset() is None
            or entitlement.expires_at.tzinfo is None
            or entitlement.expires_at.utcoffset() is None
            or entitlement.expires_at <= entitlement.issued_at
            or entitlement.effective_at.tzinfo is None
            or entitlement.effective_at.utcoffset() is None
            or entitlement.effective_at < entitlement.issued_at
            or entitlement.expires_at <= entitlement.effective_at
        ):
            return "ENTITLEMENT_TIME_INVALID"
        now = self._clock()
        if entitlement.issued_at > now or entitlement.effective_at > now:
            return "ENTITLEMENT_NOT_YET_VALID"
        if entitlement.expires_at <= now:
            return "ENTITLEMENT_EXPIRED"
        try:
            verified = self._authority_verifier.verify_entitlement(entitlement)
        except Exception:
            verified = False
        if verified is not True:
            return "ENTITLEMENT_AUTHORITY_INVALID"
        if not self._public_refs_are_safe(entitlement.evidence_refs):
            return "ENTITLEMENT_INTEGRITY_INVALID"
        return None

    def _public_refs_are_safe(self, refs: Any) -> bool:
        """Screen authority-approved immutable references, not grant authority.

        Keep existing opaque and URI references. Known Secret signatures and
        credential assignments are values, even when signed or URI-wrapped.
        """
        return (
            type(refs) is tuple
            and bool(refs)
            and all(type(ref) is str and bool(ref) for ref in refs)
            and not self._contains_sensitive_evidence(refs)
            and not any(re.search(
                r"(?i)(?:password|token|api[_-]?key|client[_-]?secret|credential)"
                r"\s*[:=]", ref
            ) for ref in refs)
        )
