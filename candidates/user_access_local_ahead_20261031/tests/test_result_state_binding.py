"""Regression tests for atomic result state binding (synthetic Lab only)."""
import unittest

from chiye_net.user_access import EnforcementDecision, RouterMode, TrafficDirection, UserClass
from tests.test_user_access_enforcement import enforcer, entitlement, register, revoke


class ResultStateBindingTests(unittest.TestCase):
    def make_active(self, count):
        runtime = enforcer()
        self.assertEqual(runtime.install_entitlement(entitlement()).decision, EnforcementDecision.ALLOW)
        for index in range(count):
            device = f"device-{index}"
            self.assertEqual(register(runtime, "ent-standard-001", "user-alpha", device).decision, EnforcementDecision.ALLOW)
            self.assertEqual(runtime.acquire_device_lease("ent-standard-001", "user-alpha", device).decision, EnforcementDecision.ALLOW)
        return runtime

    def assert_binding(self, result, registry, lease, active):
        self.assertEqual((result.registry_version, result.lease_version, result.lease_set_version, result.active_device_count), (registry, lease, lease, active))
        self.assertEqual(result.enforcement_version, f"registry:{registry};lease:{lease}")

    def test_register_with_an_existing_active_lease(self):
        runtime = self.make_active(1)
        result = register(runtime, "ent-standard-001", "user-alpha", "device-second")
        self.assertEqual(result.decision, EnforcementDecision.ALLOW)
        self.assertEqual((result.after["registry_version"], result.after["lease_set_version"], result.after["active_leases"]), (2, 1, 1))
        self.assert_binding(result, 2, 1, 1)

    def test_policy_update_preserves_existing_leases(self):
        runtime = self.make_active(2)
        update = entitlement(entitlement_id="ent-upgrade", entitlement_version="ent-v2", user_class=UserClass.OWNER_USER)
        result = runtime.install_entitlement(update)
        self.assertEqual(result.decision, EnforcementDecision.ALLOW)
        self.assertEqual((result.after["registry_version"], result.after["lease_set_version"], result.after["active_leases"]), (2, 2, 2))
        self.assert_binding(result, 2, 2, 2)

    def test_traffic_accounting_carries_current_state(self):
        runtime = self.make_active(2)
        result = runtime.account_traffic("ent-standard-001", "user-alpha", "device-0", TrafficDirection.DOWNLINK, window_id="synthetic", bytes_in_window=123)
        self.assertEqual(result.decision, EnforcementDecision.ALLOW)
        self.assertEqual(result.after["aggregate_bytes_after"], 123)
        self.assert_binding(result, 2, 2, 2)

    def test_policy_noop_carries_current_state(self):
        runtime = self.make_active(1)
        result = runtime.install_entitlement(entitlement())
        self.assertEqual(result.reason_code, "ENTITLEMENT_ALREADY_ACTIVE")
        self.assertFalse(result.changed)
        self.assertEqual(result.before, result.after)
        self.assert_binding(result, 1, 1, 1)

    def test_router_control_after_multiple_transitions(self):
        runtime = self.make_active(2)
        revoke(runtime, "ent-standard-001", "user-alpha", "device-1")
        result = runtime.evaluate_router_access("ent-standard-001", "user-alpha", RouterMode.INDIVIDUAL_DEVICE, downstream_device_id="device-0", downstream_device_count=1, downstream_identity_authoritative=True, downstream_accounting_authoritative=True, router_id="synthetic-router")
        self.assertEqual(result.decision, EnforcementDecision.ALLOW)
        self.assert_binding(result, 3, 3, 1)

    def test_denial_and_idempotent_lease_reflect_authoritative_current_state(self):
        runtime = self.make_active(2)
        denied = register(runtime, "ent-standard-001", "user-alpha", "device-third")
        self.assertEqual(denied.reason_code, "REGISTERED_DEVICE_LIMIT_REACHED")
        self.assertFalse(denied.changed)
        self.assertEqual(denied.before, denied.after)
        self.assert_binding(denied, 2, 2, 2)
        again = runtime.acquire_device_lease("ent-standard-001", "user-alpha", "device-0")
        self.assertEqual(again.reason_code, "DEVICE_LEASE_ALREADY_ACTIVE")
        self.assertFalse(again.changed)
        self.assert_binding(again, 2, 2, 2)
