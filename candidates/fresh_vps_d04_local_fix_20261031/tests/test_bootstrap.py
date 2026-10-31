"""Offline candidate tests. No playbook, cloud-init, or target is executed."""

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


BOOTSTRAP = Path(__file__).resolve().parents[1]
PAYLOADS = (
    "cloud-init/user-data.yaml",
    "fixtures/synthetic-input.json",
    "ansible/playbook.yaml",
    "ansible/inventory.example.json",
)


def load_validator():
    spec = importlib.util.spec_from_file_location("bootstrap_validator", BOOTSTRAP / "validate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BootstrapOfflineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator()

    def setUp(self):
        # Synthetic temporary copies stay outside all project worktrees.
        self.scratch = tempfile.TemporaryDirectory(prefix="chiye-d03-offline-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        for relative in PAYLOADS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BOOTSTRAP / relative, destination)

    def read_payload(self, relative):
        text = (self.root / relative).read_text(encoding="utf-8")
        if text.startswith("#cloud-config\n"):
            text = text.split("\n", 1)[1]
        return json.loads(text)

    def write_payload(self, relative, value):
        header = "#cloud-config\n" if relative == PAYLOADS[0] else ""
        (self.root / relative).write_text(header + json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def validate(self):
        report = self.validator.validate(self.root, available_tools={})
        # The public report must remain serializable and use explicit statuses.
        json.dumps(report)
        for check in report["checks"]:
            self.assertIn(check["status"], {"PASS", "FAIL", "UNKNOWN", "NOT_EXECUTED"})
        return report

    def assert_failed(self):
        report = self.validate()
        self.assertEqual(report["offline_static_status"], "FAIL", report)
        self.assertEqual(report["overall_status"], "FAIL", report)
        self.assertTrue(any(check["status"] == "FAIL" for check in report["checks"]), report)
        return report

    def assert_ansible_rejected(self):
        report = self.assert_failed()
        checks = {check["id"]: check for check in report["checks"]}
        self.assertEqual(checks["ansible_structure"]["status"], "FAIL", report)
        self.assertEqual(checks["playbook_target_mutation"]["status"], "UNKNOWN", report)
        self.assertEqual(report["d02_applicability"], "UNKNOWN", report)
        return report

    def test_valid_candidate_is_only_an_offline_static_pass(self):
        report = self.validate()
        self.assertEqual(report["offline_static_status"], "PASS", report)
        self.assertEqual(report["overall_status"], "UNKNOWN", report)
        unavailable = [check for check in report["checks"] if check["reason"] == "DEPENDENCY_UNAVAILABLE"]
        self.assertGreaterEqual(len(unavailable), 2, report)
        self.assertTrue(all(check["status"] == "NOT_EXECUTED" for check in unavailable))
        runtime = [check for check in report["checks"] if "idempotence" in check["id"]]
        self.assertTrue(runtime, report)
        self.assertTrue(all(check["status"] == "NOT_EXECUTED" for check in runtime))

    def test_valid_playbook_declares_no_target_mutation_without_granting_approval(self):
        value = self.read_payload("ansible/playbook.yaml")
        self.assertEqual(value[0]["tasks"], [])
        self.assertEqual(
            [set(task) - {"name"} for task in value[0]["pre_tasks"]],
            [{"ansible.builtin.assert"}, {"ansible.builtin.assert"},
             {"ansible.builtin.setup"}, {"ansible.builtin.assert"}],
        )
        report = self.validate()
        checks = {check["id"]: check for check in report["checks"]}
        self.assertEqual(checks["playbook_target_mutation"]["status"], "PASS", report)
        self.assertEqual(checks["playbook_target_mutation"]["reason"], "NO_TARGET_CONFIGURATION_MUTATION_DECLARED", report)
        self.assertEqual(checks["playbook_target_mutation"]["mutation_status"], "NONE_DECLARED", report)
        self.assertIs(checks["playbook_target_mutation"]["native_execution_performed"], False)
        self.assertEqual(report["d02_applicability"], "NOT_APPLICABLE_TO_NON_MUTATING_V0.1_CANDIDATE")
        self.assertIs(report["d02_approval_pending"], True)
        self.assertEqual(report["remaining_findings"], {"D-03": "OPEN", "D-04": "OPEN"})
        self.assertEqual(report["security_gate"], "PENDING")
        self.assertEqual(report["independent_verification"], "PENDING")
        self.assertEqual(report["gate_b_authorized"], "NO")
        self.assertEqual(report["overall_status"], "UNKNOWN")

    def test_invalid_or_missing_playbook_cannot_claim_mutation_absent(self):
        path = self.root / "ansible/playbook.yaml"
        for raw in (b"[{", b"null", None):
            with self.subTest(raw=raw):
                if raw is None:
                    path.unlink()
                else:
                    path.write_bytes(raw)
                self.assert_ansible_rejected()

    def test_all_four_statuses_retain_their_evidence_meaning(self):
        valid = self.validate()
        self.assertIn("PASS", {c["status"] for c in valid["checks"]})
        self.assertIn("UNKNOWN", {c["status"] for c in valid["checks"]})
        self.assertIn("NOT_EXECUTED", {c["status"] for c in valid["checks"]})
        (self.root / "cloud-init/user-data.yaml").unlink()
        failed = self.assert_failed()
        checks = {check["id"]: check for check in failed["checks"]}
        self.assertEqual(checks["cloud_init_structure"]["status"], "FAIL")
        self.assertEqual(checks["cloud_init_synthetic_render"]["status"], "NOT_EXECUTED")
        self.assertEqual(checks["secret_safe_review"]["status"], "UNKNOWN")
        self.assertEqual(checks["cloud_init_native_schema"]["status"], "NOT_EXECUTED")

    def test_tool_presence_does_not_execute_tools_or_invent_native_pass(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("external execution prohibited")) as run:
            report = self.validator.validate(
                self.root,
                available_tools={"cloud-init": "/synthetic/cloud-init", "ansible-playbook": "/synthetic/ansible-playbook"},
            )
        run.assert_not_called()
        self.assertEqual(report["offline_static_status"], "PASS", report)
        self.assertEqual(report["overall_status"], "UNKNOWN", report)
        native = [check for check in report["checks"] if "native" in check["id"]]
        self.assertGreaterEqual(len(native), 2, report)
        self.assertTrue(all(check["status"] == "NOT_EXECUTED" for check in native), report)

    def test_missing_payload_fails(self):
        (self.root / "cloud-init/user-data.yaml").unlink()
        self.assert_failed()

    def test_malformed_json_fails(self):
        (self.root / "ansible/playbook.yaml").write_text("[{", encoding="utf-8")
        self.assert_failed()

    def test_duplicate_json_key_fails_even_when_last_value_is_valid(self):
        path = self.root / "cloud-init/user-data.yaml"
        original = path.read_text(encoding="utf-8")
        self.assertIn('"users"', original)
        path.write_text(original.replace('"users":', '"users": [], "users":', 1), encoding="utf-8")
        self.assert_failed()

    def test_non_finite_json_number_fails(self):
        path = self.root / "fixtures/synthetic-input.json"
        path.write_text('{"bootstrap_user": NaN, "ssh_public_key": "synthetic"}', encoding="utf-8")
        self.assert_failed()

    def test_wrong_top_level_types_fail_without_exception(self):
        for relative in PAYLOADS:
            with self.subTest(payload=relative):
                original = (self.root / relative).read_bytes()
                try:
                    self.write_payload(relative, None)
                    self.assert_failed()
                finally:
                    (self.root / relative).write_bytes(original)

    def test_cloud_init_header_is_required(self):
        path = self.root / "cloud-init/user-data.yaml"
        path.write_text(path.read_text(encoding="utf-8").split("\n", 1)[1], encoding="utf-8")
        self.assert_failed()

    def test_cloud_init_command_directive_is_rejected(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["runcmd"] = [["echo", "synthetic-only"]]
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_cloud_init_password_or_ssh_hardening_is_rejected(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["ssh_pwauth"] = False
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_cloud_init_default_user_must_be_preserved(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["users"] = [user for user in value["users"] if user != "default"]
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_cloud_init_privileged_user_is_rejected(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["users"][1]["sudo"] = "ALL=(ALL) NOPASSWD:ALL"
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_unlocked_password_is_rejected(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["users"][1]["lock_passwd"] = False
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_password_lock_requires_boolean_not_integer(self):
        value = self.read_payload("cloud-init/user-data.yaml")
        value["users"][1]["lock_passwd"] = 1
        self.write_payload("cloud-init/user-data.yaml", value)
        self.assert_failed()

    def test_username_injection_is_rejected(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        value["bootstrap_user"] = "synthetic\nroot"
        self.write_payload("fixtures/synthetic-input.json", value)
        self.assert_failed()

    def test_privileged_fixture_username_is_rejected(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        value["bootstrap_user"] = "root"
        self.write_payload("fixtures/synthetic-input.json", value)
        self.assert_failed()

    def test_ssh_key_newline_injection_is_rejected(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        value["ssh_public_key"] += "\ncommand=synthetic"
        self.write_payload("fixtures/synthetic-input.json", value)
        self.assert_failed()

    def test_invalid_public_key_is_rejected(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        value["ssh_public_key"] = "ssh-ed25519 invalid-base64 synthetic-only"
        self.write_payload("fixtures/synthetic-input.json", value)
        self.assert_failed()

    def test_changed_synthetic_key_blob_is_rejected_despite_fixture_comment(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        parts = value["ssh_public_key"].split(" ")
        blob = bytearray(base64.b64decode(parts[1]))
        # Alter fixed fixture bytes only; no keypair or cryptographic key is generated.
        blob[-1] ^= 1
        parts[1] = base64.b64encode(blob).decode("ascii")
        value["ssh_public_key"] = " ".join(parts)
        self.write_payload("fixtures/synthetic-input.json", value)
        self.assert_failed()

    def test_real_key_material_is_not_required_for_validation(self):
        value = self.read_payload("fixtures/synthetic-input.json")
        self.assertIn("synthetic", value["ssh_public_key"].lower())
        self.assertEqual(self.validate()["offline_static_status"], "PASS")

    def test_ansible_shell_task_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["tasks"].append({"name": "Synthetic forbidden shell", "ansible.builtin.shell": "echo synthetic"})
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_firewall_task_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["tasks"].append({"name": "Synthetic forbidden firewall", "ansible.builtin.iptables": {"chain": "INPUT", "policy": "DROP"}})
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_target_mutation_modules_are_rejected(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        mutations = {
            "ansible.builtin.file": {"path": "/etc/systemd/journald.conf.d", "state": "directory"},
            "ansible.builtin.copy": {"dest": "/etc/systemd/journald.conf.d/60-chiye-bootstrap.conf", "content": "[Journal]\nStorage=auto\nSystemMaxUse=256M\nRuntimeMaxUse=64M\n"},
            "ansible.builtin.template": {"src": "synthetic.j2", "dest": "/etc/systemd/journald.conf.d/synthetic.conf"},
            "ansible.builtin.lineinfile": {"path": "/etc/ssh/sshd_config", "line": "# synthetic-never-apply"},
            "ansible.builtin.service": {"name": "systemd-journald", "state": "restarted"},
            "ansible.builtin.systemd": {"daemon_reload": True},
            "ansible.builtin.systemd_service": {"name": "systemd-journald", "state": "reloaded"},
            "ansible.builtin.command": {"argv": ["ip", "route", "add", "192.0.2.0/24", "dev", "synthetic0"]},
            "ansible.builtin.shell": "echo synthetic-never-execute",
            "ansible.posix.authorized_key": {"user": "synthetic", "key": "synthetic-never-use"},
            "ansible.builtin.iptables": {"chain": "INPUT", "policy": "DROP"},
            "ansible.posix.sysctl": {"name": "net.ipv4.ip_forward", "value": "1"},
        }
        for module, arguments in mutations.items():
            with self.subTest(module=module):
                value = json.loads(json.dumps(baseline))
                value[0]["tasks"] = [{"name": "Synthetic prohibited mutation", module: arguments}]
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()

    def test_non_journald_target_file_mutation_is_also_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["tasks"] = [{"name": "Synthetic other target write", "ansible.builtin.copy": {"dest": "/tmp/synthetic-never-create", "content": "synthetic"}}]
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_ansible_rejected()

    def test_mutation_cannot_hide_behind_disabled_conditions_or_tags(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        for disabled in ({"when": False}, {"tags": ["never"]}):
            with self.subTest(disabled=disabled):
                value = json.loads(json.dumps(baseline))
                task = {"name": "Synthetic dormant write", "ansible.builtin.copy": {"dest": "/etc/systemd/journald.conf.d/synthetic.conf", "content": "[Journal]\nSystemMaxUse=256M\n"}}
                task.update(disabled)
                value[0]["tasks"] = [task]
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()

    def test_alternate_execution_surfaces_are_rejected(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        mutation = {"name": "Synthetic hidden write", "ansible.builtin.copy": {"dest": "/etc/systemd/journald.conf.d/synthetic.conf", "content": "synthetic"}}
        additions = {
            "handlers": [mutation],
            "post_tasks": [mutation],
            "roles": ["synthetic_never_load"],
            "module_defaults": {"ansible.builtin.copy": {"dest": "/etc/synthetic"}},
            "connection": "local",
            "become_user": "root",
        }
        for key, added in additions.items():
            with self.subTest(key=key):
                value = json.loads(json.dumps(baseline))
                value[0][key] = added
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()

    def test_imports_includes_and_blocks_are_rejected(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        operations = {
            "ansible.builtin.import_tasks": "synthetic-never-load.yaml",
            "ansible.builtin.include_tasks": "synthetic-never-load.yaml",
            "ansible.builtin.include_role": {"name": "synthetic_never_load"},
            "block": [{"ansible.builtin.command": "echo synthetic-never-execute"}],
        }
        for operation, arguments in operations.items():
            with self.subTest(operation=operation):
                value = json.loads(json.dumps(baseline))
                value[0]["tasks"] = [{"name": "Synthetic alternate task", operation: arguments}]
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()
        self.write_payload("ansible/playbook.yaml", [{"ansible.builtin.import_playbook": "synthetic-never-load.yaml"}])
        self.assert_ansible_rejected()

    def test_fact_pretask_cannot_be_replaced_with_mutation(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["pre_tasks"][2] = {"name": "Synthetic mutation instead of facts", "ansible.builtin.copy": {"dest": "/etc/synthetic", "content": "synthetic"}}
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_ansible_rejected()

    def test_root_requirement_cannot_be_reintroduced(self):
        value = self.read_payload("ansible/playbook.yaml")
        assertions = value[0]["pre_tasks"][3]["ansible.builtin.assert"]["that"]
        assertions.append("ansible_facts['effective_user_id'] == 0")
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_ansible_rejected()

    def test_unverified_real_fact_collection_must_remain_blocked(self):
        value = self.read_payload("ansible/playbook.yaml")
        self.assertEqual(value[0]["pre_tasks"][1]["ansible.builtin.assert"]["that"], ["false"])
        value[0]["pre_tasks"][1]["ansible.builtin.assert"]["that"] = ["true"]
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_ansible_rejected()

    def test_fact_path_and_local_facts_must_not_be_changed(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        for mutation in ("fact_path", "local", "dynamic_fact", "min"):
            with self.subTest(mutation=mutation):
                value = json.loads(json.dumps(baseline))
                setup = value[0]["pre_tasks"][2]["ansible.builtin.setup"]
                if mutation == "fact_path":
                    setup["fact_path"] = "/etc/ansible/facts.d"
                elif mutation == "local":
                    setup["gather_subset"].append("local")
                elif mutation == "dynamic_fact":
                    setup["dynamic_fact"] = "synthetic.fact"
                else:
                    setup["gather_subset"].remove("!min")
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()

    def test_unsupported_connection_or_privilege_injections_are_rejected(self):
        baseline = self.read_payload("ansible/playbook.yaml")
        for key in ("ansible_connection", "ansible_user", "ansible_become",
                    "ansible_become_user", "ansible_python_interpreter", "ansible_ssh_common_args"):
            with self.subTest(key=key):
                value = json.loads(json.dumps(baseline))
                value[0]["vars"][key] = "synthetic"
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_ansible_rejected()

    def test_synthetic_fact_classification_does_not_accept_missing_or_invalid_values(self):
        valid = {"system": "Linux", "os_family": "Debian", "service_mgr": "systemd", "effective_user_id": 1001}
        self.assertEqual(self.validator.classify_synthetic_facts(valid), "PASS")
        for value in (None, {}, {"system": "Linux"}):
            with self.subTest(value=value):
                self.assertEqual(self.validator.classify_synthetic_facts(value), "UNKNOWN")
        for key, value in (("system", None), ("os_family", 1), ("service_mgr", []),
                           ("effective_user_id", None), ("effective_user_id", True),
                           ("effective_user_id", "1001")):
            with self.subTest(key=key, value=value):
                bad = dict(valid, **{key: value})
                self.assertEqual(self.validator.classify_synthetic_facts(bad), "UNKNOWN")
        for key, value in (("system", "Other"), ("os_family", "Other"),
                           ("service_mgr", "Other"), ("effective_user_id", 0),
                           ("effective_user_id", -1)):
            with self.subTest(key=key, value=value):
                bad = dict(valid, **{key: value})
                self.assertEqual(self.validator.classify_synthetic_facts(bad), "FAIL")

    def test_missing_or_weakened_uid_guard_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["pre_tasks"][3]["ansible.builtin.assert"]["that"].remove(
            "ansible_facts['effective_user_id'] is integer")
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_ansible_rejected()

    def test_prior_d04_launcher_rejects_the_new_candidate_without_executor_call(self):
        entry = BOOTSTRAP / "ansible/controlled_entry.py"
        digest = hashlib.sha256(entry.read_bytes()).hexdigest()
        # Historical D4 evidence pin b5218f2a… retired (pre-repair 8244 B entry).
        # Full equality pin of controlled_entry inside this receipt-tracked file
        # forms a receipt↔RECEIPT_SHA256↔pin cycle; bind repaired entry instead.
        self.assertNotEqual(
            digest, "b5218f2a5ac86c6caf37c28b2b113f0a56d7a64d48eca197e8ba70bf2a6a417a")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        spec = importlib.util.spec_from_file_location("prior_d04_launcher", entry)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.RECEIPT, "evidence/d04-repair/builder-receipt.json")
        self.assertNotEqual(module.RECEIPT_SHA256, module.LEGACY_RECEIPT_SHA256)
        executor = mock.Mock(name="synthetic_executor")
        with mock.patch.dict("os.environ", {}, clear=True):
            result = module.evaluate(module.offline_request(), executor=executor)
        self.assertEqual(result["decision"], "DENY", result)
        self.assertEqual(result["reason"], "REAL_EXECUTION_BOUNDARIES_NOT_ESTABLISHED", result)
        self.assertEqual(result["executor_calls"], 0, result)
        executor.assert_not_called()

    def test_ansible_authorization_cannot_default_to_true(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["vars"]["bootstrap_apply_authorized"] = True
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_recovery_cannot_default_to_true(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["vars"]["bootstrap_recovery_ready"] = True
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_authorization_requires_boolean_not_integer(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["vars"]["bootstrap_apply_authorized"] = 0
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_implicit_privilege_escalation_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["become"] = True
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_early_fact_gathering_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["gather_facts"] = True
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_preconditions_cannot_be_removed(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["pre_tasks"] = []
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_remote_inventory_is_rejected(self):
        value = self.read_payload("ansible/inventory.example.json")
        value["all"]["children"]["bootstrap_candidates"]["hosts"] = {"synthetic.invalid": {"ansible_host": "192.0.2.10"}}
        self.write_payload("ansible/inventory.example.json", value)
        self.assert_failed()

    def test_ansible_play_name_lookup_expression_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["name"] = "{{ lookup('pipe', 'echo synthetic-never-execute') }}"
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_pretask_name_lookup_expression_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["pre_tasks"][0]["name"] = "{{ lookup('pipe', 'echo synthetic-never-execute') }}"
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_fail_message_lookup_expression_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        value[0]["pre_tasks"][0]["ansible.builtin.assert"]["fail_msg"] = "{{ lookup('pipe', 'echo synthetic-never-execute') }}"
        self.write_payload("ansible/playbook.yaml", value)
        self.assert_failed()

    def test_ansible_journald_comment_lookup_expression_is_rejected(self):
        value = self.read_payload("ansible/playbook.yaml")
        # Reintroduce the removed write only as rejected synthetic input.
        value[0]["tasks"] = [{
            "name": "Synthetic legacy journald write",
            "ansible.builtin.copy": {
                "dest": "/etc/systemd/journald.conf.d/synthetic.conf",
                "content": "# {{ lookup('pipe', 'echo synthetic-never-execute') }}\n[Journal]\nStorage=auto\n",
            },
        }]
        self.write_payload("ansible/playbook.yaml", value)
        report = self.assert_ansible_rejected()
        # Verify Jinja was detected, not just that nonempty tasks were rejected.
        self.assertTrue(any("Jinja" in check.get("detail", "") for check in report["checks"]), report)

    def test_ansible_other_jinja_delimiters_are_rejected(self):
        for expression in ("{% set synthetic = 'never-execute' %}", "{# synthetic template comment #}"):
            with self.subTest(expression=expression):
                value = self.read_payload("ansible/playbook.yaml")
                value[0]["pre_tasks"][0]["name"] = expression
                self.write_payload("ansible/playbook.yaml", value)
                self.assert_failed()

    def test_oversized_otherwise_valid_json_is_rejected(self):
        path = self.root / "fixtures/synthetic-input.json"
        path.write_bytes(path.read_bytes() + b" " * (256 * 1024))
        report = self.assert_failed()
        self.assertTrue(any("size limit" in check.get("detail", "") for check in report["checks"]), report)

    def test_invalid_utf8_payload_is_rejected(self):
        path = self.root / "fixtures/synthetic-input.json"
        path.write_bytes(b"\xff")
        self.assert_failed()

    def test_symlink_payload_is_rejected(self):
        path = self.root / "cloud-init/user-data.yaml"
        path.unlink()
        path.symlink_to(BOOTSTRAP / "cloud-init/user-data.yaml")
        self.assert_failed()

    def test_validation_preserves_source_bytes_and_file_set(self):
        def snapshot():
            return {
                str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.root.rglob("*") if path.is_file()
            }

        before = snapshot()
        self.validate()
        self.assertEqual(snapshot(), before)

    def test_cli_success_returns_json_and_zero(self):
        completed = subprocess.run(
            [sys.executable, "-B", str(BOOTSTRAP / "validate.py"), "--root", str(self.root)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["offline_static_status"], "PASS", report)
        self.assertEqual(report["overall_status"], "UNKNOWN", report)

    def test_cli_malformed_input_returns_json_and_nonzero(self):
        (self.root / "fixtures/synthetic-input.json").write_text("{", encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-B", str(BOOTSTRAP / "validate.py"), "--root", str(self.root)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["offline_static_status"], "FAIL", report)
        self.assertEqual(report["overall_status"], "FAIL", report)
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
