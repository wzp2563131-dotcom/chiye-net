#!/usr/bin/env python3
"""Offline-only D-04 prototype. This module cannot execute Ansible.

The optional executor argument exists solely so offline tests can prove it is
never called. No authorization reference supplied here grants real authority.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).absolute().parents[1]
LEGACY_RECEIPT = "evidence/fix-01/builder-receipt.json"
LEGACY_RECEIPT_SHA256 = "b6c1dd0524090e44db7b823ca5323a526954bfd6c477063571d8aebba7ca9f02"
RECEIPT = "evidence/d04-repair/builder-receipt.json"
# Byte binding only. Independent acceptance of this candidate is still pending.
RECEIPT_SHA256 = "a91b5cb9785d346ffe9ae3736e19381c1e3c6ac7bc9ee1cb00572b27e5c71a63"
SYNTHETIC_REF = "synthetic:offline-review-only"
PLAYBOOK = "ansible/playbook.yaml"
INVENTORY = "ansible/inventory.example.json"
MAX_FILE = 2 * 1024 * 1024


class Rejected(Exception):
    """A safe, non-secret reason code for a fail-closed result."""


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_regular(root, relative):
    """Read bounded files without following symlinks; check replacement signs.

    This is detection, not protected staging or a race-free execution boundary.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        raise Rejected("NO_NOFOLLOW_SUPPORT")
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in ("..", ".") for p in rel.parts):
        raise Rejected("INVALID_FIXED_PATH")
    current = root
    try:
        if current.is_symlink() or not current.is_dir():
            raise Rejected("INVALID_CANDIDATE_ROOT")
        for part in rel.parts[:-1]:
            current = current / part
            meta = current.lstat()
            if not stat.S_ISDIR(meta.st_mode):
                raise Rejected("SYMLINK_OR_NON_DIRECTORY")
        path = current / rel.parts[-1]
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise Rejected("INVALID_INPUT_FILE")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            first = os.fstat(fd)
            if _identity(first) != _identity(before):
                raise Rejected("FILE_REPLACED")
            chunks, total = [], 0
            while True:
                data = os.read(fd, 65536)
                if not data:
                    break
                total += len(data)
                if total > MAX_FILE:
                    raise Rejected("INPUT_TOO_LARGE")
                chunks.append(data)
            if _identity(first) != _identity(os.fstat(fd)):
                raise Rejected("FILE_REPLACED")
        finally:
            os.close(fd)
        if _identity(first) != _identity(path.lstat()):
            raise Rejected("FILE_REPLACED")
        return b"".join(chunks)
    except OSError:
        raise Rejected("INPUT_UNAVAILABLE_OR_UNSAFE") from None


def _capture_legacy_candidate(root):
    """Bind all unchanged FIX-01 files; README is the authorized update."""
    receipt_bytes = _read_regular(root, LEGACY_RECEIPT)
    if hashlib.sha256(receipt_bytes).hexdigest() != LEGACY_RECEIPT_SHA256:
        raise Rejected("RECEIPT_MISMATCH")
    try:
        receipt = json.loads(receipt_bytes)
        old_files = receipt["file_sha256_excluding_this_receipt"]
        source_hashes = receipt["new_source_sha256"]
        if not isinstance(old_files, dict) or len(old_files) != 31:
            raise ValueError
        prefix = "infrastructure/bootstrap/"
        snapshot = {RECEIPT: hashlib.sha256(receipt_bytes).hexdigest()}
        validator_bytes = None
        for repo_path, expected in old_files.items():
            if not isinstance(repo_path, str) or not repo_path.startswith(prefix):
                raise ValueError
            relative = repo_path[len(prefix):]
            if relative == "README.md":
                continue  # The only permitted change to the original 32 files.
            content = _read_regular(root, relative)
            digest = hashlib.sha256(content).hexdigest()
            if digest != expected:
                raise Rejected("CANDIDATE_MISMATCH")
            snapshot[relative] = digest
            if relative == "validate.py":
                validator_bytes = content
        if validator_bytes is None or len(snapshot) != 31:
            raise ValueError
        expected_payloads = {
            name: source_hashes[prefix + name]
            for name in ("cloud-init/user-data.yaml", "fixtures/synthetic-input.json",
                         PLAYBOOK, INVENTORY)
        }
        return snapshot, validator_bytes, expected_payloads
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise Rejected("INVALID_RECEIPT") from None


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _load_json(data):
    def nonfinite(_value):
        raise ValueError("non-finite number")
    return json.loads(data, object_pairs_hook=_json_object, parse_constant=nonfinite)


def _capture_candidate(root):
    """Capture fixed bytes, not an atomic filesystem snapshot or trust root.

    The immutable historical receipt fixes the original path set. The new
    receipt binds all 32 historical files plus the revised launcher tests.
    Launcher/receipt/manifest are bound together by the external review Manifest;
    they cannot grant their own independent acceptance or execution authority.
    """
    if RECEIPT == LEGACY_RECEIPT and RECEIPT_SHA256 == LEGACY_RECEIPT_SHA256:
        return _capture_legacy_candidate(root)
    raw = _read_regular(root, RECEIPT)
    if hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
        raise Rejected("RECEIPT_MISMATCH")
    legacy_raw = _read_regular(root, LEGACY_RECEIPT)
    if hashlib.sha256(legacy_raw).hexdigest() != LEGACY_RECEIPT_SHA256:
        raise Rejected("RECEIPT_MISMATCH")
    try:
        legacy = _load_json(legacy_raw)
        prefix = "infrastructure/bootstrap/"
        old_files = legacy["file_sha256_excluding_this_receipt"]
        if type(old_files) is not dict or len(old_files) != 31:
            raise ValueError
        if any(not p.startswith(prefix) for p in old_files):
            raise ValueError
        required = {p[len(prefix):] for p in old_files}
        required.update((LEGACY_RECEIPT, "tests/test_controlled_entry.py"))
        receipt = _load_json(raw)
        if (type(receipt) is not dict or set(receipt) != {
                "schema_version", "scope", "legacy_receipt_sha256", "files", "payload_sha256"}
                or receipt["schema_version"] != "d04-repair-v1"
                or receipt["scope"] != "OFFLINE_ONLY_NOT_AUTHORITY"
                or receipt["legacy_receipt_sha256"] != LEGACY_RECEIPT_SHA256):
            raise ValueError
        files, payloads = receipt["files"], receipt["payload_sha256"]
        if type(files) is not dict or set(files) != required or len(files) != 33:
            raise ValueError
        for record in files.values():
            if (type(record) is not dict or set(record) != {"size", "sha256"}
                    or type(record["size"]) is not int or not 0 <= record["size"] <= MAX_FILE
                    or type(record["sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None):
                raise ValueError
        payload_names = ("cloud-init/user-data.yaml", "fixtures/synthetic-input.json", PLAYBOOK, INVENTORY)
        if type(payloads) is not dict or payloads != {p: files[p]["sha256"] for p in payload_names}:
            raise ValueError
        snapshot = {RECEIPT: raw}
        for relative, expected in files.items():
            content = _read_regular(root, relative)
            if (len(content) != expected["size"]
                    or hashlib.sha256(content).hexdigest() != expected["sha256"]):
                raise Rejected("CANDIDATE_MISMATCH")
            snapshot[relative] = content
        return snapshot, snapshot["validate.py"], payloads
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        raise Rejected("INVALID_RECEIPT") from None


def _validate_snapshot(snapshot, validator_bytes):
    """Reuse the verified validator with a bounded in-memory payload reader.

    No target files or plugins are executed. The four payloads come exclusively
    from captured bytes; a second capture still detects observed disk changes.
    """
    namespace = {"__name__": "controlled_offline_validator", "__file__": str(ROOT / "validate.py")}
    exec(compile(validator_bytes, str(ROOT / "validate.py"), "exec"), namespace)

    def read_payload(_root, relative):
        if relative not in namespace["PAYLOADS"].values():
            raise Rejected("INPUT_NOT_ALLOWLISTED")
        data = snapshot[relative]
        namespace["require"](len(data) <= namespace["MAX_BYTES"], "Payload exceeds offline size limit")
        text = data.decode("utf-8")
        if relative == "cloud-init/user-data.yaml":
            namespace["require"](text.startswith("#cloud-config\n"), "Missing cloud-config header")
            text = text[len("#cloud-config\n"):]
        return _load_json(text), data

    namespace["read_payload"] = read_payload
    return namespace["validate"](ROOT, available_tools={})


def _ambient_environment_is_safe():
    # No environment is forwarded anywhere. Refuse common injection channels
    # even during this prototype; this does not isolate the Python interpreter.
    forbidden = ("ANSIBLE_", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_")
    return not any(any(key.startswith(prefix) for prefix in forbidden) for key in os.environ)


def offline_request():
    """Return the only accepted synthetic request shape, not real authority."""
    return {"playbook": PLAYBOOK, "inventory": INVENTORY, "arguments": [],
            "environment": {}, "authorization_ref": SYNTHETIC_REF}


def evaluate(request, executor=None):
    """Validate offline and deny execution; executor is intentionally unused."""
    del executor
    def deny(reason, validator_status="NOT_EXECUTED"):
        return {"decision": "DENY", "reason": reason,
                "validator_status": validator_status, "executor_calls": 0,
                "real_execution": "NOT_IMPLEMENTED",
                "real_authorization": "NOT_ESTABLISHED",
                "protected_staging": "NOT_ESTABLISHED",
                "d03_05_boundary": "NOT_ESTABLISHED"}
    if type(request) is not dict or set(request) != set(offline_request()):
        return deny("INVALID_REQUEST_SHAPE")
    if (type(request["playbook"]) is not str or type(request["inventory"]) is not str
            or request["playbook"] != PLAYBOOK or request["inventory"] != INVENTORY):
        return deny("INPUT_NOT_ALLOWLISTED")
    if type(request["arguments"]) is not list or request["arguments"] != []:
        return deny("ARGUMENT_NOT_ALLOWLISTED")
    if type(request["environment"]) is not dict or request["environment"] != {}:
        return deny("ENVIRONMENT_NOT_ALLOWLISTED")
    if type(request["authorization_ref"]) is not str or request["authorization_ref"] != SYNTHETIC_REF:
        return deny("AUTHORIZATION_REFERENCE_REJECTED")
    if not _ambient_environment_is_safe():
        return deny("AMBIENT_ENVIRONMENT_REJECTED")
    try:
        before, validator_bytes, expected_payloads = _capture_candidate(ROOT)
        report = _validate_snapshot(before, validator_bytes)
        after, _, _ = _capture_candidate(ROOT)
        if before != after:
            return deny("CANDIDATE_CHANGED", "UNKNOWN")
        if report.get("offline_static_status") != "PASS" or report.get("payload_sha256") != expected_payloads:
            return deny("VALIDATOR_REJECTED", "FAIL")
    except Rejected as error:
        return deny(str(error), "UNKNOWN")
    except Exception:
        return deny("VALIDATOR_UNAVAILABLE", "UNKNOWN")
    # No user-supplied reference or boolean can establish the missing boundaries.
    # A real executor, subprocess, Ansible invocation, or staging system is absent.
    return deny("REAL_EXECUTION_BOUNDARIES_NOT_ESTABLISHED", "PASS")


def main():
    if len(sys.argv) != 1:
        result = {"decision": "DENY", "reason": "ARGUMENT_NOT_ALLOWLISTED",
                  "executor_calls": 0, "real_execution": "NOT_IMPLEMENTED"}
    else:
        result = evaluate(offline_request())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1  # Offline success never means that real execution is authorized.


if __name__ == "__main__":
    sys.exit(main())
