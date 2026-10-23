"""Verify an explicitly pinned source diff without importing recovered code.

This proves a byte relationship, never approval, parity or implementation quality.
The ordinary source trace remains strict unless both opt-in arguments are supplied.
"""

import difflib
import hashlib
import json
from pathlib import PurePosixPath

from _scope_report import confined_file, sha
from recover_authority_sources import COMMIT, TREE


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def load_adaptations(root, manifest_path, expected_sha256, *, layout):
    if manifest_path is None and expected_sha256 is None:
        return {}, None
    if not manifest_path or not expected_sha256:
        raise ValueError("Adaptations require an explicit manifest and expected SHA256")
    if layout != "reference":
        raise ValueError("Explicit adaptations currently require reference layout")
    raw = confined_file(root, manifest_path).read_bytes()
    if sha(raw) != expected_sha256:
        raise ValueError("Adaptation manifest hash differs from explicit pin")
    manifest = json.loads(raw)
    schema = manifest.get("schema")
    if (schema not in {"reference/explicit-source-adaptations/v1",
                       "reference/explicit-source-adaptations/v2"}
            or manifest.get("source_commit") != COMMIT or manifest.get("source_tree") != TREE):
        raise ValueError("Adaptation schema or original source pin differs")
    sanitized = schema == "reference/explicit-source-adaptations/v2"
    if sanitized:
        note = manifest.get("sanitization", {})
        if (note.get("kind") != "attribution-only-public-derivative"
                or note.get("upstream_byte_identity_verified_by_this_manifest") is not False
                or not note.get("scope")
                or any(not isinstance(note.get(key), str)
                       or len(note[key]) != 64
                       or any(char not in "0123456789abcdef" for char in note[key])
                       for key in ("baseline_archive_sha256", "baseline_manifest_sha256",
                                   "baseline_patch_sha256"))):
            raise ValueError("Sanitized provenance requires explicit historical pins and limits")
    elif "sanitization" in manifest:
        raise ValueError("Sanitized provenance requires the explicit v2 schema")
    patch = confined_file(root, manifest["patch_path"]).read_bytes()
    if sha(patch) != manifest["patch_sha256"]:
        raise ValueError("Adaptation patch hash differs")
    if not manifest.get("files"):
        raise ValueError("Adaptation must identify explicit files")
    reconstructed, recovered, seen = [], {}, set()
    for item in manifest["files"]:
        source, path, original_path = item["source_path"], item["path"], item["original_path"]
        paths = (source, path, original_path)
        if any(not isinstance(name, str) or not name or "\\" in name or ":" in name
               or "\n" in name or "\r" in name or ".." in PurePosixPath(name).parts
               or str(PurePosixPath(name)) != name for name in paths):
            raise ValueError("Adaptation paths must be canonical relative POSIX paths")
        if len({name.casefold() for name in paths}) != 3 or any(name.casefold() in seen for name in paths):
            raise ValueError("Duplicate or overlapping adaptation paths")
        seen.update(name.casefold() for name in paths)
        # Source names are patch labels; apply the same confinement rule as files.
        confined_file(root, source)
        original = confined_file(root, original_path).read_bytes()
        actual = confined_file(root, path).read_bytes()
        retained = item.get("retained_original")
        if retained is not None:
            if (not sanitized or not isinstance(retained, dict)
                    or retained.get("kind") != "attribution-sanitized-copy"
                    or set(retained) != {"kind", "sha256", "git_blob"}):
                raise ValueError("Sanitized original requires explicit v2 classification")
            if (sha(original) != retained["sha256"]
                    or git_blob(original) != retained["git_blob"]
                    or retained["sha256"] == item["original_sha256"]):
                raise ValueError("Sanitized original bytes differ from adaptation provenance")
        elif sha(original) != item["original_sha256"] or git_blob(original) != item["original_git_blob"]:
            raise ValueError("Retained original bytes differ from adaptation provenance")
        if sha(actual) != item["adapted_sha256"] or original == actual:
            raise ValueError("Adapted source bytes differ or contain no adaptation")
        reconstructed.extend(difflib.unified_diff(
            original.decode("utf-8").splitlines(keepends=True),
            actual.decode("utf-8").splitlines(keepends=True),
            fromfile="a/" + source, tofile="b/" + source))
        is_recovered = item.get("recovered_source")
        if type(is_recovered) is not bool:
            raise ValueError("Adaptation requires explicit recovered-source classification")
        if is_recovered:
            if path != "src/" + source:
                raise ValueError("Recovered adaptation path differs from original source layout")
            recovered[path] = {**item, "manifest_sha256": expected_sha256,
                               "approval_verified": False}
    if "".join(reconstructed).encode("utf-8") != patch:
        raise ValueError("Adapted files do not reconstruct the exact pinned patch")
    return recovered, {"path": manifest_path, "sha256": expected_sha256,
                       "patch_path": manifest["patch_path"], "patch_sha256": sha(patch),
                       "file_count": len(manifest["files"]), "approval_verified": False,
                       "sanitized_retained_copies": sanitized,
                       "upstream_byte_identity_verified": not sanitized,
                       "sanitization": manifest.get("sanitization")}
