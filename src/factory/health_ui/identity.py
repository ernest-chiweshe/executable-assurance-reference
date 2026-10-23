"""Durable clinician identities and server-side sessions.

Admission to a paid workspace and authorship inside that workspace are separate
questions.  ``workspace.py`` answers the first.  This module answers the
second with password-backed identities, explicit workspace membership and
durable, revocable sessions.

Passwords and bearer session tokens are never stored.  Passwords use PBKDF2
with a per-user salt; tokens are represented by a SHA-256 digest.  The JSON
file is intentionally inspectable for recovery, but writes are atomic and a
malformed file fails closed instead of becoming an empty identity database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Protocol

_SCHEMA = 1
_PBKDF2_ITERATIONS = 600_000
_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._+@-]{2,127}$")


class IdentityStoreDegraded(RuntimeError):
    """The durable identity file cannot be trusted or safely rewritten."""


class SessionAdmissionRefused(ValueError):
    """The exact authenticated session is no longer current for this operation."""


@dataclass(frozen=True)
class ClinicianIdentity:
    """The authenticated person and the workspace in which they are acting."""

    user_id: str
    username: str
    display_name: str
    workspace_id: str
    # Server-side provenance; not a bearer credential or an identity attribute.
    session_reference: str = dataclass_field(default="", repr=False, compare=False)
    session_expires_at: float = dataclass_field(default=0.0, repr=False, compare=False)

    @property
    def owner_id(self) -> str:
        """Stable tenant-scoped key used for case ownership, never display."""

        return f"{self.workspace_id}:{self.user_id}"


@dataclass(frozen=True)
class PasswordResetIssue:
    """One short-lived reset secret; only its digest is persisted."""

    token: str
    expires_at: float


class ClinicianAuthenticator(Protocol):
    """Authentication seam consumed by the clinician HTTP application."""

    def authenticate(
        self, username: str, password: str, workspace_id: str
    ) -> ClinicianIdentity | None: ...

    def authenticate_external(self, binding_key: str) -> ClinicianIdentity | None:
        """Resolve a verified external human to a clinician, or None if unbound.

        Part of the contract rather than an optional extra, so an authenticator that
        cannot answer it fails type-check instead of failing open at a sign-in route.
        """
        ...

    def issue_session(self, identity: ClinicianIdentity, ttl_seconds: int) -> str: ...

    def resolve_session(self, token: str) -> ClinicianIdentity | None: ...

    def revoke_session(self, token: str) -> None: ...

    def active_member(self, user_id: str, workspace_id: str) -> ClinicianIdentity | None:
        """The clinician, only while their identity is active and a member of `workspace_id`, or None.

        Read at the instant of use, never cached: deactivating a clinician or removing a membership is seen by
        the next check. This is what a clinical approval's credential receipt attests (C4)."""
        ...

    def begin_password_reset(
        self, username: str, workspace_id: str, ttl_seconds: int
    ) -> PasswordResetIssue | None: ...

    def reset_password(self, token: str, new_password: str) -> bool: ...

    def provision_customer_membership(
        self, customer_key_id: str, display_name: str, email: str, workspace_id: str,
    ) -> ClinicianIdentity:
        """Idempotently adapt an already-authorised common invitation to Health."""
        ...


def _normalise_username(value: str) -> str:
    return value.strip().casefold()


def _password_digest(password: str, salt: bytes, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    ).hex()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class IdentityStore:
    """One fail-closed JSON identity store for a single application process."""

    def __init__(
        self, path: Path, *, clock: Callable[[], float] = time.time
    ) -> None:
        self._path = path
        self._password_resets_path = path.with_name("password-resets.json")
        # External identities live in their own file for the same reason password
        # resets do, and for one more: the identity store validates its root with an
        # exact key set and raises IdentityStoreDegraded on anything unexpected. Adding
        # a key there would make every clinician file written before this change fail
        # its integrity check on the next start -- which fails CLOSED, so the doctors
        # currently signed in would be locked out by an additive feature.
        self._external_identities_path = path.with_name("external-identities.json")
        self._clock = clock
        self._lock = threading.RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data = self._empty()
        self._load()

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "users": [],
            "sessions": {},
        }

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._validate(raw)
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityStoreDegraded(
                "The clinician identity store failed an integrity check. "
                "Its original file is preserved; sign-in and bootstrap are stopped."
            ) from exc
        self._data = raw

    @staticmethod
    def _validate(raw: Any) -> None:
        if not isinstance(raw, dict) or set(raw) != {
            "schema", "users", "sessions",
        }:
            raise ValueError("invalid identity store root")
        if raw["schema"] != _SCHEMA:
            raise ValueError("unsupported identity store schema")
        if not isinstance(raw["users"], list) or not isinstance(raw["sessions"], dict):
            raise TypeError("invalid identity collections")
        usernames: set[str] = set()
        user_ids: set[str] = set()
        memberships: dict[str, set[str]] = {}
        for user in raw["users"]:
            required = {
                "user_id", "username", "display_name", "salt", "password_hash",
                "iterations", "workspaces", "active",
            }
            if not isinstance(user, dict) or set(user) != required:
                raise ValueError("invalid clinician identity")
            username = user["username"]
            if not isinstance(username, str) or not _USERNAME.fullmatch(username):
                raise ValueError("invalid clinician username")
            if username in usernames or user["user_id"] in user_ids:
                raise ValueError("duplicate clinician identity")
            user_id = user["user_id"]
            if (not isinstance(user_id, str) or len(user_id) != 32
                    or any(ch not in "0123456789abcdef" for ch in user_id)):
                raise ValueError("invalid clinician user id")
            usernames.add(username)
            user_ids.add(user_id)
            if not isinstance(user["display_name"], str) or not user["display_name"].strip():
                raise ValueError("invalid clinician display name")
            if not isinstance(user["iterations"], int) or user["iterations"] < 100_000:
                raise ValueError("weak clinician password record")
            if not isinstance(user["workspaces"], list) or not user["workspaces"]:
                raise ValueError("clinician has no workspace membership")
            if any(not isinstance(item, str) or not item for item in user["workspaces"]):
                raise ValueError("invalid clinician workspace membership")
            memberships[user_id] = set(user["workspaces"])
            if type(user["active"]) is not bool:
                raise ValueError("invalid clinician active state")
            for field in ("salt", "password_hash"):
                value = user[field]
                if (not isinstance(value, str) or len(value) != 64
                        or any(ch not in "0123456789abcdef" for ch in value)):
                    raise ValueError(f"invalid clinician {field}")
        for digest, session in raw["sessions"].items():
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)
                    or not isinstance(session, dict)
                    or set(session) != {"user_id", "workspace_id", "issued_at", "expires_at"}
                    or session["user_id"] not in user_ids
                    or not isinstance(session["workspace_id"], str)
                    or not isinstance(session["issued_at"], (int, float))
                    or not isinstance(session["expires_at"], (int, float))
                    or not math.isfinite(session["issued_at"])
                    or not math.isfinite(session["expires_at"])
                    or session["workspace_id"] not in memberships[session["user_id"]]
                    or session["expires_at"] <= session["issued_at"]):
                raise ValueError("invalid clinician session")
    def _flush(self, data: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, indent=1, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path)
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise IdentityStoreDegraded(
                "The clinician identity store could not be written; no sign-in "
                "state was changed."
            ) from exc

    def _load_password_resets(self) -> dict[str, Any]:
        if not self._password_resets_path.exists():
            return {"schema": 1, "resets": {}}
        try:
            raw = json.loads(
                self._password_resets_path.read_text(encoding="utf-8")
            )
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema", "resets"}
                or raw["schema"] != 1
                or not isinstance(raw["resets"], dict)
            ):
                raise ValueError("invalid password reset store")
            user_ids = {user["user_id"] for user in self._data["users"]}
            for digest, reset in raw["resets"].items():
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)
                    or not isinstance(reset, dict)
                    or set(reset) != {
                        "user_id", "workspace_id", "issued_at", "expires_at",
                        "password_hash_at_issue",
                    }
                    or reset["user_id"] not in user_ids
                    or not isinstance(reset["workspace_id"], str)
                    or not isinstance(reset["issued_at"], (int, float))
                    or not isinstance(reset["expires_at"], (int, float))
                    or not math.isfinite(reset["issued_at"])
                    or not math.isfinite(reset["expires_at"])
                    or reset["expires_at"] <= reset["issued_at"]
                    or not isinstance(reset["password_hash_at_issue"], str)
                    or len(reset["password_hash_at_issue"]) != 64
                    or any(
                        ch not in "0123456789abcdef"
                        for ch in reset["password_hash_at_issue"]
                    )
                ):
                    raise ValueError("invalid clinician password reset")
            return raw
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityStoreDegraded(
                "The clinician password-reset store failed an integrity check."
            ) from exc

    def _flush_password_resets(self, data: dict[str, Any]) -> None:
        tmp = self._password_resets_path.with_suffix(".json.tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, indent=1, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._password_resets_path)
            try:
                os.chmod(self._password_resets_path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise IdentityStoreDegraded(
                "The clinician password-reset store could not be written."
            ) from exc

    def _load_external_identities(self) -> dict[str, Any]:
        """Read the external-identity bindings, or an empty store, failing closed.

        Validation is deliberately as strict as the password-reset store's: a binding
        decides who may sign in as a clinician, so a malformed file must stop sign-in
        rather than be repaired silently into something permissive.
        """
        if not self._external_identities_path.exists():
            return {"schema": 1, "bindings": {}}
        try:
            raw = json.loads(self._external_identities_path.read_text(encoding="utf-8"))
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema", "bindings"}
                or raw["schema"] != 1
                or not isinstance(raw["bindings"], dict)
            ):
                raise ValueError("invalid external identity store")
            user_ids = {user["user_id"] for user in self._data["users"]}
            for key, binding in raw["bindings"].items():
                if (
                    not isinstance(key, str)
                    or not key
                    or not isinstance(binding, dict)
                    or set(binding) != {"user_id", "workspace_id", "email", "bound_at"}
                    # A binding naming a clinician who no longer exists must not resolve.
                    or binding["user_id"] not in user_ids
                    or not isinstance(binding["workspace_id"], str)
                    or not binding["workspace_id"]
                    or not isinstance(binding["email"], str)
                    or not isinstance(binding["bound_at"], (int, float))
                    or not math.isfinite(binding["bound_at"])
                ):
                    raise ValueError("invalid external identity binding")
            return raw
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityStoreDegraded(
                "The clinician external-identity store failed an integrity check."
            ) from exc

    def _flush_external_identities(self, data: dict[str, Any]) -> None:
        tmp = self._external_identities_path.with_suffix(".json.tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(data, handle, indent=1, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._external_identities_path)
            try:
                os.chmod(self._external_identities_path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise IdentityStoreDegraded(
                "The clinician external-identity store could not be written."
            ) from exc

    def bind_external_identity(
        self, binding_key: str, username: str, workspace_id: str, *, email: str = "",
    ) -> ClinicianIdentity | None:
        """Let a verified external human sign in as an existing clinician.

        Operator-authorised, never exposed as an API — the same boundary
        `bootstrap_user` keeps. The clinician account must already exist and already
        hold the workspace: this grants a second way to prove who you are, never a new
        membership and never a new person.

        Re-binding the same key to a different clinician is refused. Silently moving it
        would let one mis-issued binding hand a clinical workspace to the wrong doctor,
        and every document they sign afterwards would carry the wrong name.
        """
        normal = _normalise_username(username)
        if not binding_key.strip() or not normal or not workspace_id.strip():
            raise ValueError("external identity binding requires key, username, workspace")
        with self._lock:
            user = next(
                (item for item in self._data["users"] if item["username"] == normal),
                None,
            )
            if user is None or not user["active"]:
                return None
            if workspace_id not in user["workspaces"]:
                return None
            data = self._load_external_identities()
            existing = data["bindings"].get(binding_key)
            if existing is not None and existing["user_id"] != user["user_id"]:
                raise ValueError(
                    "that external identity is already bound to another clinician"
                )
            data["bindings"][binding_key] = {
                "user_id": user["user_id"],
                "workspace_id": workspace_id,
                "email": email,
                "bound_at": self._clock(),
            }
            self._flush_external_identities(data)
            return ClinicianIdentity(
                user["user_id"], user["username"], user["display_name"], workspace_id
            )

    def authenticate_external(self, binding_key: str) -> ClinicianIdentity | None:
        """Resolve a verified external human to a clinician, or refuse.

        Returning None for an unbound key is the no-auto-provisioning rule in the
        clinical setting: a valid Google account is not a clinician, and nothing here
        can make it one.
        """
        if not binding_key.strip():
            return None
        with self._lock:
            binding = self._load_external_identities()["bindings"].get(binding_key)
            if binding is None:
                return None
            user = next(
                (item for item in self._data["users"]
                 if item["user_id"] == binding["user_id"]),
                None,
            )
            # Deactivation and workspace removal must end external sign-in exactly as
            # they end password sign-in; the binding is not a second source of truth.
            if user is None or not user["active"]:
                return None
            workspace_id = str(binding["workspace_id"])
            if workspace_id not in user["workspaces"]:
                return None
            return ClinicianIdentity(
                user["user_id"], user["username"], user["display_name"], workspace_id
            )

    def bootstrap_user(
        self,
        username: str,
        display_name: str,
        password: str,
        workspace_ids: Iterable[str],
    ) -> ClinicianIdentity:
        """Create one operator-authorised identity; never exposed as an API."""

        normal = _normalise_username(username)
        display = display_name.strip()
        workspaces = sorted({item.strip() for item in workspace_ids if item.strip()})
        if not _USERNAME.fullmatch(normal):
            raise ValueError("username must be 3-128 simple lowercase characters")
        if not display:
            raise ValueError("display name is required")
        if not 12 <= len(password) <= 1024:
            raise ValueError("password must contain 12-1024 characters")
        if not workspaces:
            raise ValueError("at least one workspace membership is required")
        with self._lock:
            if any(user["username"] == normal for user in self._data["users"]):
                raise ValueError("that clinician username already exists")
            salt = secrets.token_bytes(32)
            user_id = uuid.uuid4().hex
            candidate = json.loads(json.dumps(self._data))
            candidate["users"].append({
                "user_id": user_id,
                "username": normal,
                "display_name": display,
                "salt": salt.hex(),
                "password_hash": _password_digest(
                    password, salt, _PBKDF2_ITERATIONS
                ),
                "iterations": _PBKDF2_ITERATIONS,
                "workspaces": workspaces,
                "active": True,
            })
            self._flush(candidate)
            self._data = candidate
        return ClinicianIdentity(user_id, normal, display, workspaces[0])

    def provision_customer_membership(
        self, customer_key_id: str, display_name: str, email: str, workspace_id: str,
    ) -> ClinicianIdentity:
        """Create/bind Health authorship from the common entitlement authority.

        The generated password is deliberately unrevealed: this account is entered by
        the one-use Hub handoff, and password recovery remains an explicit later choice.
        """
        if not customer_key_id.strip() or not workspace_id.strip():
            raise ValueError("customer membership requires key and workspace")
        username = "clinician-" + hashlib.sha256(customer_key_id.encode("utf-8")).hexdigest()[:16]
        with self._lock:
            user = next((item for item in self._data["users"] if item["username"] == username), None)
            if user is None:
                return self.bootstrap_user(
                    username, display_name.strip() or email.strip() or "Clinician",
                    secrets.token_urlsafe(48), (workspace_id,),
                )
            if workspace_id not in user["workspaces"]:
                user["workspaces"].append(workspace_id)
                user["workspaces"].sort()
                self._flush(self._data)
            return ClinicianIdentity(
                user["user_id"], user["username"], user["display_name"], workspace_id,
            )

    def authenticate(
        self, username: str, password: str, workspace_id: str
    ) -> ClinicianIdentity | None:
        normal = _normalise_username(username)
        if not normal or not password or len(password) > 1024 or not workspace_id:
            return None
        with self._lock:
            user = next(
                (item for item in self._data["users"] if item["username"] == normal),
                None,
            )
            if user is None:
                # Do equivalent PBKDF2 work so unknown usernames are not a cheap
                # timing oracle for the clinician directory.
                _password_digest(password, bytes(32), _PBKDF2_ITERATIONS)
                return None
            actual = _password_digest(
                password, bytes.fromhex(user["salt"]), user["iterations"]
            )
            if (not user["active"]
                    or workspace_id not in user["workspaces"]
                    or not hmac.compare_digest(actual, user["password_hash"])):
                return None
            return ClinicianIdentity(
                user["user_id"], user["username"], user["display_name"], workspace_id
            )

    def issue_session(self, identity: ClinicianIdentity, ttl_seconds: int) -> str:
        if ttl_seconds <= 0:
            raise ValueError("session lifetime must be positive")
        token = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            candidate = json.loads(json.dumps(self._data))
            sessions = candidate["sessions"]
            for digest, entry in tuple(sessions.items()):
                if now >= entry["expires_at"]:
                    sessions.pop(digest, None)
            sessions[_token_digest(token)] = {
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "issued_at": now,
                "expires_at": now + ttl_seconds,
            }
            self._flush(candidate)
            self._data = candidate
        return token

    def resolve_session(self, token: str) -> ClinicianIdentity | None:
        if not token:
            return None
        digest = _token_digest(token)
        now = self._clock()
        with self._lock:
            session = self._data["sessions"].get(digest)
            if session is None:
                return None
            if now >= session["expires_at"]:
                candidate = json.loads(json.dumps(self._data))
                candidate["sessions"].pop(digest, None)
                self._flush(candidate)
                self._data = candidate
                return None
            user = next(
                (item for item in self._data["users"]
                 if item["user_id"] == session["user_id"]),
                None,
            )
            if (user is None or not user["active"]
                    or session["workspace_id"] not in user["workspaces"]):
                return None
            return ClinicianIdentity(
                user["user_id"], user["username"], user["display_name"],
                session["workspace_id"],
            )

    def active_member(self, user_id: str, workspace_id: str) -> ClinicianIdentity | None:
        """The clinician, only while their identity is active and a member of `workspace_id`, or None.

        Read at the instant of use, never cached: deactivating a clinician or removing a membership is seen by
        the next check. This is what a clinical approval's credential receipt attests (C4)."""
        with self._lock:
            user = next((item for item in self._data["users"] if item["user_id"] == user_id), None)
            if user is None or user["active"] is not True or workspace_id not in user["workspaces"]:
                return None
            return ClinicianIdentity(user["user_id"], user["username"], user["display_name"], workspace_id)

    def revoke_session(self, token: str) -> None:
        if not token:
            return
        digest = _token_digest(token)
        with self._lock:
            if digest not in self._data["sessions"]:
                return
            candidate = json.loads(json.dumps(self._data))
            candidate["sessions"].pop(digest, None)
            self._flush(candidate)
            self._data = candidate

    def begin_password_reset(
        self, username: str, workspace_id: str, ttl_seconds: int
    ) -> PasswordResetIssue | None:
        """Issue one operator-delivered reset secret for an exact membership."""

        normal = _normalise_username(username)
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            raise ValueError("password reset lifetime must be 1-3600 seconds")
        if not normal or not workspace_id:
            return None
        now = self._clock()
        with self._lock:
            user = next(
                (item for item in self._data["users"] if item["username"] == normal),
                None,
            )
            if (
                user is None
                or not user["active"]
                or workspace_id not in user["workspaces"]
            ):
                # Keep an unknown account from becoming a cheap timing oracle.
                _password_digest("password-reset", bytes(32), _PBKDF2_ITERATIONS)
                return None

            token = secrets.token_urlsafe(32)
            digest = _token_digest(token)
            candidate = self._load_password_resets()
            resets = candidate["resets"]
            for old_digest, entry in tuple(resets.items()):
                if now >= entry["expires_at"] or entry["user_id"] == user["user_id"]:
                    resets.pop(old_digest, None)
            resets[digest] = {
                "user_id": user["user_id"],
                "workspace_id": workspace_id,
                "issued_at": now,
                "expires_at": now + ttl_seconds,
                "password_hash_at_issue": user["password_hash"],
            }
            self._flush_password_resets(candidate)
        return PasswordResetIssue(token, now + ttl_seconds)

    def reset_password(self, token: str, new_password: str) -> bool:
        """Consume one reset secret, replace the password and revoke sessions."""

        if not token or len(token) > 1024:
            return False
        if not 12 <= len(new_password) <= 1024:
            raise ValueError("password must contain 12-1024 characters")
        digest = _token_digest(token)
        now = self._clock()
        with self._lock:
            reset_data = self._load_password_resets()
            reset = reset_data["resets"].get(digest)
            if reset is None or now >= reset["expires_at"]:
                for old_digest, entry in tuple(reset_data["resets"].items()):
                    if now >= entry["expires_at"]:
                        reset_data["resets"].pop(old_digest, None)
                self._flush_password_resets(reset_data)
                return False

            candidate = json.loads(json.dumps(self._data))
            user = next((
                item for item in candidate["users"]
                if item["user_id"] == reset["user_id"]
            ), None)
            if (
                user is None
                or not user["active"]
                or reset["workspace_id"] not in user["workspaces"]
                or not hmac.compare_digest(
                    user["password_hash"], reset["password_hash_at_issue"]
                )
            ):
                reset_data["resets"].pop(digest, None)
                self._flush_password_resets(reset_data)
                return False
            salt = secrets.token_bytes(32)
            user["salt"] = salt.hex()
            user["password_hash"] = _password_digest(
                new_password, salt, _PBKDF2_ITERATIONS
            )
            user["iterations"] = _PBKDF2_ITERATIONS
            candidate["sessions"] = {
                session_digest: session
                for session_digest, session in candidate["sessions"].items()
                if session["user_id"] != user["user_id"]
            }
            reset_data["resets"] = {
                reset_digest: entry
                for reset_digest, entry in reset_data["resets"].items()
                if entry["user_id"] != user["user_id"]
            }
            self._flush(candidate)
            self._data = candidate
            self._flush_password_resets(reset_data)
        return True


class LegacyTestAuthenticator:
    """Explicit test-only adapter for historical clinical-behaviour tests."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._sessions: dict[str, tuple[ClinicianIdentity, float]] = {}
        self._members: dict[tuple[str, str], ClinicianIdentity] = {}
        self._inactive: set[str] = set()

    def authenticate(
        self, username: str, password: str, workspace_id: str
    ) -> ClinicianIdentity | None:
        display = username.strip()
        if not display:
            return None
        stable = hashlib.sha256(
            f"{workspace_id}\0{display.casefold()}".encode("utf-8")
        ).hexdigest()[:32]
        return ClinicianIdentity(stable, display.casefold(), display, workspace_id)

    def authenticate_external(self, binding_key: str) -> ClinicianIdentity | None:
        """Always unbound.

        This adapter exists to keep historical clinical-behaviour tests meaningful, and
        those tests predate external identity entirely. Refusing is both the honest
        answer and the safe default: a test double must never be the thing that admits
        a clinician.
        """
        return None

    def provision_customer_membership(
        self, customer_key_id: str, display_name: str, email: str, workspace_id: str,
    ) -> ClinicianIdentity:
        """Test-only semantic twin of the governed Health membership adapter.

        The common invitation authority has already admitted the customer before this
        seam is called. Keep the identity stable across repeated handoffs, as both real
        stores do, without introducing persistence into historical behaviour tests.
        """
        if not customer_key_id.strip() or not workspace_id.strip():
            raise ValueError("customer membership requires key and workspace")
        username = "clinician-" + hashlib.sha256(
            customer_key_id.encode("utf-8")
        ).hexdigest()[:16]
        user_id = hashlib.sha256(
            ("health:" + customer_key_id).encode("utf-8")
        ).hexdigest()[:32]
        display = display_name.strip() or email.strip() or "Clinician"
        return ClinicianIdentity(user_id, username, display, workspace_id)

    def issue_session(self, identity: ClinicianIdentity, ttl_seconds: int) -> str:
        token = secrets.token_urlsafe(16)
        now = self._clock()
        self._sessions[token] = (identity, now + ttl_seconds)
        self._members[(identity.user_id, identity.workspace_id)] = identity
        return token

    def active_member(self, user_id: str, workspace_id: str) -> ClinicianIdentity | None:
        """Test twin: a clinician who has signed in here is a member until `deactivate` is called."""
        if user_id in self._inactive:
            return None
        return self._members.get((user_id, workspace_id))

    def deactivate(self, user_id: str) -> None:
        """Test-only: withdraw a clinician, as an operator deactivating an identity would."""
        self._inactive.add(user_id)

    def resolve_session(self, token: str) -> ClinicianIdentity | None:
        entry = self._sessions.get(token)
        if entry is None:
            return None
        identity, expires_at = entry
        if self._clock() >= expires_at:
            self._sessions.pop(token, None)
            return None
        return identity

    def revoke_session(self, token: str) -> None:
        self._sessions.pop(token, None)

    def begin_password_reset(
        self, username: str, workspace_id: str, ttl_seconds: int
    ) -> PasswordResetIssue | None:
        return None

    def reset_password(self, token: str, new_password: str) -> bool:
        return False
