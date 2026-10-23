"""Host-injected fixture faults; every normal authority guard remains installed."""

from contextlib import contextmanager
import time

from assurance_reference.local_sessions import LocalSessions
from assurance_reference.session_credentials import SessionUnavailable
from regulated_core.clock import ClockError
from regulated_core.worm import WormUnavailable
from regulated_core.kms import KmsUnavailable
from regulated_core.signing import Ed25519Signer


class FaultSigner:
    """Local protocol driver: fail signing, never return a forged signature.

    The exception models the signer's unavailable contract. Custody remains
    dev-local; this fixture never calls or claims an external KMS/HSM.
    """

    def __init__(self, key_id):
        self.delegate = Ed25519Signer(key_id)
        self.key_id, self.alg, self.kind = key_id, self.delegate.alg, self.delegate.kind
        self.unavailable = False
        self.failed_calls = 0

    @property
    def public_key_bytes(self):
        return self.delegate.public_key_bytes

    def _check(self):
        if self.unavailable:
            self.failed_calls += 1
            raise KmsUnavailable("fictional local signer service unavailable")

    def sign(self, payload):
        self._check()
        return self.delegate.sign(payload)

    def sign_bytes(self, data):
        self._check()
        return self.delegate.sign_bytes(data)


class FaultClock:
    """Report unavailable/uncertain authority time; never manufacture a reading."""

    def __init__(self, source):
        self.source, self.domain = source, source.domain
        self.fault = None

    def _check(self):
        if self.fault == "unavailable":
            raise ClockError("fixture trusted-time source unavailable")
        if self.fault == "uncertain":
            raise ClockError("fixture clock uncertainty exceeds its configured bound")

    def read(self):
        self._check()
        return self.source.read()

    def read_on(self, connection):
        self._check()
        return self.source.read_on(connection)

    def now_us(self):
        return self.read().now_us


class FaultRetention:
    def __init__(self, store):
        self.store = store
        self.unavailable = False

    def anchor(self, *args, **kwargs):
        if self.unavailable:
            raise WormUnavailable("fixture retention service unavailable")
        return self.store.anchor(*args, **kwargs)

    def fetch(self, *args, **kwargs):
        return self.store.fetch(*args, **kwargs)

    def verify(self, *args, **kwargs):
        return self.store.verify(*args, **kwargs)


class AcknowledgementSessions(LocalSessions):
    lose_exit_acknowledgement = False
    acknowledgement_deadline_us = None
    acknowledgement_wait_seconds = 12

    @contextmanager
    def admit(self, *args, **kwargs):
        with super().admit(*args, **kwargs) as current:
            yield current
        if self.lose_exit_acknowledgement:
            self.lose_exit_acknowledgement = False
            if self.acknowledgement_deadline_us is not None:
                # The lawful effect and its transaction have already finished.
                # Delay only delivery of the acknowledgement, never a guard or write.
                timeout = time.monotonic() + self.acknowledgement_wait_seconds
                while self.clock.now_us() < self.acknowledgement_deadline_us:
                    if time.monotonic() >= timeout:
                        raise AssertionError("fixture acknowledgement wait exceeded its bound")
                    time.sleep(0.05)
            raise SessionUnavailable("fixture admission-close acknowledgement lost after transaction completion")
