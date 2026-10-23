"""Exercise the recovered KMS seam with in-process local mock custody only."""

from regulated_core.kms import KmsSigner, KmsUnavailable, LocalKmsBackend


class ObservedLocalKmsBackend(LocalKmsBackend):
    def __init__(self, key_reference):
        super().__init__(key_reference)
        self.failed_calls = 0
        self.available = True

    def set_available(self, available):
        super().set_available(available)
        self.available = available

    def sign(self, payload):
        try:
            return super().sign(payload)
        except KmsUnavailable:
            self.failed_calls += 1
            raise


class LocalKmsFixtureSigner(KmsSigner):
    """Only expose the existing mock outage switch to shared contract tests.

    Signing and canonical/byte handling remain the original KmsSigner methods.
    Its kms-external kind denotes the seam; custody.provider is local-mock and
    the private key remains in this process. No real HSM/KMS claim is made.
    """

    def __init__(self, key_id):
        self.backend = ObservedLocalKmsBackend("local-fixture:" + key_id)
        super().__init__(key_id, self.backend, self.backend.custody)

    @property
    def failed_calls(self):
        return self.backend.failed_calls

    @property
    def unavailable(self):
        return not self.backend.available

    @unavailable.setter
    def unavailable(self, unavailable):
        self.backend.set_available(not unavailable)
