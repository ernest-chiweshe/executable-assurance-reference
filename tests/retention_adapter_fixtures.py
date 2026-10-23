"""Synthetic versioned storage responses; no provider client or credentials."""

from datetime import timedelta
from io import BytesIO
import sys

import pytest


@pytest.fixture(autouse=True)
def no_provider_sdks(monkeypatch):
    # Fail any accidental lazy SDK import before it can construct a client.
    monkeypatch.setitem(sys.modules, "boto3", None)
    monkeypatch.setitem(sys.modules, "pkcs11", None)


class RetentionResponses:
    """The fake returns stored observations, independently of requested values."""

    def __init__(self):
        self.fault = None
        self.objects = {}
        self.latest = {}
        self.calls = []
        self.versioning = self.object_lock = "Enabled"

    def get_bucket_versioning(self, **request):
        return {"Status": self.versioning}

    def get_object_lock_configuration(self, **request):
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": self.object_lock}}

    def put_object(self, **request):
        self.calls.append(("put", request.copy()))
        if self.fault == "unavailable":
            raise OSError("synthetic storage unavailable")
        version = "fixture-version-" + str(len(self.objects) + 1)
        retention = {"Mode": request["ObjectLockMode"],
                     "RetainUntilDate": request["ObjectLockRetainUntilDate"]}
        if self.fault == "mode":
            retention["Mode"] = "GOVERNANCE"
        if self.fault == "short":
            retention["RetainUntilDate"] -= timedelta(microseconds=1)
        body = b"synthetic different bytes" if self.fault == "bytes" else request["Body"]
        self.objects[(request["Key"], version)] = (body, retention)
        self.latest[request["Key"]] = version
        return {} if self.fault == "version" else {"VersionId": version}

    def get_object_retention(self, **request):
        self.calls.append(("retention", request.copy()))
        if self.fault == "missing-retention":
            raise KeyError("synthetic missing retention metadata")
        return {"Retention": self.objects[(request["Key"], request["VersionId"])][1]}

    def get_object(self, **request):
        self.calls.append(("read", request.copy()))
        version = request.get("VersionId", self.latest.get(request["Key"]))
        return {"Body": BytesIO(self.objects[(request["Key"], version)][0])}
