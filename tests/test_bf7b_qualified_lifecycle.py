"""B-F7b: the tenant-partitioned pack lifecycle is the only qualified composition (candidate 060, accepted Option 1).

Offline: every reference entrypoint that selects the lifecycle store defaults to the partitioned profile, and an explicit
request for the shared legacy ``pack_lifecycle`` store is refused before any database access or signing. The E/H/P
fixture hosts inherit the same default and reach the same refusal. With PostgreSQL: every provisioned schema is
partitioned, so no runtime login can read or write ``pack_lifecycle``; the recovered regulated composition, an alternate
route that still names the legacy ledger, fails closed at the database on its first read.
"""
import inspect
import os

import psycopg
import pytest

from assurance_reference.alerts import AlertJournal
from assurance_reference.durable_governance import DurableGovernedEducationPacks
from assurance_reference.host_runtime import compose_reference_stores
from assurance_reference.lifecycle_runtime import PartitionedActivationLedger
from assurance_reference.local_clinical_fixture import build_clinical_fixture
from assurance_reference.local_education_fixture import build_education_fixture
from assurance_reference.local_fixture_host import configuration
from assurance_reference.local_product_spec_fixture import build_product_spec_fixture
from assurance_reference.role_contract import ROLES
from regulated_core.signing import Ed25519Signer, TrustDirectory
from test_host_contract import NoIOPool
from test_partitioned_composition import arguments

REFUSAL = "legacy shared pack lifecycle is not a qualified multi-tenant composition"


@pytest.mark.parametrize("entry", [compose_reference_stores, DurableGovernedEducationPacks.__init__, configuration,
                                   build_clinical_fixture, build_education_fixture, build_product_spec_fixture])
def test_every_lifecycle_entrypoint_defaults_to_the_partitioned_profile(entry):
    assert inspect.signature(entry).parameters["partitioned_lifecycle"].default is True


def test_reference_stores_refuse_the_legacy_profile_before_any_io():
    roles, kwargs = arguments()
    with pytest.raises(ValueError, match=REFUSAL):
        compose_reference_stores(roles, **kwargs, partitioned_lifecycle=False)
    assert type(compose_reference_stores(roles, **kwargs).activation) is PartitionedActivationLedger


def test_governed_packs_refuse_the_legacy_profile_before_any_io():
    roles, kwargs = arguments()
    alerts = AlertJournal(NoIOPool("alerts"), Ed25519Signer("fixture:qualified-lifecycle"), TrustDirectory())
    with pytest.raises(ValueError, match=REFUSAL):
        DurableGovernedEducationPacks(pool=NoIOPool("governor"), clock=kwargs["clock"], alerts=alerts,
                                      partitioned_lifecycle=False)
    packs = DurableGovernedEducationPacks(pool=NoIOPool("governor"), clock=kwargs["clock"], alerts=alerts)
    assert type(packs.ledger) is PartitionedActivationLedger


def test_no_runtime_login_reaches_the_legacy_store_and_the_recovered_route_fails_closed():
    from assurance_reference.local_roles import provision_local_roles
    from regulated_core.runtime_pg import compose_regulated_stores

    roles = provision_local_roles(os.environ["FACTORY_TEST_DB_URL"])
    try:
        for kind in ROLES:
            with getattr(roles, kind).connection() as conn:
                for statement in ("SELECT 1 FROM pack_lifecycle LIMIT 0",
                                  "INSERT INTO pack_lifecycle VALUES ('x', 1, '{}'::jsonb, repeat('0', 64))"):
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        with conn.transaction():
                            conn.execute(statement)
        recovered = compose_regulated_stores(roles.receiver, evidence_signer=Ed25519Signer("fixture:recovered-route"),
                                             trust=TrustDirectory())
        with pytest.raises(Exception) as refused:
            recovered.activation.active("lumiwright.education.formative-feedback")
        assert "permission denied" in str(refused.value) or isinstance(refused.value, psycopg.errors.InsufficientPrivilege)
    finally:
        for kind in ROLES:
            getattr(roles, kind).close()
