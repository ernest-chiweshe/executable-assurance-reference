"""Fresh opt-in reviewed root-admission role composition on the prepared profile.

Owner credential is used only to provision. Existing profiles and schemas are
never migrated by this entry point. The trusted host retains signer custody.
"""
from psycopg import sql
from assurance_reference.local_roles import LocalPool
from assurance_reference.local_prepared_roles import provision_local_prepared_roles, LocalPreparedRoles

_ROOT_READS=(
    'regulated_decision_evidence_v1','regulated_decision_inputs_v1',
    'regulated_evidence_checkpoints_v1','regulated_reviews_v1',
    'regulated_revocation_events_v1','regulated_root_admissions_v1',
)

def provision_local_root_roles(dsn: str) -> LocalPreparedRoles:
    roles=provision_local_prepared_roles(dsn)
    owner=LocalPool(dsn,roles.schema,'migration-owner')
    try:
        with owner.connection() as conn,conn.transaction():
            for table in _ROOT_READS:
                conn.execute(sql.SQL('GRANT SELECT ON {} TO {}').format(
                    sql.Identifier(table),sql.Identifier(roles.delegation_issuer.role)))
            conn.execute(sql.SQL('GRANT INSERT ON regulated_root_admissions_v1 TO {}').format(
                sql.Identifier(roles.delegation_issuer.role)))
        return roles
    finally:
        owner.close()
