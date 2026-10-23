"""Explicit local provisioning for append-only tenant epoch receipts.

Call only from host administration after the core schema exists, before runtime
role grants. Runtime construction never invokes this function. Existing tables
are preserved; this does not qualify or repair an arbitrary pre-existing schema.
"""
DDL = r"""
CREATE TABLE IF NOT EXISTS reference_epoch_withdrawal_receipts_v1 (
    tenant TEXT NOT NULL CHECK (length(tenant) > 0),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    operation TEXT NOT NULL CHECK (operation = 'governance:withdraw-tenant-epoch'),
    nonce TEXT NOT NULL CHECK (length(nonce) > 0),
    change_digest TEXT NOT NULL CHECK (change_digest ~ '^[0-9a-f]{64}$'),
    proof_digest TEXT NOT NULL CHECK (proof_digest ~ '^[0-9a-f]{64}$'),
    proof TEXT NOT NULL CHECK (length(proof) > 0),
    PRIMARY KEY (tenant, epoch),
    UNIQUE (tenant, operation, nonce),
    FOREIGN KEY (tenant, epoch) REFERENCES regulated_revocation_events_v1 (tenant, epoch)
);
CREATE OR REPLACE FUNCTION reference_epoch_receipt_no_mutation_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'epoch withdrawal receipts are append-only';
END $$;
ALTER TABLE reference_epoch_withdrawal_receipts_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE reference_epoch_withdrawal_receipts_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS reference_epoch_receipt_tenant_v1 ON reference_epoch_withdrawal_receipts_v1;
CREATE POLICY reference_epoch_receipt_tenant_v1 ON reference_epoch_withdrawal_receipts_v1
    USING (tenant = current_setting('app.tenant', true))
    WITH CHECK (tenant = current_setting('app.tenant', true));
DROP TRIGGER IF EXISTS reference_epoch_receipt_immutable_v1 ON reference_epoch_withdrawal_receipts_v1;
CREATE TRIGGER reference_epoch_receipt_immutable_v1 BEFORE UPDATE OR DELETE
    ON reference_epoch_withdrawal_receipts_v1 FOR EACH ROW
    EXECUTE FUNCTION reference_epoch_receipt_no_mutation_v1();
DROP TRIGGER IF EXISTS reference_epoch_receipt_no_truncate_v1 ON reference_epoch_withdrawal_receipts_v1;
CREATE TRIGGER reference_epoch_receipt_no_truncate_v1 BEFORE TRUNCATE
    ON reference_epoch_withdrawal_receipts_v1 FOR EACH STATEMENT
    EXECUTE FUNCTION reference_epoch_receipt_no_mutation_v1();
REVOKE ALL ON reference_epoch_withdrawal_receipts_v1 FROM PUBLIC;
"""


def provision_epoch_receipts(pool):
    """Execute explicit schema provisioning in one owned administrator transaction."""
    with pool.connection() as connection, connection.transaction():
        connection.execute(DDL)
