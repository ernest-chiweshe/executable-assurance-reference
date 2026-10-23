"""Phase 1 PostgreSQL evidence storage primitives; not wired to callers.

The core service appends through the unchanged recorder inside one savepoint,
then stages authenticated indexes and a freshly signed head in that same outer
transaction. It neither commits the caller transaction nor publishes protected
heads, retains evidence, grants permits, opens a pool or changes role grants.
Caller migration and pre-permit activation remain separate gated work.
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from .evidence_map import EMPTY, MapProof, MapNode, MemorySparseMap, node_digest, verify_map_proof
from .evidence_service import EvidenceError, KeySummary, UnhashableIdFlag, unhashable_id_key
from .merkle import EMPTY_ROOT
from .evidence_key_policy import valid_policy, copy_retirements
from .evidence_encoding import check_numeric_domain

PG_MAX = (1 << 63) - 1
MAP_SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_evidence_map_v2 (
 tenant TEXT NOT NULL, hash BYTEA NOT NULL CHECK(octet_length(hash)=32),
 kind TEXT NOT NULL CHECK(kind IN ('node','leaf')),
 left_hash BYTEA, right_hash BYTEA, leaf_key BYTEA, value BYTEA,
 CHECK((kind='node' AND left_hash IS NOT NULL AND right_hash IS NOT NULL AND octet_length(left_hash)=32 AND octet_length(right_hash)=32
        AND leaf_key IS NULL AND value IS NULL)
    OR (kind='leaf' AND left_hash IS NULL AND right_hash IS NULL
        AND leaf_key IS NOT NULL AND octet_length(leaf_key)=32 AND value IS NOT NULL AND octet_length(value)<=512)),
 PRIMARY KEY(tenant,hash));
CREATE TABLE IF NOT EXISTS regulated_evidence_keys_v1 (
 tenant TEXT NOT NULL, key_digest BYTEA NOT NULL CHECK(octet_length(key_digest)=32),
 key_type TEXT NOT NULL CHECK(key_type IN ('record_id','record_hash','record_id_hash','outcome_of','release_decision_eligible','release_outcome_eligible','flag')),
 tree_size BIGINT NOT NULL CHECK(tree_size>0),
 count BIGINT CHECK(count>0), first_seq BIGINT NOT NULL CHECK(first_seq>=0 AND first_seq<tree_size),
 last_seq BIGINT CHECK(last_seq>=first_seq AND last_seq<tree_size),
 key_root BYTEA CHECK(octet_length(key_root)=32),
 value_kind TEXT NOT NULL CHECK(value_kind IN ('occurrences','flag')), state_value BYTEA,
 CHECK((value_kind='occurrences' AND key_type<>'flag' AND count IS NOT NULL
        AND last_seq IS NOT NULL AND key_root IS NOT NULL AND state_value IS NULL
        AND count<=last_seq-first_seq+1 AND count<=tree_size AND ((count=1)=(first_seq=last_seq)))
    OR (value_kind='flag' AND key_type='flag' AND count IS NULL AND last_seq IS NULL
        AND key_root IS NULL AND state_value IS NOT NULL)),
 PRIMARY KEY(tenant,key_digest,tree_size));
ALTER TABLE regulated_evidence_map_v2 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_map_v2 FORCE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_keys_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_keys_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS evidence_map_tenant_v2 ON regulated_evidence_map_v2;
CREATE POLICY evidence_map_tenant_v2 ON regulated_evidence_map_v2
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP POLICY IF EXISTS evidence_keys_tenant_v1 ON regulated_evidence_keys_v1;
CREATE POLICY evidence_keys_tenant_v1 ON regulated_evidence_keys_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS evidence_map_no_mutation_v2 ON regulated_evidence_map_v2;
CREATE TRIGGER evidence_map_no_mutation_v2 BEFORE UPDATE OR DELETE ON regulated_evidence_map_v2
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS evidence_map_no_truncate_v2 ON regulated_evidence_map_v2;
CREATE TRIGGER evidence_map_no_truncate_v2 BEFORE TRUNCATE ON regulated_evidence_map_v2
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS evidence_keys_no_mutation_v1 ON regulated_evidence_keys_v1;
CREATE TRIGGER evidence_keys_no_mutation_v1 BEFORE UPDATE OR DELETE ON regulated_evidence_keys_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS evidence_keys_no_truncate_v1 ON regulated_evidence_keys_v1;
CREATE TRIGGER evidence_keys_no_truncate_v1 BEFORE TRUNCATE ON regulated_evidence_keys_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""

# Point lookup by authenticated content digest; EXPLAIN qualification is separate.
MAP_PROOF_SQL = """
SELECT kind,left_hash,right_hash,leaf_key,value FROM regulated_evidence_map_v2
 WHERE tenant=%s AND hash=%s
"""
KEY_VALUE_SQL = """
SELECT count,first_seq,last_seq,key_root,value_kind,state_value FROM regulated_evidence_keys_v1
 WHERE tenant=%s AND key_digest=%s AND tree_size<=%s::bigint ORDER BY tree_size DESC LIMIT 1
"""


def _transaction(conn: Any, tenant: str) -> None:
    from psycopg.pq import TransactionStatus
    if type(tenant) is not str or not tenant or conn.info.transaction_status != TransactionStatus.INTRANS:
        raise EvidenceError("evidence map requires an active tenant transaction")
    actual, isolation = conn.execute(
        "SELECT current_setting('app.tenant',true),current_setting('transaction_isolation')"
    ).fetchone()
    if actual != tenant or isolation not in ("read committed", "repeatable read", "serializable"):
        raise EvidenceError("evidence map transaction scope mismatch")


def _size(value: int) -> None:
    if type(value) is not int or not 0 <= value <= PG_MAX:
        raise EvidenceError("evidence map size exceeds PostgreSQL integer range")


def prefix(key: bytes, depth: int) -> bytes:
    if type(key) is not bytes or len(key) != 32 or type(depth) is not int or not 0 <= depth <= 256:
        raise EvidenceError("invalid sparse-map prefix")
    bits = int.from_bytes(key, "big")
    return ((bits >> (256 - depth)) << (256 - depth)).to_bytes(32, "big")


def proof_prefixes(key: bytes) -> tuple[list[int], list[bytes]]:
    prefix(key, 256)
    bits = int.from_bytes(key, "big")
    return list(range(1, 257)), [prefix((bits ^ (1 << (256 - depth))).to_bytes(32, "big"), depth)
                                for depth in range(1, 257)]


def _checked_map_node(row, digest):
    if row is None:raise EvidenceError("missing authenticated map node")
    kind,left,right,key,value=row
    if kind=="leaf" and left is None and right is None:
        node=MapNode(key=bytes(key) if key is not None else None,value=bytes(value) if value is not None else None)
    elif kind=="node" and key is None and value is None:
        node=MapNode(left=bytes(left) if left is not None else None,right=bytes(right) if right is not None else None)
    else:raise EvidenceError("invalid map node shape")
    if node_digest(node)!=digest:raise EvidenceError("map node digest mismatch")
    return node


# Only verified immutable map bytes are cached, never heads, permissions,
# clocks, absence, errors or staged-write readbacks. Each append owns its cache.
_MAP_READ_CACHE_LIMIT = 4096
_MAP_READ_SCOPE = ContextVar("evidence_map_read_scope", default=None)


@contextmanager
def _map_read_scope(conn, tenant):
    cache = OrderedDict()
    scope = [conn, tenant, cache, True]
    token = _MAP_READ_SCOPE.set(scope)
    try:
        yield
    finally:
        scope[3] = False
        cache.clear()
        _MAP_READ_SCOPE.reset(token)


def _map_reader(conn, tenant):
    def read(digest):
        scope = _MAP_READ_SCOPE.get()
        cache = scope[2] if scope is not None and scope[3] and scope[0] is conn and scope[1] == tenant else None
        if cache is not None and digest in cache:
            cache.move_to_end(digest)
            return cache[digest]
        row = conn.execute(MAP_PROOF_SQL, (tenant, digest)).fetchone()
        node = _checked_map_node(row, digest)
        if cache is not None:
            if len(cache) >= _MAP_READ_CACHE_LIMIT:
                cache.popitem(last=False)
            cache[digest] = node
        return node
    return read



# At most eight independent paths per protocol batch. This only preloads
# verified immutable bytes into the existing append-local cache. Normal prove()
# still validates every path, terminal, depth and authenticated root afterwards.
_MAP_PREFETCH_KEYS = 8

def _prefetch_map_paths_on(conn, tenant, root, keys):
    scope = _MAP_READ_SCOPE.get()
    if scope is None or not scope[3] or scope[0] is not conn or scope[1] != tenant:
        raise EvidenceError("map prefetch requires the owned append scope")
    if type(keys) is not tuple or len(keys) > _MAP_PREFETCH_KEYS:
        raise EvidenceError("map prefetch key bound")
    prefix(root, 0)
    for key in keys:prefix(key, 0)
    cache = scope[2]
    pending = [(key, root, 0) for key in keys if root != EMPTY[0]]
    while pending:
        missing = list(dict.fromkeys(digest for _, digest, _ in pending if digest not in cache))
        for _, digest, _ in pending:
            if digest in cache:cache.move_to_end(digest)
        if missing:
            with conn.pipeline():
                replies = [conn.execute(MAP_PROOF_SQL, (tenant, digest)) for digest in missing]
            for digest, reply in zip(missing, replies, strict=True):
                node = _checked_map_node(reply.fetchone(), digest)
                if len(cache) >= _MAP_READ_CACHE_LIMIT:cache.popitem(last=False)
                cache[digest] = node
        following = []
        for key, digest, depth in pending:
            node = cache[digest]
            if node.key is not None:
                if prefix(node.key, depth) != prefix(key, depth):
                    raise EvidenceError("misplaced map leaf")
            else:
                if depth >= 256:raise EvidenceError("map path depth exceeded")
                child = node.right if (key[depth // 8] >> (7 - depth % 8)) & 1 else node.left
                if child != EMPTY[0]:following.append((key, child, depth + 1))
        pending = following


def read_map_proof_on(conn: Any, *, tenant: str, tree_size: int, root: bytes, key: bytes) -> MapProof:
    _transaction(conn,tenant);_size(tree_size)
    tree=MemorySparseMap(reader=_map_reader(conn,tenant));tree.root=root
    try:return tree.prove(key)
    except (ValueError,KeyError,TypeError) as exc:raise EvidenceError("stored map differs from pinned root") from exc


@dataclass(frozen=True)
class MapBatch:
    tenant: str
    tree_size: int
    root: bytes
    nodes: tuple[tuple[bytes, MapNode], ...]
    values: tuple[tuple[bytes, str, KeySummary | UnhashableIdFlag], ...]


def stage_map_update_on(conn: Any, *, tenant: str, tree_size: int, previous_root: bytes,
                        updates: dict[bytes, tuple[str, KeySummary | UnhashableIdFlag]]) -> MapBatch:
    _transaction(conn,tenant);_size(tree_size)
    if tree_size==0 or type(updates) is not dict or not updates:raise EvidenceError("new map version needs key updates")
    tree=MemorySparseMap(reader=_map_reader(conn,tenant));tree.root=previous_root;values=[]
    for key,(kind,summary) in updates.items():
        if kind=="flag" and type(summary) is UnhashableIdFlag and key==unhashable_id_key(tenant):
            UnhashableIdFlag.decode(summary.bytes(),tree_size)
            if tree.prove(key).value is not None:raise EvidenceError("history flag cannot be replaced")
        elif kind in ("record_id","record_hash","record_id_hash","outcome_of","release_decision_eligible","release_outcome_eligible") and type(summary) is KeySummary:
            KeySummary.decode(summary.bytes(),tree_size)
        else:raise EvidenceError("invalid decision map value kind")
        tree.update(key,summary.bytes());values.append((key,kind,summary))
    return MapBatch(tenant,tree_size,tree.root,tuple(tree._nodes.items()),tuple(values))


def insert_map_batch_on(conn: Any, batch: MapBatch) -> None:
    _transaction(conn,batch.tenant)
    rows=[]
    for digest,node in batch.nodes:
        if node_digest(node)!=digest:raise EvidenceError("invalid staged node")
        rows.append((batch.tenant,digest,"leaf" if node.key is not None else "node",node.left,node.right,node.key,node.value))
    with conn.cursor() as cursor:
        # Bound each SQL message to staged nodes, never retained history. The
        # same transaction/tenant guard above and append savepoint remain owned
        # by the caller. Staged-write readbacks never use the map-read cache.
        for offset in range(0, len(rows), 256):
            chunk = rows[offset:offset + 256]
            expected = dict(batch.nodes[offset:offset + 256])
            cursor.execute(
                "INSERT INTO regulated_evidence_map_v2(tenant,hash,kind,left_hash,right_hash,leaf_key,value) "
                "SELECT %s, n.* FROM unnest(%s::bytea[],%s::text[],%s::bytea[],"
                "%s::bytea[],%s::bytea[],%s::bytea[]) AS n(hash,kind,left_hash,right_hash,leaf_key,value) "
                "ON CONFLICT DO NOTHING",
                (batch.tenant, *([row[column] for row in chunk] for column in range(1, 7))),
            )
            # A conflict cannot turn corrupt existing bytes into trusted content.
            # Check every requested digest exactly once, independent of row order,
            # and retain shape, digest and exact-node equality checks for each row.
            cursor.execute(
                "SELECT stored.hash,stored.kind,stored.left_hash,stored.right_hash,stored.leaf_key,stored.value "
                "FROM unnest(%s::bytea[]) AS requested(hash) CROSS JOIN LATERAL "
                "(SELECT hash,kind,left_hash,right_hash,leaf_key,value FROM regulated_evidence_map_v2 "
                "WHERE tenant=%s AND hash=requested.hash LIMIT 1) AS stored",
                (list(expected), batch.tenant),
            )
            seen = set()
            for row in cursor.fetchall():
                digest = bytes(row[0])
                if digest not in expected or digest in seen:
                    raise EvidenceError("unexpected or duplicate map readback")
                if _checked_map_node(row[1:], digest) != expected[digest]:
                    raise EvidenceError("immutable map row differs")
                seen.add(digest)
            if seen != set(expected):
                raise EvidenceError("missing authenticated map node")
        values = [(key,kind,None if kind=="flag" else value.count,value.first_seq,
                   None if kind=="flag" else value.last_seq,None if kind=="flag" else bytes.fromhex(value.key_root),
                   "flag" if kind=="flag" else "occurrences",value.bytes() if kind=="flag" else None)
                  for key,kind,value in batch.values]
        for offset in range(0, len(values), 256):
            chunk = values[offset:offset + 256]
            cursor.execute(
                "INSERT INTO regulated_evidence_keys_v1(tenant,key_digest,key_type,tree_size,count,first_seq,last_seq,"
                "key_root,value_kind,state_value) SELECT %s,n.key_digest,n.key_type,%s,n.count,n.first_seq,"
                "n.last_seq,n.key_root,n.value_kind,n.state_value FROM "
                "unnest(%s::bytea[],%s::text[],%s::bigint[],%s::bigint[],%s::bigint[],%s::bytea[],%s::text[],%s::bytea[]) "
                "AS n(key_digest,key_type,count,first_seq,last_seq,key_root,value_kind,state_value)",
                (batch.tenant,batch.tree_size,*([row[col] for row in chunk] for col in range(8))))



# Explicit provisioning only. Existing recorder schema must already be installed.
SERVICE_SCHEMA = """
CREATE TABLE IF NOT EXISTS regulated_evidence_tree_v1 (
 tenant TEXT NOT NULL, level SMALLINT NOT NULL CHECK(level BETWEEN 0 AND 62),
 idx BIGINT NOT NULL CHECK(idx>=0), hash BYTEA NOT NULL CHECK(octet_length(hash)=32),
 PRIMARY KEY(tenant,level,idx));
CREATE TABLE IF NOT EXISTS regulated_evidence_frontier_v1 (
 tenant TEXT NOT NULL, tree_size BIGINT NOT NULL CHECK(tree_size>0), frontier JSONB NOT NULL,
 PRIMARY KEY(tenant,tree_size));
CREATE TABLE IF NOT EXISTS regulated_evidence_heads_v1 (
 tenant TEXT NOT NULL, tree_size BIGINT NOT NULL CHECK(tree_size>0), sth JSONB NOT NULL,
 PRIMARY KEY(tenant,tree_size));
CREATE TABLE IF NOT EXISTS regulated_evidence_key_tree_v1 (
 tenant TEXT NOT NULL, key_digest BYTEA NOT NULL CHECK(octet_length(key_digest)=32),
 level SMALLINT NOT NULL CHECK(level BETWEEN 0 AND 62), idx BIGINT NOT NULL CHECK(idx>=0),
 hash BYTEA NOT NULL CHECK(octet_length(hash)=32), PRIMARY KEY(tenant,key_digest,level,idx));
CREATE TABLE IF NOT EXISTS regulated_evidence_key_frontier_v1 (
 tenant TEXT NOT NULL, key_digest BYTEA NOT NULL CHECK(octet_length(key_digest)=32),
 tree_size BIGINT NOT NULL CHECK(tree_size>0), frontier JSONB NOT NULL,
 PRIMARY KEY(tenant,key_digest,tree_size));
CREATE TABLE IF NOT EXISTS regulated_evidence_key_occurrences_v1 (
 tenant TEXT NOT NULL, key_digest BYTEA NOT NULL CHECK(octet_length(key_digest)=32),
 ordinal BIGINT NOT NULL CHECK(ordinal>=0), seq BIGINT NOT NULL CHECK(seq>=0),
 tree_size BIGINT NOT NULL CHECK(tree_size>seq),
 PRIMARY KEY(tenant,key_digest,ordinal), UNIQUE(tenant,key_digest,seq));
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_tree_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_tree_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_tree_v1;
CREATE POLICY tenant_scope ON regulated_evidence_tree_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_tree_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_tree_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_tree_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_tree_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_frontier_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_frontier_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_frontier_v1;
CREATE POLICY tenant_scope ON regulated_evidence_frontier_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_frontier_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_frontier_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_frontier_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_frontier_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_heads_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_heads_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_heads_v1;
CREATE POLICY tenant_scope ON regulated_evidence_heads_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_heads_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_heads_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_heads_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_heads_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_key_tree_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_key_tree_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_key_tree_v1;
CREATE POLICY tenant_scope ON regulated_evidence_key_tree_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_key_tree_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_key_tree_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_key_tree_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_key_tree_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_key_frontier_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_key_frontier_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_key_frontier_v1;
CREATE POLICY tenant_scope ON regulated_evidence_key_frontier_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_key_frontier_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_key_frontier_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_key_frontier_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_key_frontier_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""
SERVICE_SCHEMA += """
ALTER TABLE regulated_evidence_key_occurrences_v1 ENABLE ROW LEVEL SECURITY;
ALTER TABLE regulated_evidence_key_occurrences_v1 FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON regulated_evidence_key_occurrences_v1;
CREATE POLICY tenant_scope ON regulated_evidence_key_occurrences_v1
 USING(tenant=current_setting('app.tenant',true)) WITH CHECK(tenant=current_setting('app.tenant',true));
DROP TRIGGER IF EXISTS no_mutation ON regulated_evidence_key_occurrences_v1;
CREATE TRIGGER no_mutation BEFORE UPDATE OR DELETE ON regulated_evidence_key_occurrences_v1
 FOR EACH ROW EXECUTE FUNCTION regulated_authority_no_mutation_v1();
DROP TRIGGER IF EXISTS no_truncate ON regulated_evidence_key_occurrences_v1;
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON regulated_evidence_key_occurrences_v1
 FOR EACH STATEMENT EXECUTE FUNCTION regulated_authority_no_mutation_v1();
"""

# Bind integers to indexed column types. The occurrence lookup uses an ordered
# lower bound and verifies exact ordinal equality after fetching. A plain equality
# lookup, even with explicit types and a covering PK, selected the sibling seq
# index and filtered 999 matches on fresh statistics. No planner knobs are changed.
# Oldest/middle/latest positions qualify the chosen range query, not LIMIT alone.
# These exact queries are also used by the isolated normal-planner qualification.
HEAD_SQL = "SELECT tree_size,sth FROM regulated_evidence_heads_v1 WHERE tenant=%s AND tree_size=%s::bigint"
LATEST_HEAD_SQL = "SELECT tree_size,sth FROM regulated_evidence_heads_v1 WHERE tenant=%s ORDER BY tree_size DESC LIMIT 1"
FRONTIER_SQL = "SELECT frontier FROM regulated_evidence_frontier_v1 WHERE tenant=%s AND tree_size=%s::bigint"
KEY_FRONTIER_SQL = """SELECT frontier FROM regulated_evidence_key_frontier_v1
 WHERE tenant=%s AND key_digest=%s AND tree_size<=%s::bigint ORDER BY tree_size DESC LIMIT 1"""
TREE_NODE_SQL = "SELECT hash FROM regulated_evidence_tree_v1 WHERE tenant=%s AND level=%s::smallint AND idx=%s::bigint"
KEY_NODE_SQL = "SELECT hash FROM regulated_evidence_key_tree_v1 WHERE tenant=%s AND key_digest=%s AND level=%s::smallint AND idx=%s::bigint"
OCCURRENCE_SQL = """SELECT ordinal,seq,tree_size FROM regulated_evidence_key_occurrences_v1
 WHERE tenant=%s AND key_digest=%s AND ordinal>=%s::bigint ORDER BY ordinal LIMIT 1"""
ENVELOPE_SQL = "SELECT seq,entry_hash,envelope FROM regulated_decision_evidence_v1 WHERE tenant=%s AND seq=%s::bigint"


def frontier_document(frontier: Any) -> dict[str, Any]:
    from .merkle import Frontier
    if type(frontier) is not Frontier or frontier.size > PG_MAX:
        raise EvidenceError("invalid PostgreSQL frontier")
    return {"schema": "regulated/evidence-frontier/v1", "size": frontier.size,
            "slots": [None if slot is None else slot.hex() for slot in frontier.slots]}


def decode_frontier(value: Any, *, size: int, root: bytes) -> Any:
    from .merkle import Frontier
    from .evidence_service import _hex
    try:
        _size(size)
        if (type(value) is not dict or set(value) != {"schema", "size", "slots"}
                or value["schema"] != "regulated/evidence-frontier/v1"
                or type(value["size"]) is not int or value["size"] != size
                or type(value["slots"]) is not list or len(value["slots"]) > 63
                or any(slot is not None and not _hex(slot) for slot in value["slots"])):
            raise ValueError("invalid frontier encoding")
        frontier = Frontier(size, tuple(None if slot is None else bytes.fromhex(slot) for slot in value["slots"]))
        if frontier.root != root:
            raise ValueError("frontier root mismatch")
        return frontier
    except (TypeError, ValueError, KeyError, RecursionError) as exc:
        raise EvidenceError("stored frontier differs from authenticated state") from exc


class PostgresEvidenceService:
    """Core append and proof provider on caller-owned tenant transactions.

    append_record_on uses the existing recorder unchanged and nests a savepoint:
    catching a companion failure cannot accidentally commit just the envelope.
    It requires READ COMMITTED so reads AFTER the tenant lock see the preceding
    writer. No authority, time or lock checks of application callers are replaced.
    A returned head is uncommitted until the caller commits; it is not a permit.
    The separate protected-head/audit/retention gate is mandatory before use in
    an operational path, and is not activated by constructing this core service.
    """

    def __init__(self, *, tenant: str, signer: Any, clock: Any, trust: Any,
                 signing_keys: frozenset[str], historical_head_keys: dict,
                 envelope_keys_allowed: frozenset[str], envelope_domains: frozenset[str]) -> None:
        if (type(tenant) is not str or not tenant or type(envelope_keys_allowed) is not frozenset
                or not envelope_keys_allowed or type(envelope_domains) is not frozenset or not envelope_domains
                or type(signing_keys) is not frozenset or not signing_keys
                or not valid_policy(signing_keys, historical_head_keys)):
            raise EvidenceError("invalid PostgreSQL evidence service scope")
        self.tenant, self.signer, self.clock, self.trust = tenant, signer, clock, trust
        self.signing_keys, self.historical_head_keys = signing_keys, copy_retirements(signing_keys, historical_head_keys)
        self.envelope_keys_allowed, self.envelope_domains = envelope_keys_allowed, envelope_domains

    def _verify_head(self, head: Any) -> None:
        from .evidence_service import verify_head
        if not verify_head(head, tenant=self.tenant, clock_domain=self.clock.domain,
                           trust=self.trust, allowed_keys=self.signing_keys, historical_keys=self.historical_head_keys):
            raise EvidenceError("stored head signature or scope failed")
        _size(head.tree_size)

    def head_on(self, conn: Any, tree_size: int | None = None) -> Any:
        from .evidence_service import TreeHead
        _transaction(conn, self.tenant)
        if tree_size is not None:
            _size(tree_size)
            row = conn.execute(HEAD_SQL, (self.tenant, tree_size)).fetchone()
        else:
            row = conn.execute(LATEST_HEAD_SQL, (self.tenant,)).fetchone()
        if row is None:
            if tree_size is not None:
                raise EvidenceError("requested signed head is missing")
            return None
        head = TreeHead.from_document(row[1])
        self._verify_head(head)
        if head.tree_size != row[0]:
            raise EvidenceError("head row size differs from signed body")
        return head

    def _pinned_on(self, conn: Any, head: Any) -> None:
        self._verify_head(head)
        if self.head_on(conn, head.tree_size) != head:
            raise EvidenceError("stored head differs from caller pin")

    def _node_reader(self, conn: Any, key: bytes | None = None):
        def read(level: int, index: int) -> bytes:
            row = (conn.execute(TREE_NODE_SQL, (self.tenant, level, index)).fetchone() if key is None
                   else conn.execute(KEY_NODE_SQL, (self.tenant, key, level, index)).fetchone())
            if row is None or len(row[0]) != 32:
                raise EvidenceError("authenticated subtree node is missing or malformed")
            return bytes(row[0])
        return read

    def _tree_proof_on(self, conn: Any, build):
        """Pipeline bounded point reads for a deterministic Merkle proof.

        The existing proof traversal depends only on tree sizes and indices,
        never on subtree bytes. Its first pass plans addresses; placeholder
        hashes are discarded. A second pass uses every checked database row.
        No result survives this call and no transaction boundary is changed.
        """
        addresses = []

        def plan(level, index):
            if (type(level) is not int or not 0 <= level < 63
                    or type(index) is not int or not 0 <= index <= PG_MAX
                    or len(addresses) >= 4096):
                raise EvidenceError("Merkle proof address bound")
            addresses.append((level, index))
            return bytes(32)

        build(plan)
        values = []
        for start in range(0, len(addresses), 128):
            chunk = addresses[start:start + 128]
            with conn.pipeline():
                cursors = [conn.execute(TREE_NODE_SQL, (self.tenant, level, index))
                           for level, index in chunk]
            # Drain the pipeline before checking every result, as in scalar reads.
            for cursor in cursors:
                row = cursor.fetchone()
                if row is None or len(row[0]) != 32:
                    raise EvidenceError("authenticated subtree node is missing or malformed")
                values.append(bytes(row[0]))
        position = 0

        def read(level, index):
            nonlocal position
            if position >= len(addresses) or addresses[position] != (level, index):
                raise EvidenceError("Merkle proof traversal changed")
            value = values[position]
            position += 1
            return value

        proof = build(read)
        if position != len(addresses):
            raise EvidenceError("Merkle proof traversal incomplete")
        return proof

    def _append_consistency_on(self, conn, size, overlay):
        from .merkle import consistency_proof

        def build(read_old):
            def read(level, index):
                address = (level, index)
                return overlay[address] if address in overlay else read_old(level, index)
            return consistency_proof(read, size, size + 1)

        return self._tree_proof_on(conn, build)

    def append_record_on(self, conn: Any, recorder: Any, record: Any, record_hash: str) -> tuple[Any, Any]:
        from .evidence_encoding import canonical_bytes, envelope_bytes, loads as evidence_loads
        from .evidence import GENESIS, verify_envelope
        from .evidence_service import envelope_keys, occurrence_bytes, sign_head
        from .merkle import Frontier, consistency_proof, verify_consistency
        from .persistence_pg import PostgresDecisionRecorder, decode_envelope
        _transaction(conn, self.tenant)
        if (not isinstance(recorder, PostgresDecisionRecorder) or record.tenant_id != self.tenant
                or conn.execute("SELECT current_setting('transaction_isolation')").fetchone()[0] != "read committed"):
            raise EvidenceError("append requires the tenant recorder and READ COMMITTED")
        try:
            check_numeric_domain(record)
            envelope_bytes(record)
        except (ValueError, RecursionError) as exc:
            raise EvidenceError("appended record exceeds admitted numeric domain") from exc
        with conn.transaction(), _map_read_scope(conn, self.tenant):  # append-local cache; savepoint unchanged
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                         ("regulated-evidence-v1:" + self.tenant,))
            previous = self.head_on(conn)
            size = 0 if previous is None else previous.tree_size
            if size == PG_MAX:
                raise EvidenceError("PostgreSQL evidence size exhausted")
            if previous is None:
                frontier, old_map = Frontier(), EMPTY[0]
            else:
                row = conn.execute(FRONTIER_SQL, (self.tenant, size)).fetchone()
                if row is None:
                    raise EvidenceError("signed head has no frontier")
                frontier = decode_frontier(row[0], size=size, root=bytes.fromhex(previous.tree_root))
                old_map = bytes.fromhex(previous.map_root)
            # Legacy recorder performs its own unchanged fresh clock/signature
            # checks. Its independent clock-floor commits remain independent.
            envelope = recorder._append_on(conn, record, record_hash)
            if (type(envelope.seq) is not int or envelope.seq != size
                    or envelope.prev_hash != (GENESIS if previous is None else previous.last_entry_hash)
                    or envelope.record.tenant_id != self.tenant
                    or envelope.signature.key_id not in self.envelope_keys_allowed
                    or envelope.clock_domain not in self.envelope_domains
                    or not verify_envelope(envelope, self.trust)):
                raise EvidenceError("recorder append differs from authenticated history or policy")
            # Index the exact decoded view while classifying representation errors.
            # The recorder's object and original signed bytes remain unchanged.
            try:
                raw = envelope_bytes(envelope)
                stored_envelope = decode_envelope(evidence_loads(raw))
            except (ValueError, TypeError, RecursionError) as exc:
                raise EvidenceError("invalid appended evidence representation") from exc
            frontier, completed = frontier.append(raw)
            # Verify consistency against old storage before publishing the new
            # head; new completed nodes form a bounded overlay, never a copy.
            overlay = {(n.level, n.index): n.digest for n in completed}
            path = self._append_consistency_on(conn, size, overlay)
            if not verify_consistency(size, size + 1, EMPTY_ROOT if previous is None else bytes.fromhex(previous.tree_root),
                                      frontier.root, path):
                raise EvidenceError("stored tree does not extend the signed prefix")
            updates, pending = {}, []
            indexed_keys = envelope_keys(stored_envelope)
            preload_keys = tuple(indexed_keys)
            if type(stored_envelope.record.record_id) is list or type(stored_envelope.record.record_id) is dict:
                preload_keys += (unhashable_id_key(self.tenant),)
            for offset in range(0, len(preload_keys), _MAP_PREFETCH_KEYS):
                _prefetch_map_paths_on(conn, self.tenant, old_map,
                                       preload_keys[offset:offset + _MAP_PREFETCH_KEYS])
            # Read independent immutable key frontiers in bounded protocol batches.
            # SQL, tenant/head binding and every per-key proof/decode check remain
            # unchanged; no clock or authority result is reused.
            indexed_items = tuple(indexed_keys.items())
            for offset in range(0, len(indexed_items), 8):
                chunk = indexed_items[offset:offset + 8]
                with conn.pipeline():
                    replies = [conn.execute(KEY_FRONTIER_SQL, (self.tenant, key, size))
                               for key, kind in chunk]
                for (key, kind), reply in zip(chunk, replies, strict=True):
                    proof = read_map_proof_on(conn, tenant=self.tenant, tree_size=size, root=old_map, key=key)
                    old = None if proof.value is None else KeySummary.decode(proof.value, size)
                    row = reply.fetchone()
                    if old is None:
                        if row is not None:
                            raise EvidenceError("unindexed occurrence frontier")
                        key_frontier = Frontier()
                    else:
                        if row is None:
                            raise EvidenceError("occurrence frontier is missing")
                        key_frontier = decode_frontier(row[0], size=old.count, root=bytes.fromhex(old.key_root))
                    ordinal = key_frontier.size
                    key_frontier, key_nodes = key_frontier.append(occurrence_bytes(size))
                    summary = KeySummary(ordinal + 1, size if old is None else old.first_seq, size, key_frontier.root.hex())
                    updates[key] = kind, summary
                    pending.append((key, ordinal, key_frontier, key_nodes))
            if (type(stored_envelope.record.record_id) is list or type(stored_envelope.record.record_id) is dict):
                flag_key = unhashable_id_key(self.tenant)
                flag_proof = read_map_proof_on(conn, tenant=self.tenant, tree_size=size, root=old_map, key=flag_key)
                if flag_proof.value is None:
                    updates[flag_key] = "flag", UnhashableIdFlag(size)
                else:
                    UnhashableIdFlag.decode(flag_proof.value, size)
            batch = stage_map_update_on(conn, tenant=self.tenant, tree_size=size + 1,
                                        previous_root=old_map, updates=updates)
            head = sign_head(tenant=self.tenant, tree_size=size + 1, tree_root=frontier.root,
                             map_root=batch.root, last_entry_hash=envelope.chain_hash(), previous=previous,
                             signer=self.signer, clock=self.clock, trust=self.trust,
                             signing_keys=self.signing_keys, historical_keys=self.historical_head_keys)
            self._insert_append_on(conn, head, frontier, completed, pending, batch)
            return envelope, head

    def _insert_append_on(self, conn, head, frontier, completed, pending, batch):
        from itertools import islice
        from .evidence_encoding import canonical_bytes
        statements = self._append_write_statements(head, frontier, completed, pending)
        with conn.cursor() as cursor:
            # Only already-prepared append writes share these bounded protocol
            # batches. Drain every batch before map scope/readback validation.
            while chunk := tuple(islice(statements, 8)):
                with conn.pipeline():
                    for sql, params in chunk:
                        cursor.execute(sql, params)
            insert_map_batch_on(conn, batch)
            cursor.execute("INSERT INTO regulated_evidence_heads_v1(tenant,tree_size,sth) VALUES(%s,%s,%s::jsonb)",
                           (self.tenant, head.tree_size, canonical_bytes(head.document()).decode()))

    def _append_write_statements(self, head, frontier, completed, pending):
        from .evidence_encoding import canonical_bytes
        for offset in range(0, len(completed), 256):
            chunk = completed[offset:offset + 256]
            yield (
                "INSERT INTO regulated_evidence_tree_v1(tenant,level,idx,hash) "
                "SELECT %s,n.* FROM unnest(%s::smallint[],%s::bigint[],%s::bytea[]) AS n(level,idx,hash)",
                (self.tenant,[n.level for n in chunk],[n.index for n in chunk],[n.digest for n in chunk]))
        yield ("INSERT INTO regulated_evidence_frontier_v1(tenant,tree_size,frontier) VALUES(%s,%s,%s::jsonb)",
                       (self.tenant, head.tree_size, canonical_bytes(frontier_document(frontier)).decode()))
        key_nodes = [(key,n.level,n.index,n.digest) for key,ordinal,key_frontier,nodes in pending for n in nodes]
        for offset in range(0, len(key_nodes), 256):
            chunk = key_nodes[offset:offset + 256]
            yield (
                "INSERT INTO regulated_evidence_key_tree_v1(tenant,key_digest,level,idx,hash) "
                "SELECT %s,n.* FROM unnest(%s::bytea[],%s::smallint[],%s::bigint[],%s::bytea[]) AS n(key_digest,level,idx,hash)",
                (self.tenant,*([row[col] for row in chunk] for col in range(4))))
        for offset in range(0, len(pending), 256):
            chunk = pending[offset:offset + 256]
            yield (
                "INSERT INTO regulated_evidence_key_frontier_v1(tenant,key_digest,tree_size,frontier) "
                "SELECT %s,n.key_digest,%s,n.frontier FROM unnest(%s::bytea[],%s::jsonb[]) AS n(key_digest,frontier)",
                (self.tenant,head.tree_size,[key for key,ordinal,key_frontier,nodes in chunk],
                 [canonical_bytes(frontier_document(key_frontier)).decode() for key,ordinal,key_frontier,nodes in chunk]))
            yield (
                "INSERT INTO regulated_evidence_key_occurrences_v1(tenant,key_digest,ordinal,seq,tree_size) "
                "SELECT %s,n.key_digest,n.ordinal,%s,%s FROM unnest(%s::bytea[],%s::bigint[]) AS n(key_digest,ordinal)",
                (self.tenant,head.tree_size-1,head.tree_size,[key for key,ordinal,key_frontier,nodes in chunk],
                 [ordinal for key,ordinal,key_frontier,nodes in chunk]))


    def consistency_on(self, conn: Any, previous: Any, head: Any) -> tuple[bytes, ...]:
        from .evidence_service import verify_head_extension
        from .merkle import consistency_proof
        _transaction(conn, self.tenant)
        self._pinned_on(conn, head)
        if previous is not None:
            self._pinned_on(conn, previous)
        size = 0 if previous is None else previous.tree_size
        if size > head.tree_size:
            raise EvidenceError("consistency request regresses")
        proof = self._tree_proof_on(conn, lambda read: consistency_proof(read, size, head.tree_size))
        if not verify_head_extension(previous, head, proof, tenant=self.tenant, clock_domain=self.clock.domain,
                                     trust=self.trust, allowed_keys=self.signing_keys, historical_keys=self.historical_head_keys):
            raise EvidenceError("stored consistency proof failed")
        return proof

    def history_flag_on(self, conn: Any, *, head: Any) -> Any:
        from .evidence_service import HistoryFlagProof, verify_history_flag
        _transaction(conn, self.tenant)
        self._pinned_on(conn, head)
        mapping = read_map_proof_on(conn, tenant=self.tenant, tree_size=head.tree_size,
                                    root=bytes.fromhex(head.map_root), key=unhashable_id_key(self.tenant))
        proof = HistoryFlagProof(head, mapping)
        verify_history_flag(proof, expected_head=head, tenant=self.tenant, clock_domain=self.clock.domain,
                            trust=self.trust, allowed_head_keys=self.signing_keys, historical_head_keys=self.historical_head_keys)
        return proof

    def lookup_on(self, conn: Any, *, head: Any, key_type: str, key: Any,
                  selection: str, ordinal: int | None = None) -> Any:
        from .evidence_encoding import canonical_bytes, envelope_bytes, loads as evidence_loads
        from .evidence_service import (LookupProof, OccurrenceProof, lookup_key, verify_lookup, _natural)
        from .merkle import inclusion_proof
        _transaction(conn, self.tenant)
        digest = lookup_key(self.tenant, key_type, key)
        if (selection not in ("count", "absent", "first", "latest", "ordinal")
                or (selection == "ordinal" and not _natural(ordinal))
                or (selection != "ordinal" and ordinal is not None)):
            raise EvidenceError("invalid lookup selection")
        self._pinned_on(conn, head)
        mapping = read_map_proof_on(conn, tenant=self.tenant, tree_size=head.tree_size,
                                    root=bytes.fromhex(head.map_root), key=digest)
        item = None
        if mapping.value is not None and selection not in ("count", "absent"):
            summary = KeySummary.decode(mapping.value, head.tree_size)
            wanted = 0 if selection == "first" else summary.count - 1 if selection == "latest" else ordinal
            if wanted < summary.count:
                row = conn.execute(OCCURRENCE_SQL, (self.tenant, digest, wanted)).fetchone()
                if (row is None or row[0] != wanted or type(row[1]) is not int or not 0 <= row[1] < head.tree_size
                        or row[2] != row[1] + 1):
                    raise EvidenceError("occurrence association is missing or inconsistent")
                seq = row[1]
                stored = conn.execute(ENVELOPE_SQL, (self.tenant, seq)).fetchone()
                if stored is None:
                    raise EvidenceError("occurrence envelope is missing")
                raw = envelope_bytes(stored[2])
                item = OccurrenceProof(wanted, seq, raw,
                                       inclusion_proof(self._node_reader(conn, digest), wanted, summary.count),
                                       inclusion_proof(self._node_reader(conn), seq, head.tree_size))
        proof = LookupProof(head, mapping, item)
        result = verify_lookup(proof, expected_head=head, tenant=self.tenant, key_type=key_type, key=key,
                               selection=selection, ordinal=ordinal, clock_domain=self.clock.domain,
                               trust=self.trust, allowed_head_keys=self.signing_keys, historical_head_keys=self.historical_head_keys,
                               allowed_envelope_keys=self.envelope_keys_allowed,
                               allowed_envelope_domains=self.envelope_domains)
        if result.envelope is not None and (stored[0] != result.envelope.seq or stored[1] != result.envelope.chain_hash()):
            raise EvidenceError("stored envelope metadata differs from authenticated body")
        return proof
