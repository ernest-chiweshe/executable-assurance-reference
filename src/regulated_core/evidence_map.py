"""Persistent compact map v2. Single-key subtrees collapse; depth never exceeds256.

Work is proportional to visited path depth and value bytes, not a universal
logarithmic bound. Historical roots use immutable content-addressed nodes.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import base64
from typing import Any
from .evidence_encoding import canonical_bytes, loads

DEPTH = 256
MAX_VALUE = 512
EMPTY_LEAF = sha256(b"regulated/evidence-map/v2:empty").digest()
EMPTY = (EMPTY_LEAF,) * 257

def _digest(value):
    return type(value) is bytes and len(value) == 32

def key_digest(tenant: str, key_type: str, key: Any) -> bytes:
    if type(tenant) is not str or not tenant or type(key_type) is not str or not key_type:
        raise ValueError("key requires a tenant and type")
    return sha256(canonical_bytes({"schema":"regulated/evidence-key/v1", "tenant":tenant,
                                   "type":key_type, "key":key})).digest()

def _leaf(key, value):
    return sha256(b"regulated/evidence-map/v2:leaf\x00" + key + sha256(value).digest()).digest()

def _branch(left, right):
    return sha256(b"regulated/evidence-map/v2:node\x00" + left + right).digest()

def _bit(key, depth):
    return (key[depth // 8] >> (7 - depth % 8)) & 1

def _prefix(a, b, depth):
    return int.from_bytes(a,"big") >> (256-depth) == int.from_bytes(b,"big") >> (256-depth)

@dataclass(frozen=True)
class MapProof:
    key: bytes
    value: bytes | None
    siblings: tuple[bytes, ...]
    other_key: bytes | None = None
    other_value: bytes | None = None

    def document(self):
        terminal = {"kind":"empty"}
        if self.value is not None or self.other_key is not None:
            key, value = (self.key,self.value) if self.value is not None else (self.other_key,self.other_value)
            terminal = {"kind":"leaf","key":key.hex(),"value":base64.b64encode(value).decode("ascii")}
        return {"schema":"regulated/evidence-map-proof/v2", "key":self.key.hex(),
                "depth":len(self.siblings),"siblings":[x.hex() for x in self.siblings],"terminal":terminal}

    def bytes(self):
        return canonical_bytes(self.document())

    @classmethod
    def from_bytes(cls, raw):
        try:
            if type(raw) is not bytes or len(raw)>65536: raise ValueError("proof size")
            d=loads(raw)
            if set(d)!={"schema","key","depth","siblings","terminal"} or d["schema"]!="regulated/evidence-map-proof/v2": raise ValueError("proof schema")
            if type(d["depth"]) is not int or not 0<=d["depth"]<=256 or type(d["siblings"]) is not list or len(d["siblings"])!=d["depth"]: raise ValueError("proof depth")
            def hx(v):
                if type(v) is not str or len(v)!=64 or any(c not in "0123456789abcdef" for c in v): raise ValueError("proof hash")
                return bytes.fromhex(v)
            key=hx(d["key"]);siblings=tuple(hx(x) for x in d["siblings"]);t=d["terminal"]
            if t=={"kind":"empty"}: p=cls(key,None,siblings)
            elif type(t) is dict and set(t)=={"kind","key","value"} and t["kind"]=="leaf":
                k=hx(t["key"]);v=base64.b64decode(t["value"],validate=True)
                if len(v)>MAX_VALUE:raise ValueError("leaf size")
                p=cls(key,v,siblings) if k==key else cls(key,None,siblings,k,v)
            else:raise ValueError("proof terminal")
            if p.bytes()!=raw:raise ValueError("noncanonical proof")
            return p
        except (ValueError,TypeError,KeyError,AttributeError) as e:
            raise ValueError("invalid map proof encoding") from e

@dataclass(frozen=True)
class MapNode:
    left: bytes | None = None
    right: bytes | None = None
    key: bytes | None = None
    value: bytes | None = None

def node_digest(node):
    if type(node) is not MapNode:raise ValueError("invalid map node")
    if node.key is not None:
        if not _digest(node.key) or type(node.value) is not bytes or len(node.value)>MAX_VALUE or node.left is not None or node.right is not None:raise ValueError("invalid map leaf")
        return _leaf(node.key,node.value)
    if not _digest(node.left) or not _digest(node.right) or node.value is not None or node.left==node.right==EMPTY_LEAF:raise ValueError("invalid map branch")
    return _branch(node.left,node.right)

def verify_map_proof(root, expected_key, proof):
    if not _digest(root) or not _digest(expected_key) or type(proof) is not MapProof:return False
    if not _digest(proof.key) or proof.key!=expected_key or type(proof.siblings) is not tuple or len(proof.siblings)>256 or any(not _digest(x) for x in proof.siblings):return False
    depth=len(proof.siblings)
    if proof.value is not None:
        if type(proof.value) is not bytes or len(proof.value)>MAX_VALUE or proof.other_key is not None or proof.other_value is not None:return False
        digest=_leaf(expected_key,proof.value)
    elif proof.other_key is not None:
        if not _digest(proof.other_key) or proof.other_key==expected_key or type(proof.other_value) is not bytes or len(proof.other_value)>MAX_VALUE or not _prefix(proof.other_key,expected_key,depth):return False
        digest=_leaf(proof.other_key,proof.other_value)
    else:
        if proof.other_value is not None:return False
        digest=EMPTY_LEAF
    if digest!=EMPTY_LEAF and depth and proof.siblings[-1]==EMPTY_LEAF:return False
    for i in range(depth-1,-1,-1):
        sibling=proof.siblings[i]
        if digest==sibling==EMPTY_LEAF:return False
        digest=_branch(sibling,digest) if _bit(expected_key,i) else _branch(digest,sibling)
    return digest==root

class MemorySparseMap:
    def __init__(self, reader=None):
        self.root=EMPTY_LEAF
        self._nodes={}
        self._reader=reader
        self.read_count=0

    def _read(self,digest,depth):
        self.read_count+=1
        try:node=self._nodes[digest]
        except KeyError:
            if self._reader is None:raise ValueError("missing map node")
            node=self._reader(digest)
        try: valid=node_digest(node)==digest and (node.key is not None or depth<256)
        except ValueError as exc: raise ValueError("corrupt map node") from exc
        if not valid: raise ValueError("corrupt map node")
        return node

    def prove(self,key,root=None):
        if not _digest(key):raise ValueError("invalid key")
        digest=self.root if root is None else root
        if not _digest(digest):raise ValueError("invalid root")
        siblings=[]
        while digest!=EMPTY_LEAF:
            depth=len(siblings);node=self._read(digest,depth)
            if node.key is not None:
                if not _prefix(node.key,key,depth):raise ValueError("misplaced leaf")
                p=MapProof(key,node.value,tuple(siblings)) if node.key==key else MapProof(key,None,tuple(siblings),node.key,node.value)
                break
            if _bit(key,depth):siblings.append(node.left);digest=node.right
            else:siblings.append(node.right);digest=node.left
        else:p=MapProof(key,None,tuple(siblings))
        if not verify_map_proof(self.root if root is None else root,key,p):raise ValueError("noncanonical map path")
        return p

    def _put(self,node):
        digest=node_digest(node)
        old=self._nodes.get(digest)
        if old is not None and old!=node:raise ValueError("content-address collision")
        self._nodes[digest]=node
        return digest

    def update(self,key,value):
        if type(value) is not bytes or len(value)>MAX_VALUE:raise ValueError("map value exceeds512 bytes")
        proof=self.prove(key);depth=len(proof.siblings)
        digest=self._put(MapNode(key=key,value=value))
        if proof.other_key is not None:
            split=depth
            while split<256 and _bit(key,split)==_bit(proof.other_key,split):split+=1
            if split==256:raise ValueError("duplicate key")
            old=_leaf(proof.other_key,proof.other_value)
            digest=self._put(MapNode(left=old,right=digest) if _bit(key,split) else MapNode(left=digest,right=old))
            for i in range(split-1,depth-1,-1):
                digest=self._put(MapNode(left=EMPTY_LEAF,right=digest) if _bit(key,i) else MapNode(left=digest,right=EMPTY_LEAF))
        for i in range(depth-1,-1,-1):
            sibling=proof.siblings[i]
            digest=self._put(MapNode(left=sibling,right=digest) if _bit(key,i) else MapNode(left=digest,right=sibling))
        self.root=digest
        return digest
