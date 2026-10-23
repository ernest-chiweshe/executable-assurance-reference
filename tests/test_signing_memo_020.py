"""Exact cryptographic memo tests; policy and mutable inputs are never memoized."""
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import pytest
from regulated_core.signing import (
    Ed25519Signer, EcdsaP384Signer, TrustDirectory, Signature,
    _verify_ed25519_exact, _load_public_key, ALG_ED25519,
)

@pytest.fixture(autouse=True)
def clear_memo():
    _verify_ed25519_exact.cache_clear()
    yield
    _verify_ed25519_exact.cache_clear()

def setup():
    signer = Ed25519Signer("one")
    trust = TrustDirectory()
    trust.register_signer(signer)
    data = b"exact signed message"
    return signer, trust, data, signer.sign_bytes(data)

def test_repeated_exact_signature_reuses_only_crypto():
    signer, trust, data, sig = setup()
    assert trust.verify_bytes(data, sig)
    assert trust.verify_registered_bytes(data, sig.key_id, sig.value)
    assert _verify_ed25519_exact.cache_info().hits == 1
    assert not trust.verify_bytes(data, replace(sig, key_id="unknown"))
    assert not trust.verify_bytes(data, replace(sig, alg="unknown"))
    assert _verify_ed25519_exact.cache_info().hits == 1

@pytest.mark.parametrize("change", ["message", "signature", "key"])
def test_each_exact_component_is_bound_and_failure_not_cached(change):
    signer, trust, data, sig = setup()
    assert trust.verify_bytes(data, sig)
    if change == "message":
        data += b"!"
    elif change == "signature":
        raw = bytearray.fromhex(sig.value); raw[0] ^= 1
        sig = replace(sig, value=raw.hex())
    else:
        other = Ed25519Signer("one")
        # Simulate directory key replacement; every call must resolve it afresh.
        trust._keys["one"] = (ALG_ED25519, _load_public_key(ALG_ED25519, other.public_key_bytes))
    for _ in range(2):
        assert not trust.verify_bytes(data, sig)
    assert _verify_ed25519_exact.cache_info().currsize == 1
    assert _verify_ed25519_exact.cache_info().hits == 0

def test_mutable_payload_is_reencoded_each_call():
    signer, trust, _, _ = setup()
    payload = {"nested": [1]}
    sig = signer.sign(payload)
    assert trust.verify(payload, sig)
    payload["nested"].append(2)
    assert not trust.verify(payload, sig)

def test_oversized_messages_and_other_algorithms_bypass_memo():
    signer, trust, _, _ = setup()
    data = b"x" * 16385
    sig = signer.sign_bytes(data)
    assert trust.verify_bytes(data, sig)
    other = EcdsaP384Signer("p384"); trust.register_signer(other)
    assert trust.verify_bytes(b"small", other.sign_bytes(b"small"))
    assert _verify_ed25519_exact.cache_info().currsize == 0

def test_bounded_eviction_revalidates_successfully():
    signer, trust, data, sig = setup()
    assert trust.verify_bytes(data, sig)
    for i in range(1025):
        raw = str(i).encode()
        assert trust.verify_bytes(raw, signer.sign_bytes(raw))
    assert _verify_ed25519_exact.cache_info().currsize == 1024
    misses = _verify_ed25519_exact.cache_info().misses
    assert trust.verify_bytes(data, sig)
    assert _verify_ed25519_exact.cache_info().misses == misses + 1

def test_concurrent_successes_and_invalid_signatures():
    signer, trust, data, sig = setup()
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(pool.map(lambda _: trust.verify_bytes(data, sig), range(100)))
        assert not any(pool.map(lambda _: trust.verify_bytes(data+b"!", sig), range(100)))
    assert _verify_ed25519_exact.cache_info().currsize == 1
