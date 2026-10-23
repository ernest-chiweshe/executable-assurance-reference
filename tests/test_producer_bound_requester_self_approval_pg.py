"""Requester self-approval where the review carries a server-derived producer identity (product vertical).

The inherited exchange opens the approval request with ``requester_id = review_producer_id or record.actor_id``
(frozen approval_exchange.py:140, unchanged). The product vertical sets a producer identity, so the human who
opened the review is not the request's requester_id. The signed policy forbids requester approval; this test
shows it is enforced at grant on the actual path: a requester self-grant, even when certified for the role, is
refused, the review stays awaiting, and no release follows. Fictional people; isolated PostgreSQL; actual restricted logins.
"""
from dataclasses import replace

import pytest

from regulated_core.approval_evidence import ReviewError
from test_product_spec_authority import product, roles  # noqa: F401


def test_requester_cannot_self_approve_a_producer_bound_review(product):  # noqa: F811
    c = product
    c.certify("requester", "reviewer")
    contract = c.engine.governed_contract("inventory", tenant=c.tenant, context=c.context)
    opened = c.engine.open_review("inventory", context=c.context)
    with pytest.raises(ReviewError):
        c.gates["requester"].grant_review(spec=c.spec, contract=contract,
            context=replace(c.context, now_us=c.clock.now_us()), review_id=opened["review_id"], role="reviewer")
    state = c.gates["requester"].get_review(spec=c.spec, contract=contract,
        context=replace(c.context, now_us=c.clock.now_us()), review_id=opened["review_id"])
    assert state["status"] == "awaiting-review"
    with pytest.raises(Exception):  # noqa: B017 - any refusal; the safety property is checked below
        c.engine.release("inventory", str(c.path), context=replace(c.context, approval=opened["review_id"]))
    assert not c.path.exists()
