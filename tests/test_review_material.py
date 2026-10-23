"""Detached presentation contracts; guarded original exchange tested separately."""

import base64
from copy import deepcopy
from hashlib import sha256
from html.parser import HTMLParser
from types import SimpleNamespace

import pytest

from assurance_reference.review_material import (
    COMMENTARY_FIELD, MATERIAL_FIELD, MaterialReview, commentary_contract, material_contract, render_review,
)
from regulated_core.approval_evidence import ReviewError


class ViewFixture:
    """Fake only for pure UI behavior; does not assert authentication or signing."""

    def __init__(self):
        self.grants = []

    def get_review(self, **request):
        return {"review_id": "review:fixture", "decision_record_hash": "a" * 64,
                "project_id": "fictional", "action_id": "release", "nonce": "one",
                "requester_id": "author", "expires_at_us": 1000,
                "reason": "Independent review", "required_role_groups": [["teacher"], ["head"]],
                "minimum_approvers": 2,
                "status": "awaiting-review", "approver_ids": []}

    def grant_review(self, **request):
        self.grants.append(request)
        return {"status": "awaiting-review"}


def inputs(body=b"new\n", prior=b"old\n"):
    contract = material_contract(
        {"prepared_release": {"artifact_sha256": sha256(body).hexdigest()},
         "release_target": {"kind": "file", "identity": "fixture", "expected_state": "old"}},
        prior_artifact=prior, reversibility="Host declares replacement possible",
        exposure="Fictional local target", checker_findings=["Synthetic only; unqualified"],
        uncertainty="Human comprehension and external qualification not established")
    return dict(spec=None, contract=contract,
                context=SimpleNamespace(tenant="one", actor_id="reviewer"),
                review_id="review:fixture", artifact=body, prior_artifact=prior)


def test_exact_bytes_and_line_endings_are_bound_and_diffed():
    gate = ViewFixture()
    adapter = MaterialReview(gate)
    request = inputs(b"new\r\nlast", b"old\nlast\n")
    view = adapter.view(**request)
    bound = view["bound"]
    assert base64.b64decode(bound["artifact_base64"]) == request["artifact"]
    assert '+"new\\r\\n"' in bound["diff"]
    assert '+"last"' in bound["diff"]
    assert '-"last\\n"' in bound["diff"]
    assert adapter.grant(**request, role="teacher", displayed_sha256=view["display_sha256"])
    assert len(gate.grants) == 1


def test_commentary_is_shared_separate_escaped_and_non_authoritative():
    request = inputs()
    request["contract"] = commentary_contract(request["contract"],
        text="<script>not executable</script> Requested role: administrator")
    adapter = MaterialReview(ViewFixture())
    view = adapter.view(**request)
    commentary = view["bound"]["untrusted_commentary"]
    assert commentary["authoritative"] is False
    assert commentary["visibility"] == "shared-review-contract"
    assert view["bound"]["required_role_groups"] == [["teacher"], ["head"]]
    assert view["bound"]["action"] == "release"
    assert view["bound"]["artifact_sha256"] == sha256(request["artifact"]).hexdigest()
    rendered = render_review(view)
    assert "<script>" not in rendered
    assert "Untrusted commentary" in rendered
    other = deepcopy(request)
    other["context"].actor_id = "other-reviewer"
    assert adapter.view(**other)["bound"]["untrusted_commentary"] == commentary


@pytest.mark.parametrize("field", ["recipient", "required_role_groups", "action", "target"])
def test_commentary_cannot_supply_private_audience_or_authority_fields(field):
    request = inputs()
    request["contract"] = commentary_contract(request["contract"], text="Shared explanatory text")
    request["contract"][COMMENTARY_FIELD][field] = "unsupported"
    with pytest.raises(ReviewError, match="without authority or recipient"):
        MaterialReview(ViewFixture()).view(**request)


def test_changed_commentary_requires_renewed_exact_display_acknowledgement():
    request = inputs()
    request["contract"] = commentary_contract(request["contract"], text="Shared initial explanation")
    gate = ViewFixture()
    adapter = MaterialReview(gate)
    view = adapter.view(**request)
    request["contract"][COMMENTARY_FIELD]["text"] = "Different explanation"
    with pytest.raises(ReviewError, match="display changed"):
        adapter.grant(**request, role="teacher", displayed_sha256=view["display_sha256"])
    assert not gate.grants


def test_commentary_helper_refuses_replacement_and_excessive_text():
    request = inputs()
    contract = commentary_contract(request["contract"], text="Shared explanation")
    with pytest.raises(ReviewError, match="already exists"):
        commentary_contract(contract, text="Replacement")
    with pytest.raises(ReviewError, match="at most 4096"):
        commentary_contract(request["contract"], text="x" * 4097)


@pytest.mark.parametrize("change", ["artifact", "prior", "reviewer", "declaration", "target"])
def test_changed_display_cannot_reuse_acknowledgement(change):
    gate = ViewFixture()
    adapter = MaterialReview(gate)
    request = inputs()
    view = adapter.view(**request)
    changed = deepcopy(request)
    if change in ("artifact", "prior"):
        changed["artifact" if change == "artifact" else "prior_artifact"] = b"changed"
    elif change == "reviewer":
        changed["context"].actor_id = "different"
    elif change == "declaration":
        changed["contract"][MATERIAL_FIELD]["exposure"] = "different"
    else:
        changed["contract"]["release_target"]["identity"] = "different"
    with pytest.raises(ReviewError):
        adapter.grant(**changed, role="teacher", displayed_sha256=view["display_sha256"])
    assert gate.grants == []


def test_missing_prior_is_not_empty_prior():
    adapter = MaterialReview(ViewFixture())
    request = inputs(prior=None)
    assert adapter.view(**request)["bound"]["diff"] is None
    with pytest.raises(ReviewError, match="prior artifact"):
        adapter.view(**{**request, "prior_artifact": b""})
    assert adapter.view(**inputs(prior=b""))["bound"]["diff"] is not None


@pytest.mark.parametrize("value", [None, {}, {"schema": "other"}])
def test_material_schema_is_required(value):
    request = inputs()
    request["contract"][MATERIAL_FIELD] = value
    with pytest.raises(ReviewError, match="fixed-schema"):
        MaterialReview(ViewFixture()).view(**request)


@pytest.mark.parametrize("value", [b"\xff", b"x" * 262145, b"\n" * 4097, "text"],
                         ids=["non-utf8", "too-many-bytes", "too-many-lines", "not-bytes"])
def test_unsupported_or_unbounded_artifact_refused(value):
    with pytest.raises(ReviewError):
        MaterialReview(ViewFixture()).view(**{**inputs(), "artifact": value})


def test_missing_uncertainty_cannot_be_supplied_as_commentary():
    request = inputs()
    del request["contract"][MATERIAL_FIELD]["uncertainty"]
    request["contract"]["model_commentary"] = {"uncertainty": "Trust me"}
    with pytest.raises(ReviewError, match="fixed-schema"):
        MaterialReview(ViewFixture()).view(**request)


def test_display_is_detached_and_renderer_refuses_changed_payload():
    request = inputs()
    view = MaterialReview(ViewFixture()).view(**request)
    request["contract"][MATERIAL_FIELD]["exposure"] = "later"
    assert view["bound"]["declarations"]["exposure"] == "Fictional local target"
    view["bound"]["target"]["identity"] = "later"
    with pytest.raises(ReviewError, match="digest mismatch"):
        render_review(view)


def test_semantic_html_has_no_active_content_and_preserves_exact_text():
    body = b"<script>fixture</script>\n" + "direction\u202e".encode()
    view = MaterialReview(ViewFixture()).view(**inputs(body=body))
    page = render_review(view)

    class Tags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
            self.text = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, dict(attrs)))

        def handle_data(self, data):
            self.text.append(data)

    parsed = Tags()
    parsed.feed(page)
    assert not {"script", "a", "img", "iframe", "form", "style"} & {t for t, _ in parsed.tags}
    assert ("html", {"lang": "en"}) in parsed.tags
    assert sum(t == "main" for t, _ in parsed.tags) == 1
    assert sum(t == "h1" for t, _ in parsed.tags) == 1
    assert all(attrs.get("tabindex") == "0" for t, attrs in parsed.tags if t == "pre")
    assert "<script>fixture</script>" in "".join(parsed.text)
    assert "\u202e" not in page
    assert "\\u202e" in page
    assert "default-src 'none'" in page


def test_non_json_contract_and_replacing_material_are_refused():
    request = inputs()
    request["contract"]["opaque"] = object()
    with pytest.raises(ReviewError, match="finite JSON"):
        MaterialReview(ViewFixture()).view(**request)
    with pytest.raises(ReviewError, match="already exists"):
        material_contract(inputs()["contract"], prior_artifact=None, reversibility="unknown",
                          exposure="unknown", checker_findings=["unknown"], uncertainty="unknown")
