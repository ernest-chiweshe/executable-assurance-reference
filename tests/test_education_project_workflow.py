"""Unchanged Project OS preparation/review/release over restricted durable state."""

from dataclasses import replace
from pathlib import Path

from assurance_reference.education_workflow import compose_education_workflow
from test_education_session_release import education  # noqa: F401

# Imported pytest fixture and arguments intentionally share their name.
# ruff: noqa: F811


def test_prepared_project_release_survives_reconstruction_and_never_rerenders(education):
    app = education
    renders = []
    def render(contract, destination):
        renders.append(destination)
        assert Path(destination) != app.path
        Path(destination).write_bytes(contract["body"].encode())
        return destination
    def state_store():
        return compose_education_workflow(app, renderer=render)[0]
    def protocol():
        return compose_education_workflow(app, renderer=render)[1]
    state = state_store()
    state.create("geometry", {"contract": app.contract})
    release = protocol()
    context = replace(app.context, release_target=str(app.path))
    prepared = release.contract("geometry", tenant="school-a", context=context)
    contract = prepared.for_approval()
    assert prepared.prepared.content == app.body
    opened = app.gates["requester"].open_review(spec=app.spec, contract=contract, context=context)
    assert opened["minimum_approvers"] == 2
    for principal, role in (("teacher", "teacher"), ("head", "head-of-department")):
        review = app.gates[principal].grant_review(spec=app.spec, contract=contract,
            context=replace(context, actor_id=principal, now_us=app.clock.now_us()),
            review_id=opened["review_id"], role=role)
    assert review["status"] == "approved"
    context = replace(context, approval=opened["review_id"])
    assert release.release("geometry", str(app.path), context) == str(app.path.resolve())
    assert app.path.read_bytes() == app.body
    saved = state_store().load("geometry")
    assert len(saved["emissions"]) == 1
    assert saved["emissions"][0]["allowed"] is True
    assert saved["emissions"][0]["decision_record_hash"]
    assert saved["release_outcomes"][-1]["state"] == "committed"
    first_write = app.path.stat().st_mtime_ns
    rebuilt = protocol()
    assert rebuilt.release("geometry", str(app.path), context) == str(app.path.resolve())
    assert app.path.stat().st_mtime_ns == first_write
    assert len(renders) == 1
    assert len(state_store().load("geometry")["emissions"]) == 1
    observation = rebuilt.observe("geometry", str(app.path), context)
    assert observation.outcome.state == "committed"
    assert app.stores.recorder.verify_chain("school-a")
