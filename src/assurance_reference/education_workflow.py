"""Compose the unchanged Project OS protocol around an authenticated local host."""

from dataclasses import replace
from pathlib import Path

from assurance_reference.project_state import compose_project_state
from factory.ledger import FileArtifactStore
from factory.projectos.governed_release import GovernedRelease


def compose_education_workflow(app, *, renderer=None):
    """Return restricted choreography state and the governed release protocol.

    The supplied app is a trusted host composition, never request data. The
    optional renderer is a host dependency; its output is prepared privately
    before approval and only the gate's receiver may perform the release.
    """
    state = compose_project_state(pool=app.roles.project_state, sessions=app.sessions,
        authenticated=app.identities["requester"], namespace="education")

    def render(contract, destination):
        if Path(destination).resolve() == app.path.resolve():
            raise ValueError("preparation cannot render directly to the release target")
        if renderer is not None:
            return renderer(contract, destination)
        Path(destination).write_bytes(contract["body"].encode())
        return destination

    def review_context(project, contract, context, saved):
        if hasattr(app, "scoped"):
            source = saved.get("source_material")
            if not isinstance(source, dict):
                raise ValueError("scoped Education requires retained project source material")
            return replace(context, now_us=app.clock.now_us(), retained_state=source)
        return replace(context, now_us=app.clock.now_us())

    protocol = GovernedRelease(spec=app.spec, gate=app.gates["requester"],
        build_contract=lambda saved, approved: saved["contract"], exporter=render,
        artifacts=FileArtifactStore(app.path.parent / "prepared-artifacts"), state=state,
        clock=lambda: app.clock.now_us() / 1_000_000,
        review_context=review_context)
    return state, protocol
