"""Deterministic investigation utilities over normalized evidence.

Nothing in this package infers, scores, or classifies. It establishes the facts that a
later reasoning layer will be asked to interpret.

Import the submodules directly::

    from app.investigation.correlation import group_by_user
    from app.investigation.timeline import sort_evidence

The submodules are deliberately not re-exported here: ``timeline`` is runnable as
``python -m app.investigation.timeline``, and importing it during package import would
make ``runpy`` load it twice.
"""
