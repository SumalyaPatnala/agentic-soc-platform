"""Application services coordinating models, tools, and agents.

Import the submodules directly (``from app.services.validation import build_report``).
Nothing is re-exported here because ``validation`` is runnable as
``python -m app.services.validation``, and importing it during package import would
make ``runpy`` load it twice.
"""
