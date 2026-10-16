"""Kafka streaming helpers.

Import the submodules directly. Nothing is re-exported here because producer and
consumer modules are runnable as ``python -m``, and importing them during package
import would make ``runpy`` load them twice.
"""
