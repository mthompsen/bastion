"""Measurement harness: corpora, labelled splits, metrics, and the bench runner.

Everything Bastion downloads for measurement lives in a cache outside the
repository (:func:`bastion.bench.cache.cache_root`); the repository commits
only pins, manifests, label tables, and small result summaries.
"""
