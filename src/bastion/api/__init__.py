"""Bastion's local JSON API (START_PROMPT section 8 item 7): FastAPI, bound to 127.0.0.1 only.

The contract is ``docs/api/openapi.json``, generated from :func:`create_app` and checked by
the tests, so the committed document and the code cannot drift apart.
"""

from bastion.api.app import API_HOST, DEFAULT_PORT, create_app, openapi_document

__all__ = ["API_HOST", "DEFAULT_PORT", "create_app", "openapi_document"]
