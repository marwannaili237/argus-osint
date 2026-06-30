"""
Argus OSINT – App Re-export

Convenience module that re-exports the FastAPI app instance from main.py.
"""

from argus.main import app

__all__ = ["app"]
