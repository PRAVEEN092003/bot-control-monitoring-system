"""
tests/conftest.py — Shared pytest fixtures.

Clean test architecture:
- Function-scoped `app`: each test gets a fresh Flask application and app context
- Function-scoped `db`: drops and creates all tables cleanly for full DB isolation
- Function-scoped `client`: fresh test client with isolated cookies and session
"""

import pytest
from app import create_app
from config import TestingConfig
from extensions import db as _db


@pytest.fixture(scope="function")
def app():
    """Create a fresh Flask application and app context for each test."""
    test_app = create_app(TestingConfig)
    ctx = test_app.app_context()
    ctx.push()
    yield test_app
    ctx.pop()


@pytest.fixture(scope="function")
def db(app):
    """Provide a fresh database schema for each test."""
    _db.create_all()
    yield _db
    _db.session.remove()
    _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    """Provide a fresh HTTP test client for each test."""
    with app.test_client() as test_client:
        yield test_client
