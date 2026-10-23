import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("PATCHPILOT_AI_PROVIDER", "none")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from app import db
    db.reset_for_tests(str(tmp_path / "test.db"))
    from app.main import app
    return TestClient(app)
