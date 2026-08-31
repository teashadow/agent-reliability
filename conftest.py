"""Repo-root conftest: put the monorepo root on sys.path.

CI runs the bare `pytest` binary (not `python -m pytest`), which does NOT add
the working directory to sys.path — so package-style imports of the
test_fixtures tree break under CI while passing locally. This conftest makes
the root importable no matter how pytest is invoked. The teeth gate must fail
for real reasons, not for import geography.
"""

import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
