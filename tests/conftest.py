"""Lets the tests import the backend code. Run inside Docker:  docker compose exec backend python -m pytest tests -q"""
import os
import sys

BACKEND = os.path.join(os.path.dirname(__file__), "..", "backend")
sys.path.insert(0, BACKEND if os.path.isdir(BACKEND) else "/app")
