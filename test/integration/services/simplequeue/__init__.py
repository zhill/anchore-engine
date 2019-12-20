"""
Integration test for lease handling subsystem. Requires a running postgres database.
"""

from concurrent.futures.thread import ThreadPoolExecutor
import time
import uuid
import pytest
from test.fixtures import anchore_db

from anchore_engine.db import db_locks, session_scope, Lease
from anchore_engine.subsys import logger
from anchore_engine.subsys.logger import enable_test_logging

enable_test_logging()


def test_list_queues():
    pass


def test_get_queue_msg():
    pass

def test_is_inqueue():
    pass


def performance_test_queue():
    pass


