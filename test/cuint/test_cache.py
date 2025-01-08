import pytest
from cuint import C
from cuint.cache import fact, hello

NULL = 0

def test_hello():
    assert hello(1) == 2

def test_fact():
    assert fact(6) == 720
    assert fact(0) == 1
    assert fact(-42) == 1 