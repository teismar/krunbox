"""
Unit tests for port management and dynamic SSH tunneling.
"""

import socket
import pytest
from krunbox.core.ports import is_port_in_use, find_free_port, parse_port_spec
from krunbox.core.sandbox import PortMapping

def test_is_port_in_use():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert is_port_in_use(port) is True
    finally:
        s.close()
    assert is_port_in_use(port) is False

def test_find_free_port():
    p = find_free_port(start_port=21000)
    assert 21000 <= p < 65535
    assert not is_port_in_use(p)

def test_find_free_port_avoid():
    p1 = find_free_port(start_port=21000)
    p2 = find_free_port(start_port=21000, avoid={p1})
    assert p2 != p1

def test_parse_port_spec_single():
    mapping = parse_port_spec("3000")
    assert isinstance(mapping, PortMapping)
    assert mapping.guest_port == 3000
    assert mapping.host_port >= 3000

def test_parse_port_spec_pair():
    mapping = parse_port_spec("8080:80")
    assert mapping.host_port == 8080
    assert mapping.guest_port == 80

def test_parse_port_spec_with_ip():
    mapping = parse_port_spec("127.0.0.1:9000:90")
    assert mapping.host_port == 9000
    assert mapping.guest_port == 90

def test_parse_port_spec_invalid():
    with pytest.raises(ValueError):
        parse_port_spec("1:2:3:4")
