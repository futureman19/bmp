"""Isolate ordering and closure from cryptography and wire serialization."""
from itertools import permutations

import pytest

from agent_evidence import evaluator


@pytest.mark.parametrize('order', list(permutations('GAB')))
def test_shared_included_parent(order):
    sources = {'G': ('external',), 'A': ('G',), 'B': ('G',), 'S': ('A', 'B', 'A')}
    graph = {key: sources[key] for key in (*order, 'S')}
    assert evaluator._valid_ancestry(graph, 'S') == (order[0] == 'G')


def test_unrelated_entry():
    assert not evaluator._valid_ancestry({'U': (), 'A': (), 'S': ('A',)}, 'S')
