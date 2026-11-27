def test_checked_transitions(tmp_path):
    from agent_state.vectors import artifacts, replay, ROOT
    import json
    one = artifacts()
    assert one == artifacts()
    for name, data in one.items():
        assert (ROOT / name).read_bytes() == data
        for case in json.loads(data)['cases']:
            replay(case, tmp_path / case['name'])
