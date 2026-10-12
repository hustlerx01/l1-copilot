import pathlib, yaml
def test_sigma_rules_parse():
    rules = list((pathlib.Path(__file__).resolve().parents[1] / "sigma").glob("*.yml"))
    assert len(rules) == 3
    for r in rules:
        d = yaml.safe_load(r.read_text())
        assert {"title", "id", "logsource", "detection", "level"} <= d.keys()
        assert any(t.startswith("attack.t") for t in d["tags"])
