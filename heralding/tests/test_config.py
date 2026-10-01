from importlib import resources
from pathlib import Path

import yaml

FIXTURES = Path(__file__).parent / "fixtures"


def test_default_config_is_valid_yaml():
    text = resources.files("heralding").joinpath("heralding.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    assert "capabilities" in config


def test_tpot_config_fixture_loads():
    config = yaml.safe_load((FIXTURES / "tpot_heralding.yml").read_text(encoding="utf-8"))
    # T-Pot ships the literal string "None" for unset certificate fields
    assert config["capabilities"]["pop3s"]["protocol_specific_data"]["cert"]["state"] == "None"
