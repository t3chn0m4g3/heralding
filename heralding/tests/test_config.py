from importlib import resources

import yaml


def test_default_config_is_valid_yaml():
    text = resources.files("heralding").joinpath("heralding.yml").read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    assert "capabilities" in config
