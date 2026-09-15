import pytest


def test_pacli_transition_import():
    with pytest.deprecated_call():
        import pacli

        assert pacli.__version__ is not None


def test_pacli_cli_import():
    from pacli.cli import cli

    assert callable(cli)
