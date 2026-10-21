"""Static installer contract: governed browser, pinned npm tools, no default no-sandbox."""

from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts/install-kali.sh"


def test_installer_installs_governed_browser_and_uses_root_venv():
    text = SCRIPT.read_text()
    assert 'VENV_DIR="${REDJOHN_VENV_DIR:-$REPO_ROOT/.venv}"' in text
    assert 'install -e "${ROOT_DIR}[browser]"' in text
    assert "playwright install --with-deps chromium" in text
    assert 'exec "$VENV_DIR/bin/$cmd_name"' in text


def test_installer_pins_npm_tools_and_does_not_enable_no_sandbox_by_default():
    text = SCRIPT.read_text()
    assert "@latest" not in text
    assert "agent-browser@0.26.0 @ast-grep/cli@0.51.0" in text
    assert "js-beautify@2.0.3 retire@6.1.0" in text
    assert "--ignore-scripts" in text
    assert "npm rebuild -g agent-browser @ast-grep/cli" in text
    assert 'if [ "\\${REDJOHN_LEGACY_BROWSER_NO_SANDBOX:-0}" = "1" ]; then' in text
