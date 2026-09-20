import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from singular import keys  # noqa: E402
from singular.agent import init_agent  # noqa: E402
from singular.keys import SigningKey  # noqa: E402
from singular.ledger.chain import Chain  # noqa: E402
from singular.ledger.client import LocalLedger  # noqa: E402

PASS = "correct horse battery staple"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    # Full-cost scrypt is exercised once in test_keys; everywhere else keep the suite quick.
    monkeypatch.setattr(keys, "_SCRYPT_N", 2**14)


@pytest.fixture
def chain(tmp_path):
    c = Chain.create(tmp_path / "chain.db", "test", SigningKey.generate())
    yield c
    c.close()


@pytest.fixture
def ledger(chain):
    return LocalLedger(chain)


@pytest.fixture
def owner():
    return SigningKey.generate()


def make_home(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "SOUL.md").write_text("You are Ada, a contracts assistant.\n")
    (path / "skills" / "review").mkdir(parents=True)
    (path / "skills" / "review" / "SKILL.md").write_text("# review\nRead the contract twice.\n")
    (path / "memories").mkdir()
    (path / "memories" / "MEMORY.md").write_text("- client prefers short answers\n")
    (path / ".env").write_text("OPENAI_API_KEY=sk-secret\n")
    (path / "config.yaml").write_text("model: x\n")
    return path


@pytest.fixture
def agent(tmp_path, ledger, owner):
    home = make_home(tmp_path / "home")
    return init_agent(home, ledger, "local", owner, PASS, name="Ada", function="contracts assistant",
                      lease_ttl_ms=60_000)
