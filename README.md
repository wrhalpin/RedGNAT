<p align="center">
  <img src="assets/logo/readme-banner.png" alt="RedGNAT" width="800">
</p>

<p align="center">
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License Apache 2.0"></a>
  <a href="https://github.com/wrhalpin/RedGNAT/actions/workflows/pylint.yml"><img src="https://github.com/wrhalpin/RedGNAT/actions/workflows/pylint.yml/badge.svg" alt="Pylint"></a>
  <a href="https://github.com/wrhalpin/RedGNAT/actions/workflows/python-tests.yml"><img src="https://github.com/wrhalpin/RedGNAT/actions/workflows/python-tests.yml/badge.svg" alt="Tests"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/coverage-%E2%89%A570%25-green" alt="Coverage ≥70%"></a>
  <a href="https://oasis-open.github.io/cti-documentation/stix/intro"><img src="https://img.shields.io/badge/STIX-2.1-blueviolet" alt="STIX 2.1"></a>
</p>

---

**Continuous Automated Red Teaming (CART) addon for the GNAT-o-sphere.** RedGNAT ingests live threat intelligence from GNAT and SandGNAT, builds scoped adversary-emulation scenarios, executes them under layered safety controls, and feeds detection gaps back into GNAT as structured intelligence requirements.

**[Documentation](https://wrhalpin.github.io/RedGNAT/)** · **[GNAT](https://github.com/wrhalpin/GNAT)** · **[SandGNAT](https://github.com/wrhalpin/SandGNAT)**

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp config/config.ini.example redgnat.ini
# edit redgnat.ini — set db_url, redis_url, gnat config_path
docker compose up -d
make migrate
make worker &
make api
```

See the [getting-started tutorial](docs/tutorials/getting-started.md) for the full walkthrough.

## License

Apache 2.0.
