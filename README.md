# RedGNAT

**CART Addon for GNAT** — Safe Red Teaming Made Simple

RedGNAT is the controlled adversary-emulation arm of the GNAT-o-sphere. It ingests intelligence from GNAT and SandGNAT, turns that intelligence into scoped emulation scenarios, executes them under explicit safety controls, and feeds the resulting gaps back into GNAT as follow-up work.

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
