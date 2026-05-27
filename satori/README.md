# Satori Runtime Directory

This directory is for Satori runtime configuration and generated artifacts:

- `config.example.toml`
- `runs/`
- `cache/`
- `packets/`
- `jobs/`
- `reports/`
- `memory/`

The Rust implementation lives in:

```text
src/satori/
```

That module contains the CLI, pipeline, ingestion, analysis, graph, packet builders, `o3` client, job generation, validation, memory, and report code.
