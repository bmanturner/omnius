---
spec_id: RSK-TOOLS
title: Bundle Validation Tools
version: 0.1.0
status: informative
last_verified: 2026-08-23
---

# Bundle Validation Tools


## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r tools/requirements.txt
python tools/validate_bundle.py
```

The validator checks structured-file parsing, Markdown metadata, module/profile schemas, dependency closure, provider slots, task cycles, acceptance and recommendation references, source IDs, contract examples, and unresolved placeholders.

The implementation repository SHOULD port these checks into `cargo xtask specs verify`; the Python tool remains a portable specification-bundle check.
