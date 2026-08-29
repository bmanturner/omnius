---
spec_id: OMNIUS-TOOLS
title: Bundle Validation Tools
version: 0.1.0
status: informative
last_verified: 2026-08-23
---

# Bundle Validation Tools


## Generate

From the repository root:

```bash
cargo xtask specs generate
```

This deterministically regenerates the three complete-spec documents, their archive
manifests and checksum inventories, and the base Markdown document manifest. These
derived files must not be edited manually.

## Validate

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r specs/tools/requirements.txt
cargo xtask specs verify
python specs/tools/validate_bundle.py specs
python specs/tools/validate_web_feature_suite.py specs
python specs/tools/validate_llm_mcp_feature_suite.py specs
```

The validators check structured-file parsing, Markdown metadata, module/profile
schemas, dependency closure, provider slots, task cycles, acceptance and
recommendation references, source IDs, contract examples, unresolved placeholders,
and every generated archive byte count and checksum.
