---
spec_id: OMNIUS-WEB-TOOLS
title: Web Feature Suite Validation Tool
version: 0.1.0
status: normative
last_verified: 2026-08-24
---

# Web Feature Suite Validation Tool

Run from the combined specification directory after extracting the extension:

```bash
python tools/validate_web_feature_suite.py .
```

The validator requires Python 3.11 or later plus the same `PyYAML` and `jsonschema` dependencies used by the base bundle validator.

It checks:

- Base bundle version and required files.
- Parsing of JSON, YAML, and TOML.
- Markdown frontmatter and unique specification IDs.
- Extension path collision against the original bundle manifest.
- Base plus extension module/profile JSON Schema validation.
- Module dependencies, conflicts, provider slots, and profile inheritance.
- Base plus extension task references and cycles.
- Acceptance and recommendation references.
- Frontend exposure coverage for every module.
- Extension-specific schemas and examples.
- Research source references.
- Prohibited unresolved drafting markers.
- Extension manifest hashes.

It does not compile Rust or TypeScript, install packages, run browsers, or prove runtime acceptance criteria. Those are implementation tasks.
