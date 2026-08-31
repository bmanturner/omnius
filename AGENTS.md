# Agent Instructions

## Build artifact cleanup

When you build anything solely for testing or verification and it writes artifacts under `target/`, delete those generated artifacts after verification completes. Do not leave temporary test or verification builds in `target/`.

## Documentation maintenance

When changing code, keep all affected documentation current in the same change. Update or remove stale documentation as behavior, APIs, configuration, workflows, or operational requirements evolve.
