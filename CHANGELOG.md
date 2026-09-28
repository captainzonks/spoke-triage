# Changelog

<!--
==============================================================================
CHANGELOG.md - Release history
==============================================================================
Description: Notable changes in each release, newest first
Author: Matt Barham
Created: 2026-09-27
Modified: 2026-09-27
Version: 0.4.0
==============================================================================
Document Type: Changelog
Audience: Operator, Module Developer
Status: Active (living document)
==============================================================================
-->

All notable changes to this project are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). What
counts as a breaking change for a Spoke module is defined in the Spoke hub's
ADR-029.

## [0.4.0] - 2026-09-28

### Fixed

- analyst: Claim the newest pending run, retire superseded ones (#3)
- analyst: Validate finding hashes, write atomically, select by window (#4)
- common: Normalize clock times and quoted paths with spaces (#5)
- deps: Bump sha2 0.10 -> 0.11 (#14)
- deps: Bump rand 0.8 -> 0.10 (#15)
- Keep secrets out of Config behind a redacting Secret type (ADR-026) (#17)
- analyst: Drop prompt caching (ADR-027) (#18)
- Put the collector behind its own egress guard (ADR-028) (#19)
