# ADR-0001: Three-layer architecture with pure core

Status: Accepted
Date: 2026-05-24

## Context

scanner/scanner.py grew into a monolith. Every test required the full scan
pipeline, making the test suite slow and discouraging test-first development.

## Decision

Three-layer architecture:
- scanner/core/   — PURE, no I/O, tests in milliseconds
- scanner/engines/ — IMPURE, subprocess/network/file allowed
- scanner/cli/    — BOUNDARY, user input/output only

scanner/core/ functions accept and return primitive Python types.
They never raise I/O exceptions.

## Consequences

Positive: unit tests for core/ run < 100ms per file.
Negative: scanner/scanner.py must be incrementally hollowed out.

## Alternatives rejected

Single-file: fast to start, impossible to test in isolation.
Class-based pipeline: adds complexity without depth.
