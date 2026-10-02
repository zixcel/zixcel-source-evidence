# Using zixcel-source-evidence

Index source observations and query evidence tied to a specific source revision.

## Before you start

This is a source-evidence implementation. Complete semantic resolution and effect inference remain outside its current guarantees.

## First steps

Run from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## How to assess the result

- Create and inspect a local source index.
- Resolve bounded evidence queries to retained source references.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
