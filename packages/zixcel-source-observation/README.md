# zixcel-source-observation

Observe explicitly selected local folders and spreadsheet documents through a bounded read interface.

## What you can do

- Inspect a permitted folder.
- Read supported workbook structure while retaining source references.

## Current scope

Only the registered area is eligible. The observer does not modify source documents.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
