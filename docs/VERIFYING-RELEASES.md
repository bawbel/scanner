# Verifying a release

Releases of `bawbel-scanner` are published to PyPI by the GitHub Actions workflow
`publish.yml` in this repository, and PyPI holds signed build provenance for the files
([PEP 740](https://peps.python.org/pep-0740/) attestations, signed through
[Sigstore](https://www.sigstore.dev/)). You can check a release file against it.

A pass tells you where the file came from. It does not tell you what the code does. See
[What a pass means](#what-a-pass-means-and-what-it-does-not).

---

## Check a release

```bash
pip install pypi-attestations
pypi-attestations verify pypi \
  --repository https://github.com/bawbel/scanner \
  pypi:bawbel_scanner-1.3.0-py3-none-any.whl
```

```text
OK: bawbel_scanner-1.3.0-py3-none-any.whl
```

The exit code is 0. The `pypi:` form downloads that file from PyPI, together with its provenance,
and checks them. The source distribution works the same way:
`pypi:bawbel_scanner-1.3.0.tar.gz`.

`--repository` is the repository you expect the file to have been published from. Always give it
yourself. The check passes only if the provenance names that repository.

## Check the file you already have

If you downloaded a file, or want to check what `pip` fetched, give the verifier the path. It
compares the file's digest with the one in the provenance.

```bash
pip download bawbel-scanner==1.3.0 --no-deps -d dl
pypi-attestations verify pypi \
  --repository https://github.com/bawbel/scanner \
  dl/bawbel_scanner-1.3.0-py3-none-any.whl
```

```text
OK: bawbel_scanner-1.3.0-py3-none-any.whl
```

## What a failure looks like

A file that was changed after it was published:

```text
Verification failed for bawbel_scanner-1.3.0-py3-none-any.whl: Verification failed: subject does not match distribution digest
```

The wrong repository:

```text
Verification failed: provenance was signed by repository "bawbel/scanner", expected "bawbel/gate"
```

Both exit with code 1. Do not install a file that fails.

## Look at the provenance yourself

PyPI serves it from its integrity endpoint:

```bash
curl -s -H "Accept: application/vnd.pypi.integrity.v1+json" \
  https://pypi.org/integrity/bawbel-scanner/1.3.0/bawbel_scanner-1.3.0-py3-none-any.whl/provenance \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print([b['publisher'] for b in d['attestation_bundles']])"
```

For 1.3.0 the publisher it names is GitHub, repository `bawbel/scanner`, workflow `publish.yml`,
environment `pypi`.

The `provenance` field of PyPI's JSON API (`https://pypi.org/pypi/bawbel-scanner/json`) is empty
for these files. That is not the place to look.

## What a pass means, and what it does not

A pass means:

- the file's digest is the one in an attestation that PyPI holds for it
- the attestation was signed with the identity of a GitHub Actions workflow of the repository you
  named
- so the file was published by that repository's workflow and has not changed since

A pass does not mean:

- that the code does what it says, or has no defects. It says nothing about the code
- that you reviewed the source the workflow built from
- that the repository's own access and workflow settings are what you would want

Provenance answers "did this come from where I think it did". It is one input to deciding whether
to run something, not the decision.

---

Output on this page is from `pypi-attestations` 0.0.31. Newer versions may word messages
differently. Report a problem with a release privately, as described in
[SECURITY.md](../SECURITY.md).
