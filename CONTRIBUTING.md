# Contributing

Thanks for helping. Bug reports, questions about the design and pull requests
are all welcome. For security problems, don't open an issue: see
[SECURITY.md](SECURITY.md).

## Layout

- `src/`: the npm package (library and CLI), TypeScript, built into `dist/`.
- `python/`: the Python package, which only reads files.
- `test/`: Node tests; `test/vectors.json` holds test vectors shared by both
  implementations.
- `docs/DESIGN.md`: the file format; `docs/THREAT_MODEL.md`: what it protects.

## Building and testing

```sh
npm ci
npm test                      # builds, then runs every Node test

cd python
python -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest
```

The interoperability tests check the key wrapping against the reference `age`
CLI and are skipped when it isn't installed (`brew install age`,
`apt install age`). The ssh-agent tests need `ssh-agent` and `ssh-add` on the
`PATH`. CI runs everything on Linux, macOS and Windows.

## Changing the format or the parser

The file format is shared by two implementations, so a change to it starts in
`docs/DESIGN.md`, not in the code:

1. Open an issue describing the change and why it is needed.
2. Update `docs/DESIGN.md` (and `docs/THREAT_MODEL.md` if what is protected
   changes).
3. Change both implementations in the same pull request.
4. Regenerate the vectors with `npm run vectors` and commit `test/vectors.json`.
   The output is random, so the whole file changes; that's expected.

Parsing must stay identical to the `dotenv` npm package. `test/dotenv-compat.test.js`
compares the two on random input; add a case to `scripts/make-vectors.mjs` for
anything it finds.

## Pull requests

- One change per pull request, with tests that fail without it.
- Error messages say what went wrong and what to run to fix it.
- Never put real keys or secrets in tests, issues or logs. The tests generate
  their own keys.
- Update `CHANGELOG.md` under "Unreleased".
