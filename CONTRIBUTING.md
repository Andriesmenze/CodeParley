# Contributing

Thank you for your interest in CodeParley.

- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **Bugs and proposals:** open an issue first, with the version, platform and mode, and what you expected. For a change
  beyond a small fix, agree on the approach in the issue before writing it.

- **Pull requests:** outside pull requests are not accepted at present; please open an issue instead. CI runs only on
  commits signed with the maintainer's key, so it cannot test a pull request from another author yet. This will change
  once CI supports outside contributions.

## How changes are tested

CI runs only on commits signed with the maintainer's key (the **Commit identity** job, see
[docs/development.md](docs/development.md#ci)). Before proposing a change in an issue, or to try one locally, run the
checks yourself:

```bash
npm ci
npm run typecheck
npm run build
npm test
```

Run the custodian builds and self-tests too if you change `custodian/`. [docs/development.md](docs/development.md) has
the commands, the test classes and what CI does not cover.

## Guidelines

- Keep platform behaviour explicit: a test that does not apply to a platform skips and says so.
- Never edit the stores under `test/fixtures/compat/`: released versions wrote them, and the compatibility tests depend
  on their exact bytes.
- Never put credentials, real account names, machine paths or session data in code, tests, fixtures or commit messages.
  Use synthetic values.
- A change to what CodeParley claims or guarantees needs a matching change to [docs/security.md](docs/security.md).
- A new file that should ship in the npm package needs a deliberate change to `package.json` `files` and to the content
  policy in `scripts/package/lib/policy.mjs`.

## Licence

CodeParley is licensed under the [Apache License 2.0](LICENSE). Under its section 5, a contribution you submit is
licensed under the same terms, unless you state otherwise.
