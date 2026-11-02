# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

Report a suspected vulnerability privately, through GitHub's private vulnerability reporting for this repository:
the **Security** tab, then **Report a vulnerability**. Do not open a public issue, pull request or discussion for it.

Please include:

- the CodeParley version, the platform (Windows 11 or Ubuntu 24.04) and the mode (manual review or the protected loop);
- what the attacker controls: the implementer's session, the reviewed repository's content, a local account, the
  network;
- the steps to reproduce, and what you observed against what [docs/security.md](docs/security.md) says should happen.

There is no bug bounty. Reports are handled on a best-effort basis.

## Scope

[docs/security.md](docs/security.md) states the security claim, the trust model and every known limit. A documented
limit is not a vulnerability in itself; a way past one, or a way around a guarantee it states, is. Examples:

- model-controlled input that creates operator authority, a loop grant, a budget, a decision or a fix confirmation;
- a write to the working tree by a review, or a delegated fix applied without the operator's confirmation of its
  exact content;
- reviewer access beyond the sanitized, read-only snapshot, or content excluded as confidential reaching Codex;
- a protected request the custodian accepts when it should fail closed, or a change to the custodian's store from the
  implementer account;
- a completion state reported that the recorded evidence does not support.

## Release integrity

Each release's manifest is signed with the project's release key.
[docs/verifying-releases.md](docs/verifying-releases.md) has the key's fingerprint and the verification steps.
