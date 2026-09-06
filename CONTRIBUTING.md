# Contributing to Veer

Thank you for helping improve Veer. Veer is a pre-alpha control-plane project,
so contributors should expect contracts and implementation details to evolve
through reviewed issues and pull requests.

## Before you start

- Search the issue tracker and existing pull requests before proposing work.
- Use or open an issue that states the outcome, acceptance criteria, and
  evidence expected from the change.
- Do not include credentials, private data, exploit details, generated auth
  state, or proprietary source material in issues, commits, or test fixtures.
- Report suspected vulnerabilities through the private process in
  [SECURITY.md](SECURITY.md), not through a public issue or pull request.

## Developer Certificate of Origin

Veer uses the [Developer Certificate of Origin 1.1][dco] instead of a
Contributor License Agreement. By contributing, you certify the DCO terms for
each contribution.

Every commit in a pull request requires an author-matching `Signed-off-by` trailer.

```text
Signed-off-by: Your Name <your.email@example.com>
```

Create the trailer with Git's sign-off option:

```sh
git commit --signoff
```

A sign-off records the contributor's certification; it is not a copyright
assignment. DCO CI checks every commit in the pull-request range. If a commit
is missing or has a mismatched trailer, amend or rebase that commit and update
the branch. Do not add a sign-off for another person unless they personally
made the certification.

## Development workflow

1. Create one focused branch for one issue from current `main`.
2. Make the smallest cohesive change that satisfies the issue's complete
   acceptance criteria without overstating implemented behavior.
3. Add focused regression tests for changed behavior and negative tests for
   failure boundaries.
4. Run the reproducible local gate:

   ```sh
   ./hack/dev bootstrap
   ./hack/dev check
   ```

5. Commit with `--signoff`, push the branch, and open a pull request that links
   the issue and reports exact validation evidence.

The local gate uses deterministic repository-local tools and must not require
cloud credentials, administrator access, paid services, or live provider
calls. See [docs/development.md](docs/development.md) for the complete command
and isolation contract.

## Pull-request expectations

A pull request should:

- link its issue and address every applicable acceptance criterion;
- keep unrelated refactors and generated churn out of the change;
- state user-visible, security, operational, and cost effects;
- update documentation when setup, architecture, status, or limitations
  change;
- preserve Veer's distinction between reference contracts and executed,
  durable provider behavior; and
- resolve applicable review discussions before merge.

Maintainers merge only from a reviewed, validated head revision according to
[GOVERNANCE.md](GOVERNANCE.md). Passing tests are evidence for the behavior
they exercise, not proof of broader production readiness.

## License and community standards

Veer is licensed under the [Apache License 2.0](LICENSE), SPDX identifier
`Apache-2.0`. Contributions accepted into Veer are licensed under the same
terms. Participation is governed by the
[Contributor Covenant 2.1](CODE_OF_CONDUCT.md).

[dco]: https://developercertificate.org/
