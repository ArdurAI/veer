# Veer Governance

## Alpha governance model

Veer uses maintainer-led consensus during its alpha period. The model favors
clear ownership and rapid, reviewable decisions while the contributor and
maintainer community is still forming. It is expected to evolve as the project
and community mature.

ArdurAI is the project steward. During alpha, ArdurAI retains final authority
over tie-break decisions, releases, security embargoes, maintainer appointment
and removal, and changes to this governance model.

## Roles

### Contributors

Anyone participating through issues, documentation, code, design, testing, or
review is a contributor. Contributions must follow
[CONTRIBUTING.md](CONTRIBUTING.md), including the Developer Certificate of
Origin 1.1 sign-off requirement, and the
[Code of Conduct](CODE_OF_CONDUCT.md).

### Maintainers

Maintainers are trusted contributors authorized by ArdurAI to triage issues,
review changes, manage project operations, and merge work within their areas.
They are expected to apply the project's documented contracts consistently,
disclose conflicts of interest, protect embargoed reports, and distinguish
verified implementation from proposed direction.

Maintainers are appointed or removed by ArdurAI based on sustained technical
judgment, constructive participation, security awareness, and reliable
stewardship. Maintainer status is a responsibility, not an entitlement.

## Decision process

Routine decisions are made by consensus among the maintainers participating in
the relevant issue or pull request. Consensus means material objections have
been considered and resolved or explicitly documented; it does not require
unanimity or a formal vote.

Material architecture, compatibility, security, governance, release, and cost
decisions must be recorded in a public issue, pull request, or architecture
decision record with the alternatives and rationale. When consensus cannot be
reached in a reasonable time, ArdurAI decides the outcome and records the
reasoning.

A maintainer with a material personal or commercial conflict should disclose
it and recuse from the deciding approval. Security and conduct matters may use
restricted participation to protect reporters and affected people.

## Review and merge

Changes are merged only when their issue acceptance criteria are evidenced,
required CI is green for the exact head revision, and applicable review
discussions are resolved. Maintainers may require additional review for
security-sensitive, compatibility-sensitive, or high-blast-radius changes.
Urgency does not waive the documented security or correctness boundary.

## Releases and security embargoes

ArdurAI designates releases and the people authorized to publish them. A public
repository state is not itself a release commitment or support guarantee.

Reports made under [SECURITY.md](SECURITY.md) may be discussed and fixed under
a private embargo. ArdurAI determines the embargo participants, coordinated
disclosure timing, and release response after considering reporter input and
user risk. Embargoed information must not be copied into public project
channels before coordinated disclosure.

## Transparency and amendments

Project decisions and their rationale are public by default. Security reports,
conduct reports, personal data, credentials, and legally restricted material
are exceptions and remain limited to people who need access.

Governance changes require a public proposal and explicit ArdurAI approval
during alpha. The approved change and its rationale must be committed to this
file before it takes effect.

Veer is licensed under the [Apache License 2.0](LICENSE), SPDX identifier
`Apache-2.0`.
