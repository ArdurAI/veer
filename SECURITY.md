# Security Policy

## Supported versions

Veer is pre-alpha and has no supported release series yet.

| Version | Supported |
| --- | --- |
| Current `main` | Yes, on a best-effort pre-alpha basis |
| Tags, forks, and historical commits | No |

This table describes the vulnerability-response scope. It does not claim that
`main` is production ready or that its APIs, storage formats, or deployment
topology are stable.

## Report a vulnerability privately

Do not open a public issue, discussion, or pull request for a suspected
vulnerability. Public disclosure can put users at risk before a fix exists.
You are not required to create a public issue before reporting privately.

Use one of these confidential channels:

1. Submit a [private GitHub vulnerability report][private-report]. This is the
   primary channel and keeps discussion and any temporary fix private.
2. If GitHub private reporting is unavailable, email the monitored ArdurAI role
   address [info@ardur.ai](mailto:info@ardur.ai).

Include the affected revision, impact, prerequisites, reproduction steps, and
any suggested mitigation. Do not send production credentials, access tokens,
private customer data, or unrelated personal information. If sensitive
artifacts are necessary, first ask through the private channel how to transfer
them safely.

Conduct concerns are handled separately under
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), using the same monitored role
address.

## Response targets

ArdurAI targets:

- acknowledgment within two business days;
- an initial severity and scope assessment within five business days; and
- a status update at least every seven calendar days while active remediation
  is underway.

These are response targets, not a resolution guarantee. Remediation timing
depends on severity, exploitability, affected users, fix complexity, and the
need for coordinated releases.

## Coordinated disclosure

Please keep the report and remediation details private until ArdurAI and the
reporter agree on disclosure or a fix is available. ArdurAI will validate the
report, develop and test a fix, assess affected versions, prepare release and
upgrade guidance when applicable, and coordinate public credit with the
reporter unless anonymity is requested.

ArdurAI may accelerate disclosure when active exploitation creates material
user risk, or delay it when additional time is necessary to protect users. The
reasoning will be shared with the reporter through the private channel.

## Good-faith research

Use test environments and data you are authorized to access. Avoid privacy
violations, service disruption, destructive testing, social engineering, and
accessing or retaining data beyond what is necessary to demonstrate impact.
Stop testing and report immediately if you encounter sensitive data or create
a risk to other users.

[private-report]: https://github.com/ArdurAI/veer/security/advisories/new
