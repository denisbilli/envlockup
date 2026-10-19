# Security policy

Please report vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://github.com/denisbilli/envlockup/security/advisories/new),
not in public issues.

Include what you found, how to reproduce it, and the versions affected (npm
package, Python package, or both). You should get a first answer within a week.
Once a fix is released, the advisory is published with credit to you, unless you
prefer otherwise.

## Scope

In scope: the file format and its cryptography, the npm package (library and
CLI) and the Python package, including how they handle keys, ssh-agent and the
files they write.

What envlockup does and does not protect against is described in the
[threat model](docs/DESIGN.md#threat-model). A report that one of the listed
limits applies (for example, that someone with write access to the file can
delete a variable) is not a vulnerability, but a way around something the threat
model says is caught is.

## Supported versions

Only the latest release of each package receives security fixes.
