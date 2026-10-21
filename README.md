# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Last updated: 21 October 2026
TLP:CLEAR

This repository contains operational information regarding the critical PHP vulnerabilities tracked by CERT-EU as CVE-2026-109618 and CVE-2026-109619.

PHP is a widely used open-source server-side scripting language, so these vulnerabilities may affect a broad range of internet-facing web applications and products that embed or depend on PHP.

## Current status

Public reporting indicates that both vulnerabilities can be triggered with a simple POST request and may lead to unauthenticated remote code execution and shell access. PHP rates both issues CVSS v4.0 9.2. CERT-EU reports that PHP 5 and later versions may be affected; earlier versions have not been assessed.

PHP announced a security release for 21 October 2026 at 14:00 UTC (16:00 CEST). Until that release is published, technical details and fixed versions remain unconfirmed. Multiple public proof-of-concept exploits are already available. As of 21 October 2026, NCSC has no indication of active exploitation, but considers large-scale exploitation likely in the short term.

## Recommended actions

- Identify PHP-based applications and their runtime versions, with priority on internet-facing systems.
- Patch to fixed PHP releases as soon as they become available.
- If immediate patching is not possible, consider isolating internet-facing PHP applications from public networks until a fix is applied.
- Monitor vendor advisories, internet-facing logs, and public exploit activity.

For additional information see:

- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [PHP announcement: Upcoming Critical PHP Security Release](https://www.php.net/archive/2026.php#2026-10-20-1)

## Repository contents

| Directory | Purpose |
| --- | --- |
| [software](software) | Contains inventory lists of software products with a PHP dependency potentially affected by the vulnerabilities. |
| [tools](tools) | Contains tools for using/generating files within this repo |

Please note that this repository is not complete and is currently being expanded.

## Contributions welcome

If you have additional information relevant to these PHP vulnerabilities, please open a pull request with a source that can be verified.

For updates to the paginated software list, please edit the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files, so pull requests that only modify generated Markdown will not be merged.
