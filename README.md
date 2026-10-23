# php2shell vulnerabilities (CVE-2026-109618, CVE-2026-109619)

Operational information: 21 October 2026 17:25 CEST<br>
Software list last status update: 23 October 2026 13:29 CEST<br>
## TLP:CLEAR

This repository contains operational information regarding the critical PHP vulnerabilities tracked by CERT-EU as CVE-2026-109618 and CVE-2026-109619.

PHP is a widely used open-source server-side scripting language, so these vulnerabilities may affect a broad range of internet-facing web applications and products that embed or depend on PHP.

## Current status

On 21 October 2026, PHP published fixed releases for CVE-2026-109618 and CVE-2026-109619: PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. PHP states that both vulnerabilities can allow unauthenticated remote code execution and that all PHP installations serving web requests are at risk, including PHP-FPM, Apache with mod_php, php-cgi, FrankenPHP and LiteSpeed. PHP considers the risk highest for mod_php, where an unauthenticated request can trigger exploitation before application code runs.

PHP describes CVE-2026-109618 as remote code execution via out-of-memory corruption during request cleanup, and CVE-2026-109619 as remote code execution via stale request-owned global state reused by a later request on the same worker. PHP 8.1 and older are no longer supported by the PHP project; distributions and LTS vendors may provide backported packages, and PHP has published minimal source backports for PHP 7.4, 8.0 and 8.1.

The impact is not limited to websites: PHP is also embedded in appliances, network devices, management interfaces and other vendor products where administrators may not be able to update PHP directly.

## Recommended actions

- Identify PHP-based applications and their runtime versions, with priority on internet-facing systems and web-serving SAPIs.
- Update to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35, or apply vendor-provided backported packages.
- Check third-party images, appliances and embedded runtimes separately; for products that bundle PHP, apply vendor updates as soon as they become available.
- If immediate patching is not possible, follow PHP's temporary mitigations, including disabling `session.upload_progress`, restarting workers, and reviewing the official `memory_limit`, `post_max_size` and PHP 8.5 `fatal_error_backtraces` guidance. PHP states that these measures are not complete fixes.
- Monitor vendor advisories, internet-facing logs, and public exploit activity.

For additional information see:

- [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)
- [PHP security advisory: Critical remote code execution vulnerabilities, update now](https://www.php.net/archive/2026.php#2026-10-21-5)
- [List of advisories from other EU national CSIRT's](https://github.com/enisaeu/CNW/blob/main/advisories/2026/CNW-2026-04_php.md)

## Repository contents

| Directory | Purpose |
| --- | --- |
| [detection_mitigation](detection_mitigation) | Contains detection and mitigation material for the vulnerabilities. |
| [software](software) | Contains inventory lists of software products with a PHP dependency potentially affected by the vulnerabilities. |
| [tools](tools) | Contains tools for using/generating files within this repo |

The repository is being updated as the situation develops. Check back for updates.

## Latest software status updates

| Date and time | Supplier | Product | Version (see Status) | Status CVE-2026-109618 | Status CVE-2026-109619 | Notes | Links |
|:------------------------|:---------|:--------|:--------------------:|:----------------------:|:----------------------:|:------|------:|
|2026-10-23 13:29:32 +0200|CloudLinux|CloudLinux ea-PHP fixed packages for CloudLinux 7-10|ea-php52 through ea-php85: vendor fixed build matrix released 2026-10-21 20:55 UTC (EL7/8/9/10)|Fix|Fix|CVE assessment: CloudLinux confirms fixed ea-php52 through ea-php85 packages in stable for EL7/8/9/10. Use the exact vendor package revisions, not the upstream PHP number alone: for example ea-php84 8.4.26-2.elX.cloudlinux.1 contains both fixes. CL6 and other platforms are not included in this fixed scope.<br>Vendor-confirmed published fix for both PHP2Shell CVEs in this specific package or image scope.|[source](<https://cloudlinux.statuspage.io/incidents/zl0vt1yq3dj5>)|
|2026-10-23 13:29:32 +0200|CloudLinux / TuxCare|CloudLinux Alt-PHP fixed packages for CloudLinux 7-10 and Ubuntu 22.04|Stable security builds released 2026-10-21/22; CL8/9 PHP 8.2.35-1, 8.3.36-1, 8.4.27-1, 8.5.12-1 also released 2026-10-23|Fix|Fix|CVE assessment: CloudLinux confirms fixed alt-php 5.2-5.6, 7.0-7.4 and 8.0-8.5 for CL7/8/9; Ubuntu 22.04 covers 5.2, 5.6, 7.0-7.4 and 8.0-8.5. CL10 has fixed 5.2 in stable and other branches through ELS ALT PHP. CL8/9 also have new upstream-number builds for 8.2-8.5. CL6 and unlisted platform/branch combinations are excluded. Check backport revisions and changelogs.<br>Vendor-confirmed published fix for both PHP2Shell CVEs in this specific package or image scope.|[source](<https://cloudlinux.statuspage.io/incidents/zl0vt1yq3dj5>)|
|2026-10-23 13:29:32 +0200|FileCloud|FileCloud Server PHP installation and maintenance|FileCloud Server 23.263.2 (PHP 8.4.27), Windows and Linux|Fix|Fix|CVE assessment: Fixed in FileCloud Server 23.263.2, which includes PHP 8.4.27, for Windows and Linux. Earlier Server versions are affected. This does not confirm completion of the separately announced FileCloud Online rollout.<br>FileCloud confirms that Server 23.263.2 includes PHP 8.4.27 and fixes both CVEs on Windows and Linux.|[source 1](<https://docs.filecloud.com/fcdoc/latest/server/upgrade-filecloud/upgrade-using-update-tool-windows-only>)<br>[source 2](<https://docs.filecloud.com/fcdoc/latest/server/security-advisories/2026-security-advisories/filecloud-release-23-263-security-advisories/advisory-2026-10-03-php2shell-critical-php-remote-code-execution-vulnerabilities>)|
|2026-10-23 13:29:32 +0200|FileRun|FileRun official Docker image (fixed PHP rebuild)|filerun/filerun:2026.03 rebuilt with fixed PHP, announced 2026-10-21|Fix|Fix|CVE assessment: FileRun confirms its official Docker image already includes the PHP fix and identifies filerun/filerun:2026.03 in the update instructions. Re-pull and recreate the container. Non-Docker FileRun installations still require a separate PHP update.<br>Vendor-confirmed published fix for both PHP2Shell CVEs in this specific package or image scope.|[source](<https://filerun.com/index.php/php-security-alert-21oct26>)|
|2026-10-23 13:29:32 +0200|FrankenPHP|FrankenPHP static builds|FrankenPHP 1.13.2 static binaries with PHP 8.5.12|Fix|Fix|CVE assessment: Fixed in FrankenPHP 1.13.2 static binaries embedding PHP 8.5.12. Replace the embedded runtime binary; updating a separate system PHP installation does not repair older static builds.<br>FrankenPHP 1.13.2 publishes static binaries with PHP 8.5.12 fixing both PHP2Shell CVEs.|[source 1](<https://frankenphp.dev/docs/static/>)<br>[source 2](<https://www.php.net/archive/2026.php#2026-10-21-1>)<br>[source 3](<https://github.com/php/frankenphp/issues/2732>)<br>[source 4](<https://github.com/php/frankenphp/releases/tag/v1.13.2>)|

See the [full software status update history](software/changelog_software_list.md).

## Contributions welcome

If you have any additional information to share relevant to these PHP vulnerabilities, feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

For updates to the software list: our strong preference is to receive edits in the SPDX source files in `software/spdx/`. The Markdown list pages are generated automatically from those files. In case this proves too difficult: don't worry. We'll attempt to backport edits in the .md files to the SPDX source files, but without any guarantees. 

