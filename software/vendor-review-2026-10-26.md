# Official public-source review — 26 October 2026

This review concerns **CVE-2026-109618** and **CVE-2026-109619**. Status names are exactly those defined in [software/README.md](README.md): **Vulnerable**, **Not vuln**, **Fix**, and **Investigation**. “Both” in the tables means both CVEs.

Eligibility was frozen at main commit `2fdc314`: only the **611 products** with at least one **Investigation** or **Vulnerable** assessment were selected. Products already assessed only as Fix, Not vuln or Workaround were excluded. References to fixed container or package variants below describe remediation for an eligible parent product; they are not a new review of excluded inventory entries.

The review used fresh public vendor/upstream publications and maintainer statements. It attempted the 886 distinct HTTPS references attached to eligible records (865 returned an HTTP response; 21 failed), searched their official domains for the CVEs/PHP2Shell, and followed relevant official advisories. A successful HTTP response can still be a JavaScript shell, login page or documentation without a CVE assessment. Such responses were not accepted as confirmation. Public rendered advisory text was used for HPE, NetApp, Quest and F5; no vendor support login, private correspondence, installation testing or exploitation was used.

The tables contain **63 distinct eligible products** with confirmed findings in the stated scopes. Products can appear in more than one table when vulnerable installations and a released fix coexist, or when the CVEs differ. A Fix means the named release/build or deployment scope has a vendor-confirmed fix; it does not mean existing installations have installed it.

## Vulnerable

| Inventory ID | Product | CVE scope | Confirmed scope / version | Official source |
| --- | --- | --- | --- | --- |
| PHP-0632 | Apex Central | Both | Apex Central; temporary mitigation is published, permanent patch is still being prepared. | [trend](https://success.trendmicro.com/en-US/solution/KA-0024802) |
| PHP-0631 | Apex One | Both | Apex One on-premises server; temporary mitigation is published, permanent patch is still being prepared. | [trend](https://success.trendmicro.com/en-US/solution/KA-0024802) |
| PHP-0730 | Carbon Black App Control Server | Both | Carbon Black App Control Server is listed as affected. The linked product-specific bulletin requires login, so its patch details were not used. | [broadcom](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Enterprise-Security-Group-Advisory-for-PHP2Shell/39404) |
| PHP-0749 | Cisco Expressway Select Series | Both | Expressway Select Series; 15.5.21 is listed with TBD availability. | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0698 | Cisco Expressway Series | Both | Expressway Series; 15.5.21 is listed with TBD availability, not a confirmed released fix. | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0699 | Cisco Ultra-Reliable Wireless Backhaul (URWB) | Both | URWB; 27.1.1 is planned for February 2027. Vendor says exploitation requires administrator authentication. | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0624 | Citrix NetScaler ADC and Citrix NetScaler Gateway | Both | NetScaler ADC / Gateway affected; interim exposure restrictions do not establish a released fix. | [citrix](https://support.citrix.com/external/article/CTX697263) |
| PHP-0387 | CloudLinux Alt-PHP / PHP Selector runtime family | Both | Unpatched CloudLinux Alt-PHP / PHP Selector builds; fixed stable builds and backports are available. | [cloudlinux](https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916-PHP-CVE-2026-109618-CVE-2026-109619-PHP2Shell-fixed-alt-php-and-ea-php-packages-and-how-to-verify) |
| PHP-0388 | CloudLinux legacy ea-PHP extended-support packages | Both | Unpatched CloudLinux ea-PHP builds; use the vendor package release, not just the upstream PHP version. | [cloudlinux](https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916-PHP-CVE-2026-109618-CVE-2026-109619-PHP2Shell-fixed-alt-php-and-ea-php-packages-and-how-to-verify) |
| PHP-0007 | Drupal | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [drupal](https://www.drupal.org/association/blog/after-the-php-security-release-auditing-your-drupal-sites) |
| PHP-0210 | FileRun | Both | FileRun on unpatched serving PHP; no FileRun application setting or update repairs PHP. | [filerun](https://filerun.com/index.php/php-security-alert-21oct26) |
| PHP-0024 | GLPI | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [glpi](https://www.glpi-project.org/en/%F0%9F%9A%A8-critical-php2shell-php-vulnerabilities-cve-2026-109618-cve-2026-109619-what-you-need-to-know-for-your-glpi-server/) |
| PHP-0120 | Grav CMS | Both | Grav sites on unpatched serving PHP; the application and hosted/container scopes differ. | [grav](https://mail.getgrav.org/blog/php-critical-security-release-october-2026) |
| PHP-0221 | grommunio Web | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [grommunio](https://grommunio.com/news/php2shell-patched-php-packages-available/) |
| PHP-0389 | ISPConfig 3 control panel UI and scripts | Both | ISPConfig control panel and hosted PHP sites on unpatched runtimes; multipart guard is temporary. | [ispconfig](https://www.ispconfig.org/blog/php2shell-critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619/) |
| PHP-0629 | Junos OS J-Web (EX/SRX scope) | CVE-2026-109618 | Junos OS J-Web on EX/SRX using affected PHP. CVE-2026-109619 remains Investigation; SRX 25.2R1 removes PHP, without an equivalent EX fix established here. | [juniper](https://supportportal.juniper.net/s/article/2026-10-Reference-Advisory-Status-of-PHP2Shell-vulnerabilities-on-Juniper-Products-CVE-2026-109618-CVE-2026-109619) |
| PHP-0128 | MODX Revolution | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [modx](https://community.modx.com/t/critical-php-vulnerabilities-upgrade-immediately/9312) |
| PHP-0013 | Moodle | Both | Moodle HQ warns that unpatched self-hosted Moodle sites remain exposed to PHP2Shell and must update PHP. Only its specifically named patched public site is confirmed restored. | [moodle](https://moodle.org/news/); [php](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP-0657 | MyUTM portal | Both | MyUTM hosted licensing portal ran affected PHP and was taken offline for updating; restoration with a completed fix is not confirmed. | [sophos](https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell) |
| PHP-0281 | Nagios Fusion web component subsystem | Both | Nagios Fusion PHP web subsystem on unpatched distribution PHP; the vendor directs customers to distribution updates. | [nagios](https://www.nagios.com/security-disclosures/) |
| PHP-0280 | Nagios XI web configuration-wizard subsystem | Both | Nagios XI PHP web subsystem on unpatched distribution PHP; the vendor notice applies to Nagios solutions. | [nagios](https://www.nagios.com/security-disclosures/) |
| PHP-0015 | Nextcloud Server | Both | Nextcloud project warning explicitly identifies its online PHP server scope; update the serving PHP runtime. This does not establish a fix for every packaging variant. | [nextcloud](https://github.com/nextcloud/server/issues/65754); [php](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP-0119 | October CMS | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [october](https://octobercms.com/blog/post/php-security-alert-critical-php-vulnerabilities-and-your-october-cms-sites) |
| PHP-0623 | PAN-OS | Both | PAN-OS management web interface, including HTTPS UI and XML API; branch-specific affected ranges are in the advisory. Future ETA releases are excluded from confirmed fixes. | [pan](https://security.paloaltonetworks.com/CVE-2026-109618) |
| PHP-0625 | Panorama | Both | Panorama virtual and M-Series management interface under the PAN-OS advisory. | [pan](https://security.paloaltonetworks.com/CVE-2026-109618) |
| PHP-0649 | PHP core and Zend Engine affected web-serving release scope | Both | PHP core / Zend Engine serving web requests, before the fixed release or vendor backport. | [php](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP-0658 | phpMyFAQ | CVE-2026-109618 | phpMyFAQ on PHP-CGI with cgi.fix_pathinfo=1, as specifically described by the project. CVE-2026-109619 remains Investigation. | [phpmyfaq](https://phpmyfaq.de/) |
| PHP-0621 | Plesk for Linux | Both | Plesk for Linux with unpatched hosted PHP; internal-engine remediation is separate. | [plesk](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk) |
| PHP-0622 | Plesk for Windows | Both | Plesk for Windows with unpatched hosted PHP; internal-engine remediation is separate. | [plesk](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk) |
| PHP-0029 | Plesk Obsidian hosted-site PHP | Both | Unpatched hosted-site PHP handlers; fixed Plesk package scopes are listed below. | [plesk](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk) |
| PHP-0719 | QNAP Note Station 3 | Both | Note Station 3 3.9.14 and earlier; fixed version still to be announced. | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0720 | QNAP QNE (ADRA) | Both | QNE (ADRA) 1.0.7 and earlier; fixed version still to be announced. | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0721 | QNAP QVR Surveillance | Both | QVR Surveillance 3.0.3 and earlier, ARM32 models; fixed version still to be announced. | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0722 | QNAP TVR OS | Both | TVR OS 1.0.4 and earlier; fixed version still to be announced. | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0364 | Red Hat Enterprise Linux 9 PHP RPM/AppStreams | Both | Unpatched RHEL 9 base PHP and php:8.3 packages covered by the linked errata. | [rhel-base](https://access.redhat.com/errata/RHSA-2026:87151); [rhel83](https://access.redhat.com/errata/RHSA-2026:87079) |
| PHP-0420 | Render customer PHP Docker hosting | Both | Customer PHP Docker services on Render using an unpatched runtime; rebuild and redeploy the image. | [render](https://render.com/docs/advisory-php2shell) |
| PHP-0237 | SuiteCRM | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [suitecrm](https://suitecrm.com/critical-php-security-release/) |
| PHP-0603 | Synology PHP 7.3 archived package family | Both | Synology PHP 7.3 is affected and end of life; vendor will not provide a fix. The advisory being marked Resolved does not fix this package. | [synology](https://www.synology.com/en-global/security/advisory/Synology_SA_26_14) |
| PHP-0006 | WordPress | Both | Self-hosted / operator-managed serving PHP is unpatched; update PHP rather than only the application. | [wordpress](https://automattic.com/2026/10/21/php2shell/) |

## Not vuln

| Inventory ID | Product | CVE scope | Confirmed scope / version | Official source |
| --- | --- | --- | --- | --- |
| PHP-0689 | Cisco Catalyst Center (formerly DNA Center) | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0704 | Cisco CX Cloud | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0706 | Cisco IoT Control Center | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0750 | Cisco Meraki Dashboard | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0692 | Cisco WAN Automation Engine (WAE) | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |
| PHP-0732 | CloudSOC Cloud Access Security Broker (CASB) | Both | CloudSOC CASB service; excludes the separate SpanVA appliance | [broadcom](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/Enterprise-Security-Group-Advisory-for-PHP2Shell/39404) |
| PHP-0678 | FortiDDoS-F | Both | FortiDDoS-F; vendor-confirmed not impacted scope | [fortinet](https://fortiguard.fortinet.com/psirt/FG-IR-26-186) |
| PHP-0752 | ONTAP 9 | CVE-2026-109619 | ONTAP 9; vendor says only CVE-2026-109618 affects this product. | [netapp](https://security.netapp.com/advisory/NTAP-20261021-0021) |
| PHP-0713 | Slido | Both | Vendor-confirmed not vulnerable product scope | [cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-php-october26-Jj384Daq) |

## Fix

| Inventory ID | Product | CVE scope | Confirmed scope / version | Official source |
| --- | --- | --- | --- | --- |
| PHP-0627 | BIG-IP APM PHP page templates | Both | BIG-IP 17.1.3.7 / 17.5.1.11 / 21.1.0.4 | [f5](https://my.f5.com/manage/s/article/K000163821) |
| PHP-0626 | BIG-IP TMOS platform PHP | Both | BIG-IP 17.1.3.7 / 17.5.1.11 / 21.1.0.4 | [f5](https://my.f5.com/manage/s/article/K000163821) |
| PHP-0387 | CloudLinux Alt-PHP / PHP Selector runtime family | Both | Stable vendor alt-php fixed-build matrix for 5.2–8.5; distribution and package release numbers matter for backports. | [cloudlinux](https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916-PHP-CVE-2026-109618-CVE-2026-109619-PHP2Shell-fixed-alt-php-and-ea-php-packages-and-how-to-verify) |
| PHP-0388 | CloudLinux legacy ea-PHP extended-support packages | Both | Stable CloudLinux ea-php52–ea-php85 fixed builds with the CloudLinux release suffix. | [cloudlinux](https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916-PHP-CVE-2026-109618-CVE-2026-109619-PHP2Shell-fixed-alt-php-and-ea-php-packages-and-how-to-verify) |
| PHP-0360 | Fedora PHP distribution package family | Both | php-8.4.27-2.fc43; php-8.5.12-1.fc44; php-8.5.12-1.fc45; php-8.5.12-1.fc46 (Rawhide) | [fedora](https://bugzilla.redhat.com/show_bug.cgi?id=2556842) |
| PHP-0210 | FileRun | Both | Official filerun/filerun image rebuilt with patched PHP; vendor example tag 2026.03. Pull and recreate the container. | [filerun](https://filerun.com/index.php/php-security-alert-21oct26) |
| PHP-0120 | Grav CMS | Both | Official getgrav/grav image tags rebuilt on 21 October with patched PHP; pull and recreate. | [grav](https://mail.getgrav.org/blog/php-critical-security-release-october-2026) |
| PHP-0221 | grommunio Web | Both | Out-of-band PHP packages in grommunio community and supported repositories for SUSE-based installations, announced 21 October; restart PHP-FPM. | [grommunio](https://grommunio.com/news/php2shell-patched-php-packages-available/) |
| PHP-0751 | HPE Networking ClearPass Policy Manager | Both | ClearPass 6.14.1 + PHP CVE hotfix / ClearPass 6.11.16 + PHP CVE hotfix | [hpe](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05171en_us&docLocale=en_US) |
| PHP-0673 | KACE Systems Management Appliance | Both | KACE SMA 15.0 CU5 (15.0.378) / 15.1 CU2 (15.1.177) | [quest](https://support.quest.com/kace-systems-management-appliance/kb/4385046/quest-kace-response-to-cve-2026-109618-and-cve-2026-109619-php2shell) |
| PHP-0752 | ONTAP 9 | CVE-2026-109618 | 9.15.1P20HF1 / 9.16.1P16HF1 / 9.17.1P11HF1 / 9.18.1P8HF1 / 9.19.1P3HF1 | [netapp](https://security.netapp.com/advisory/NTAP-20261021-0021) |
| PHP-0016 | ownCloud Classic 11 | Both | owncloud/server:11.0.1 Docker rebuild of 22 October; PHP package 8.3.6-0ubuntu0.24.04.13. Scope is the rebuilt image, not all ownCloud 11 installations. | [owncloud](https://github.com/orgs/owncloud/discussions/27) |
| PHP-0208 | ownCloud Server 10 | Both | owncloud/server:10.16.6 Docker rebuild of 22 October; PHP package 1:7.4.33-31+freexian22.04.1+php+1. Pull and redeploy; the PHP branch number alone is insufficient. | [owncloud](https://github.com/orgs/owncloud/discussions/27) |
| PHP-0265 | Part-DB server | Both | Official jbtronics/part-db1:2.20.2 image repushed with PHP 8.4.27; confirmation is by project member jbtronics. | [partdb](https://github.com/Part-DB/Part-DB-server/issues/1615#issuecomment-6324675679) |
| PHP-0649 | PHP core and Zend Engine affected web-serving release scope | Both | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This is a runtime fix, not an automatic fix for every downstream installation. | [php](https://www.php.net/archive/2026.php#2026-10-21-5) |
| PHP-0284 | phpLDAPadmin | Both | Official Docker release 2.3.12 containing PHP 8.4.27; confirmation is by repository owner leenooks. | [phpldap](https://github.com/leenooks/phpLDAPadmin/issues/491#issuecomment-6339838166) |
| PHP-0621 | Plesk for Linux | Both | Hosted Linux PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; 7.4.33 / 8.0.30 / 8.1.34 builds dated 21 October. | [plesk](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk) |
| PHP-0622 | Plesk for Windows | Both | Hosted Windows PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. | [plesk](https://support.plesk.com/hc/en-us/articles/44397729587351-Vulnerability-CVE-2026-109618-and-CVE-2026-109619-PHP2Shell-Remote-code-execution-in-PHP-shipped-with-Plesk) |
| PHP-0425 | QNAP QTS built-in PHP runtime | Both | QTS 6.1.0.3656 build 20261023 / QTS 5.2.11.3661 build 20261023 | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0426 | QNAP QuTS hero built-in PHP runtime | Both | QuTS hero h6.1.0.3656 / h6.0.2.3656 / h5.2.11.3661, each build 20261023 | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0717 | QNAP QuTScloud | Both | QuTScloud c5.2.9.3661 build 20261023 | [qnap](https://www.qnap.com/en/security-advisory/qsa-26-18) |
| PHP-0364 | Red Hat Enterprise Linux 9 PHP RPM/AppStreams | Both | RHEL 9 base PHP and php:8.3 fixed packages in RHSA-2026:87151 and RHSA-2026:87079; select the correct stream and architecture. | [rhel-base](https://access.redhat.com/errata/RHSA-2026:87151); [rhel83](https://access.redhat.com/errata/RHSA-2026:87079) |
| PHP-0381 | Roundcube Webmail Docker image family | Both | Roundcube image rebuilds confirmed successful by maintainer pabzm on 21 October. A later fpm-alpine regression required another rebuild; see caveat below. | [roundcube](https://github.com/roundcube/roundcubemail-docker/issues/468#issuecomment-6325191782); [roundcube-alpine](https://github.com/roundcube/roundcubemail-docker/issues/468#issuecomment-6361850134) |
| PHP-0297 | Shlink | Both | Shlink 5.1.8 Docker images: release notes explicitly identify fixes for both CVEs through updated Alpine/PHP. | [shlink](https://github.com/shlinkio/shlink/releases/tag/v5.1.8) |
| PHP-0159 | Spryker Commerce OS | Both | spryker-php image release 20261021, containing PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. This applies to the runtime images, not every Commerce OS deployment. | [spryker](https://docs.spryker.com/docs/about/all/releases/image-releases/spryker-php/release-notes-spryker-php-20261021.html) |

## Investigation and scope limits

- Junos OS J-Web and phpMyFAQ have explicit CVE-2026-109618 confirmation; this review did not establish a product-specific CVE-2026-109619 conclusion for either. Their second assessment remains Investigation.

- Cisco ISE Portal Builder, Unified Industrial Wireless Software and Ultra Cloud Core / Converged Policy and Charging remain under investigation in the Cisco advisory. No absence-based Not vuln conclusion was applied to Cisco Panoptica.

- FortiDDoS, FortiClient Cloud Services, FortiSOAR and FortiSOAR PaaS remain under investigation in FG-IR-26-186. FortiDDoS-F is a different product and is explicitly not impacted.

- Broadcom Content Analysis remains under investigation. CloudSOC CASB is explicitly not vulnerable; the affected SpanVA appliance is a separate scope. The App Control product bulletin redirected to login; only its public parent advisory was used.

- PAN-OS lists several unaffected target builds without ETAs, but its Solution section still describes upcoming fixes. This review retains Vulnerable and does not claim confirmed release availability from that inconsistent text alone. Scheduled Cisco releases are also excluded from Fix.

- Roundcube maintainer comments confirm successful rebuilds, followed by an fpm-alpine regression and another rebuild in progress. This supports the released rebuilt-image scope, not a blanket claim that every later tag or locally cached image is patched. The broad image family remains Vulnerable in the inventory.

- QNAP QSA-26-18 revision 1.1 confirms firmware fixes in its resolved table. Pending application fixes are separate; it does not establish that the older optional PHP7.4 package is fixed. The historical QuMagie entry was not reclassified solely because it is absent from the updated affected-products table.

- WordPress.com publicly says every hosted site is protected and needs no customer action. The reviewed text does not explicitly identify a completed PHP patch or say the product is intrinsically not vulnerable. This review therefore leaves the eligible hosting entry in Investigation rather than inferring Fix or Not vuln from “protected”. [WordPress.com statement](https://wordpress.com/support/php-security-update-october-2026-cve-2026-109618-and-cve-2026-109619-php2shell/).

- Claims about vendor-hosted SuiteCRM, MODX Cloud, GLPI Network Cloud or other hosted services were not transferred to self-hosted applications. Those hosted services were not separate eligible entries. Likewise, Nextcloud application guidance and a scheduled Docker rebuild do not prove that every Nextcloud image, Snap, NextcloudPi or app has a released fix.

- No additional product-specific official confirmation was established for the other eligible records. Their existing inventory assessments were preserved; they are not counted here as newly confirmed vulnerable merely because they depend on PHP. Failure to find a public statement is not evidence of non-vulnerability.

## Inventory changes and reproducibility

The SPDX source fragments update 18 product status assessments and replace PHP-only inference with explicit vendor evidence for seven additional applications. This report is a dated evidence summary; the SPDX fragments remain the inventory source of truth. Existing IDs and unrelated assessments are preserved. The compiler newline metadata is aligned with the repository’s existing tracked LF files to avoid a whole-file line-ending change.

Validation: compile source fragments; parse the compiled JSON; regenerate alphabetic Markdown, full history and README latest updates with both opt-in flags and `--history-ref origin/main`; run the repository unit tests; check compiler freshness, references, eligibility and the diff. Local research scripts, raw page captures and AI.md are not publication artifacts.
