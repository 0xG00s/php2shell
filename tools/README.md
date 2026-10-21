# Tools

This repository tracks CVE-2026-109618 and CVE-2026-109619. PHP's official advisory identifies PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 as fixed upstream releases.

## `generate_software_list_from_spdx3.py`

Generates the alphabetized Markdown software list in `software/` from an SPDX 3 JSON document.

Usage:

```bash
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software
```

When only a filename is provided, the tool reads it from `software/spdx/`. An explicit path may also be provided.
