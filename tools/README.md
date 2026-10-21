# Tools

## `generate_software_list_from_spdx3.py`

Generates the alphabetized Markdown software list in `software/` from an SPDX 3 JSON document.

Usage:

```bash
python tools/generate_software_list_from_spdx3.py PHP_Downstream_Inventory.spdx3.json -o software
```

When only a filename is provided, the tool reads it from `software/spdx/`. An explicit path may also be provided.
