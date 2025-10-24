```sql
// Translated content (automatically translated on 24-10-2025 01:12:07):
event.type="Module Load" and (endpoint.os="windows" and (module.path contains "\\goopdate.dll" and (not (module.path contains "C:\\Program Files (x86)\\" or module.path contains "C:\\Program Files\\")) and (not (((src.process.image.path contains "\\AppData\\Local\\Temp\\GUM" and src.process.image.path contains ".tmp\\Dropbox") and (module.path contains "\\AppData\\Local\\Temp\\GUM" and module.path contains ".tmp\\goopdate.dll")) or ((src.process.image.path contains "\\AppData\\Local\\Temp\\GUM" or src.process.image.path contains ":\\Windows\\SystemTemp\\GUM") and src.process.image.path contains ".tmp\\GoogleUpdate.exe" and (module.path contains "\\AppData\\Local\\Temp\\GUM" or module.path contains ":\\Windows\\SystemTemp\\GUM"))))))
```


# Original Sigma Rule:
```yaml
title: Potential Goopdate.DLL Sideloading
id: b6188d2f-b3c4-4d2c-a17d-9706e0851af0
status: test
description: Detects potential DLL sideloading of "goopdate.dll", a DLL used by googleupdate.exe
references:
    - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf
author: X__Junior (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-15
modified: 2025-10-07
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1574.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith: '\goopdate.dll'
    filter_main_generic:
        ImageLoaded|startswith:
            # Many third party chromium based apps use this DLLs. It's better to create a baseline and add specific filters
            - 'C:\Program Files (x86)\'
            - 'C:\Program Files\'
    filter_optional_dropbox_installer_temp:
        Image|contains|all:
            - '\AppData\Local\Temp\GUM'
            - '.tmp\Dropbox'
        ImageLoaded|contains|all:
            - '\AppData\Local\Temp\GUM'
            - '.tmp\goopdate.dll'
    filter_optional_googleupdate_temp:
        Image|contains:
            - '\AppData\Local\Temp\GUM'
            - ':\Windows\SystemTemp\GUM'
        Image|endswith: '.tmp\GoogleUpdate.exe'
        ImageLoaded|contains:
            - '\AppData\Local\Temp\GUM'
            - ':\Windows\SystemTemp\GUM'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - False positives are expected from Google Chrome installations running from user locations (AppData) and other custom locations. Apply additional filters accordingly.
    - Other third party chromium browsers located in AppData
level: medium
```
