```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\GoogleUpdate.exe" and (not ((tgt.process.image.path contains "\\Google" or (tgt.process.image.path contains "\\setup.exe" or tgt.process.image.path contains "chrome_updater.exe" or tgt.process.image.path contains "chrome_installer.exe")) or not (tgt.process.image.path matches "\.*")))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious GoogleUpdate Child Process
id: 84b1ecf9-6eff-4004-bafb-bae5c0e251b2
related:
    - id: bdbab15a-3826-48fa-a1b7-723cd8f32fcc
      type: derived
status: test
description: Detects potentially suspicious child processes of "GoogleUpdate.exe"
references:
    - https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-15
modified: 2023-05-22
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\GoogleUpdate.exe'
    filter_main_known_legit:
        # Some other legit child process might exist. It's better to make a baseline before running this in production
        - Image|contains: '\Google' # Example: GoogleUpdate.exe, GoogleCrashHandler.exe, GoogleUpdateComRegisterShell64.exe
        - Image|endswith:
              - '\setup.exe'
              - 'chrome_updater.exe'
              - 'chrome_installer.exe'
    filter_main_image_null:
        Image: null
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
