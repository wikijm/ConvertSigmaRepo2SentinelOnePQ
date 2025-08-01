```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "~1\" or tgt.process.image.path contains "~2\") and (not (((src.process.image.path in ("C:\Windows\System32\Dism.exe","C:\Windows\System32\cleanmgr.exe")) or (src.process.image.path contains "\WebEx\WebexHost.exe" or src.process.image.path contains "\thor\thor64.exe") or tgt.process.displayName="InstallShield (R)" or tgt.process.displayName="InstallShield (R) Setup Engine" or tgt.process.publisher="InstallShield Software Corporation") or ((tgt.process.image.path contains "\AppData\" and tgt.process.image.path contains "\Temp\") or (tgt.process.image.path contains "~1\unzip.exe" or tgt.process.image.path contains "~1\7zG.exe"))))))
```


# Original Sigma Rule:
```yaml
title: Use Short Name Path in Image
id: a96970af-f126-420d-90e1-d37bf25e50e1
related:
    - id: 349d891d-fef0-4fe4-bc53-eee623a15969
      type: similar
status: test
description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image detection
references:
    - https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
    - https://twitter.com/frack113/status/1555830623633375232
author: frack113, Nasreddine Bencherchali
date: 2022-08-07
modified: 2023-03-21
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '~1\'
            - '~2\'
    filter1:
        - ParentImage:
              - C:\Windows\System32\Dism.exe
              - C:\Windows\System32\cleanmgr.exe  # Spawns DismHost.exe with a shortened username (if too long)
        - ParentImage|endswith:
              - '\WebEx\WebexHost.exe'  # Spawns a shortened version of the CLI and Image processes
              - '\thor\thor64.exe'
        - Product: 'InstallShield (R)'
        - Description: 'InstallShield (R) Setup Engine'
        - Company: 'InstallShield Software Corporation'
    filter_installers:
        - Image|contains|all:
              - '\AppData\'
              - '\Temp\'
        - Image|endswith:
              - '~1\unzip.exe'
              - '~1\7zG.exe'
    condition: selection and not 1 of filter*
falsepositives:
    - Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process.
level: medium
```
