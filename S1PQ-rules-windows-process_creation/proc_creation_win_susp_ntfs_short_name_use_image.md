```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "~1.bat" or tgt.process.image.path contains "~1.dll" or tgt.process.image.path contains "~1.exe" or tgt.process.image.path contains "~1.hta" or tgt.process.image.path contains "~1.js" or tgt.process.image.path contains "~1.msi" or tgt.process.image.path contains "~1.ps1" or tgt.process.image.path contains "~1.tmp" or tgt.process.image.path contains "~1.vbe" or tgt.process.image.path contains "~1.vbs" or tgt.process.image.path contains "~2.bat" or tgt.process.image.path contains "~2.dll" or tgt.process.image.path contains "~2.exe" or tgt.process.image.path contains "~2.hta" or tgt.process.image.path contains "~2.js" or tgt.process.image.path contains "~2.msi" or tgt.process.image.path contains "~2.ps1" or tgt.process.image.path contains "~2.tmp" or tgt.process.image.path contains "~2.vbe" or tgt.process.image.path contains "~2.vbs") and (not src.process.image.path="C:\Windows\explorer.exe") and (not (src.process.image.path contains "\WebEx\WebexHost.exe" or src.process.image.path contains "\thor\thor64.exe" or tgt.process.image.path="C:\PROGRA~1\WinZip\WZPREL~1.EXE" or tgt.process.image.path contains "\VCREDI~1.EXE"))))
```


# Original Sigma Rule:
```yaml
title: Use NTFS Short Name in Image
id: 3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b
related:
    - id: dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795
      type: similar
status: test
description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid Image based detection
references:
    - https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
    - https://twitter.com/jonasLyk/status/1555914501802921984
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-06
modified: 2023-07-20
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '~1.bat'
            - '~1.dll'
            - '~1.exe'
            - '~1.hta'
            - '~1.js'
            - '~1.msi'
            - '~1.ps1'
            - '~1.tmp'
            - '~1.vbe'
            - '~1.vbs'
            - '~2.bat'
            - '~2.dll'
            - '~2.exe'
            - '~2.hta'
            - '~2.js'
            - '~2.msi'
            - '~2.ps1'
            - '~2.tmp'
            - '~2.vbe'
            - '~2.vbs'
    filter_main_generic_parent:
        ParentImage: 'C:\Windows\explorer.exe'
    filter_optional_webex:
        ParentImage|endswith: '\WebEx\WebexHost.exe'
    filter_optional_thor:
        ParentImage|endswith: '\thor\thor64.exe'
    filter_optional_winzip:
        Image: 'C:\PROGRA~1\WinZip\WZPREL~1.EXE'
    filter_optional_vcred:
        Image|endswith: '\VCREDI~1.EXE'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Software Installers
level: medium
```
