```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "~1.exe" or tgt.process.cmdline contains "~1.bat" or tgt.process.cmdline contains "~1.msi" or tgt.process.cmdline contains "~1.vbe" or tgt.process.cmdline contains "~1.vbs" or tgt.process.cmdline contains "~1.dll" or tgt.process.cmdline contains "~1.ps1" or tgt.process.cmdline contains "~1.js" or tgt.process.cmdline contains "~1.hta" or tgt.process.cmdline contains "~2.exe" or tgt.process.cmdline contains "~2.bat" or tgt.process.cmdline contains "~2.msi" or tgt.process.cmdline contains "~2.vbe" or tgt.process.cmdline contains "~2.vbs" or tgt.process.cmdline contains "~2.dll" or tgt.process.cmdline contains "~2.ps1" or tgt.process.cmdline contains "~2.js" or tgt.process.cmdline contains "~2.hta") and (not ((src.process.image.path contains "\\WebEx\\WebexHost.exe" or src.process.image.path contains "\\thor\\thor64.exe") or tgt.process.cmdline contains "C:\\xampp\\vcredist\\VCREDI~1.EXE"))))
```


# Original Sigma Rule:
```yaml
title: Use NTFS Short Name in Command Line
id: dd6b39d9-d9be-4a3b-8fe0-fe3c6a5c1795
related:
    - id: 3ef5605c-9eb9-47b0-9a71-b727e6aa5c3b
      type: similar
status: test
description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
references:
    - https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
    - https://twitter.com/jonasLyk/status/1555914501802921984
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-05
modified: 2022-09-21
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '~1.exe'
            - '~1.bat'
            - '~1.msi'
            - '~1.vbe'
            - '~1.vbs'
            - '~1.dll'
            - '~1.ps1'
            - '~1.js'
            - '~1.hta'
            - '~2.exe'
            - '~2.bat'
            - '~2.msi'
            - '~2.vbe'
            - '~2.vbs'
            - '~2.dll'
            - '~2.ps1'
            - '~2.js'
            - '~2.hta'
    filter:
        - ParentImage|endswith:
              - '\WebEx\WebexHost.exe'
              - '\thor\thor64.exe'
        - CommandLine|contains: 'C:\xampp\vcredist\VCREDI~1.EXE'
    condition: selection and not filter
falsepositives:
    - Applications could use this notation occasionally which might generate some false positives. In that case Investigate the parent and child process.
level: medium
```
