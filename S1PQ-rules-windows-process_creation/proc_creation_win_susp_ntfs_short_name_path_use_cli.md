```sql
// Translated content (automatically translated on 09-10-2025 01:53:45):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "~1\\" or tgt.process.cmdline contains "~2\\") and (not ((src.process.image.path in ("C:\\Windows\\System32\\Dism.exe","C:\\Windows\\System32\\cleanmgr.exe","C:\\Program Files\\GPSoftware\\Directory Opus\\dopus.exe")) or (src.process.image.path contains "\\WebEx\\WebexHost.exe" or src.process.image.path contains "\\thor\\thor64.exe" or src.process.image.path contains "\\veam.backup.shell.exe" or src.process.image.path contains "\\winget.exe" or src.process.image.path contains "\\Everything\\Everything.exe" or src.process.image.path contains "\\aurora-agent-64.exe" or src.process.image.path contains "\\aurora-agent.exe") or src.process.image.path contains "\\AppData\\Local\\Temp\\WinGet\\" or (tgt.process.cmdline contains "\\appdata\\local\\webex\\webex64\\meetings\\wbxreport.exe" or tgt.process.cmdline contains "C:\\Program Files\\Git\\post-install.bat" or tgt.process.cmdline contains "C:\\Program Files\\Git\\cmd\\scalar.exe")))))
```


# Original Sigma Rule:
```yaml
title: Use Short Name Path in Command Line
id: 349d891d-fef0-4fe4-bc53-eee623a15969
related:
    - id: a96970af-f126-420d-90e1-d37bf25e50e1
      type: similar
status: test
description: Detect use of the Windows 8.3 short name. Which could be used as a method to avoid command-line detection
references:
    - https://www.acunetix.com/blog/articles/windows-short-8-3-filenames-web-security-problem/
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc959352(v=technet.10)
    - https://twitter.com/frack113/status/1555830623633375232
author: frack113, Nasreddine Bencherchali
date: 2022-08-07
modified: 2025-07-04
tags:
    - attack.defense-evasion
    - attack.t1564.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '~1\'
            - '~2\'
    filter:
        - ParentImage:
              - 'C:\Windows\System32\Dism.exe'
              - 'C:\Windows\System32\cleanmgr.exe'
              - 'C:\Program Files\GPSoftware\Directory Opus\dopus.exe'
        - ParentImage|endswith:
              - '\WebEx\WebexHost.exe'
              - '\thor\thor64.exe'
              - '\veam.backup.shell.exe'
              - '\winget.exe'
              - '\Everything\Everything.exe'
              - '\aurora-agent-64.exe'
              - '\aurora-agent.exe'
        - ParentImage|contains: '\AppData\Local\Temp\WinGet\'
        - CommandLine|contains:
              - '\appdata\local\webex\webex64\meetings\wbxreport.exe'
              - 'C:\Program Files\Git\post-install.bat'
              - 'C:\Program Files\Git\cmd\scalar.exe'
    condition: selection and not filter
falsepositives:
    - Applications could use this notation occasionally which might generate some false positives. In that case investigate the parent and child process.
level: medium
```
