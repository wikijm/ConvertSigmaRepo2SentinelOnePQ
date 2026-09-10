```sql
// Translated content (automatically translated on 10-09-2026 04:17:17):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\\msiexec.exe" and (tgt.process.cmdline contains " -Y" or tgt.process.cmdline contains " /Y" or tgt.process.cmdline contains " –Y" or tgt.process.cmdline contains " —Y" or tgt.process.cmdline contains " ―Y")) and (not (tgt.process.cmdline contains "\\MsiExec.exe\" /Y \"C:\\Program Files\\" or tgt.process.cmdline contains "\\MsiExec.exe\" /Y \"C:\\Program Files (x86)\\" or tgt.process.cmdline contains "\\MsiExec.exe\" /Y \"C:\\Windows\\System32\\" or tgt.process.cmdline contains "\\MsiExec.exe\" /Y \"C:\\Windows\\SysWOW64\\"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Msiexec Execute Arbitrary DLL
id: 6f4191bb-912b-48a8-9ce7-682769541e6d
status: test
description: |
    Adversaries may abuse msiexec.exe to proxy execution of malicious payloads.
    Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi)
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.007/T1218.007.md
    - https://twitter.com/_st0pp3r_/status/1583914515996897281
author: frack113
date: 2022-01-16
modified: 2026-01-09
tags:
    - attack.stealth
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|windash: ' /Y'
    filter_main_legit_path:
        CommandLine|contains:
            - '\MsiExec.exe" /Y "C:\Program Files\'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\'
            - '\MsiExec.exe" /Y "C:\Windows\System32\'
            - '\MsiExec.exe" /Y "C:\Windows\SysWOW64\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate script
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_msiexec_execute_dll/info.yml
```
