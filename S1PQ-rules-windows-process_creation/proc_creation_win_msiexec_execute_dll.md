```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\msiexec.exe" and (tgt.process.cmdline contains " -y" or tgt.process.cmdline contains " /y" or tgt.process.cmdline contains " –y" or tgt.process.cmdline contains " —y" or tgt.process.cmdline contains " ―y")) and (not (tgt.process.cmdline contains "\MsiExec.exe\" /Y \"C:\Program Files\Bonjour\mdnsNSP.dll" or tgt.process.cmdline contains "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Bonjour\mdnsNSP.dll" or tgt.process.cmdline contains "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll" or tgt.process.cmdline contains "\MsiExec.exe\" /Y \"C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll" or tgt.process.cmdline contains "\MsiExec.exe\" /Y \"C:\Windows\CCM\" or tgt.process.cmdline contains "\MsiExec.exe\" /Y C:\Windows\CCM\" or tgt.process.cmdline contains "\MsiExec.exe\" -Y \"C:\Program Files\Bonjour\mdnsNSP.dll" or tgt.process.cmdline contains "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Bonjour\mdnsNSP.dll" or tgt.process.cmdline contains "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll" or tgt.process.cmdline contains "\MsiExec.exe\" -Y \"C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll" or tgt.process.cmdline contains "\MsiExec.exe\" -Y \"C:\Windows\CCM\" or tgt.process.cmdline contains "\MsiExec.exe\" -Y C:\Windows\CCM\"))))
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
modified: 2024-03-13
tags:
    - attack.defense-evasion
    - attack.t1218.007
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\msiexec.exe'
        CommandLine|contains|windash: ' -y'
    filter_apple:
        CommandLine|contains:
            - '\MsiExec.exe" /Y "C:\Program Files\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll'
            - '\MsiExec.exe" /Y "C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll'
            - '\MsiExec.exe" /Y "C:\Windows\CCM\'
            - '\MsiExec.exe" /Y C:\Windows\CCM\' # also need non-quoted execution
            - '\MsiExec.exe" -Y "C:\Program Files\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" -Y "C:\Program Files (x86)\Bonjour\mdnsNSP.dll'
            - '\MsiExec.exe" -Y "C:\Program Files (x86)\Apple Software Update\ScriptingObjectModel.dll'
            - '\MsiExec.exe" -Y "C:\Program Files (x86)\Apple Software Update\SoftwareUpdateAdmin.dll'
            - '\MsiExec.exe" -Y "C:\Windows\CCM\'
            - '\MsiExec.exe" -Y C:\Windows\CCM\' # also need non-quoted execution
    condition: selection and not 1 of filter_*
falsepositives:
    - Legitimate script
level: medium
```
