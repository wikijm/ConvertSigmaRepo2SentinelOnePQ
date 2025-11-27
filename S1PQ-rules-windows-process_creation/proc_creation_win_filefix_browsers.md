```sql
// Translated content (automatically translated on 27-11-2025 02:01:20):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\brave.exe" or src.process.image.path contains "\\chrome.exe" or src.process.image.path contains "\\firefox.exe" or src.process.image.path contains "\\msedge.exe") and (tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe") and tgt.process.cmdline contains "#"))
```


# Original Sigma Rule:
```yaml
title: FileFix - Suspicious Child Process from Browser File Upload Abuse
id: 4be03877-d5b6-4520-85c9-a5911c0a656c
status: experimental
description: |
    Detects potentially suspicious subprocesses such as LOLBINs spawned by web browsers. This activity could be associated with the "FileFix" social engineering technique,
    where users are tricked into launching the file explorer via a browser-based phishing page and pasting malicious commands into the address bar.
    The technique abuses clipboard manipulation and disguises command execution as benign file path access, resulting in covert execution of system utilities.
references:
    - https://mrd0x.com/filefix-clickfix-alternative/
author: 0xFustang
date: 2025-06-26
modified: 2025-06-30
tags:
    - attack.execution
    - attack.t1204.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\brave.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\msedge.exe'
        Image|endswith:
            - '\bitsadmin.exe'
            - '\certutil.exe'
            - '\cmd.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
        CommandLine|contains: '#'
    condition: selection
falsepositives:
    - Legitimate use of PowerShell or other utilities launched from browser extensions or automation tools
level: high
```
