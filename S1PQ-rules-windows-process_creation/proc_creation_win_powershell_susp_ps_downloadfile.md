```sql
// Translated content (automatically translated on 20-10-2025 02:04:56):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "powershell" and tgt.process.cmdline contains ".DownloadFile" and tgt.process.cmdline contains "System.Net.WebClient"))
```


# Original Sigma Rule:
```yaml
title: PowerShell DownloadFile
id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
status: test
description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
references:
    - https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html
author: Florian Roth (Nextron Systems)
date: 2020-08-28
modified: 2021-11-27
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command-and-control
    - attack.t1104
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'powershell'
            - '.DownloadFile'
            - 'System.Net.WebClient'
    condition: selection
falsepositives:
    - Unknown
level: high
```
