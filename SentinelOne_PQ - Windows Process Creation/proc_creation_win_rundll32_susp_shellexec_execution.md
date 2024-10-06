```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "ShellExec_RunDLL" and (tgt.process.cmdline contains "regsvr32" or tgt.process.cmdline contains "msiexec" or tgt.process.cmdline contains "\Users\Public\" or tgt.process.cmdline contains "odbcconf" or tgt.process.cmdline contains "\Desktop\" or tgt.process.cmdline contains "\Temp\" or tgt.process.cmdline contains "Invoke-" or tgt.process.cmdline contains "iex" or tgt.process.cmdline contains "comspec")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Usage Of ShellExec_RunDLL
id: d87bd452-6da1-456e-8155-7dc988157b7d
related:
    - id: 36c5146c-d127-4f85-8e21-01bf62355d5a
      type: obsolete
status: test
description: Detects suspicious usage of the ShellExec_RunDLL function to launch other commands as seen in the the raspberry-robin attack
references:
    - https://redcanary.com/blog/raspberry-robin/
    - https://www.microsoft.com/en-us/security/blog/2022/10/27/raspberry-robin-worm-part-of-larger-ecosystem-facilitating-pre-ransomware-activity/
    - https://github.com/SigmaHQ/sigma/issues/1009
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-01
modified: 2022-12-30
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection_openasrundll:
        CommandLine|contains: 'ShellExec_RunDLL'
    selection_suspcli:
        CommandLine|contains:
            # Add more LOLBINs and Susp Paths
            - 'regsvr32'
            - 'msiexec'
            - '\Users\Public\'
            - 'odbcconf'
            - '\Desktop\'
            - '\Temp\'
            - 'Invoke-'
            - 'iex'
            - 'comspec'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```