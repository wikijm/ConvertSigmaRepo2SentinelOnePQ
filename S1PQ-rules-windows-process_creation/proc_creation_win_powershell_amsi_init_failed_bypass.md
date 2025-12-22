```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "System.Management.Automation.AmsiUtils" and tgt.process.cmdline contains "amsiInitFailed") or (tgt.process.cmdline contains "[Ref].Assembly.GetType" and tgt.process.cmdline contains "SetValue($null,$true)" and tgt.process.cmdline contains "NonPublic,Static")))
```


# Original Sigma Rule:
```yaml
title: Potential AMSI Bypass Via .NET Reflection
id: 30edb182-aa75-42c0-b0a9-e998bb29067c
related:
    - id: 4f927692-68b5-4267-871b-073c45f4f6fe
      type: obsolete
status: test
description: Detects Request to "amsiInitFailed" that can be used to disable AMSI Scanning
references:
    - https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/
    - https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/
author: Markus Neis, @Kostastsale
date: 2018-08-17
modified: 2023-02-03
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains|all:
              - 'System.Management.Automation.AmsiUtils'
              - 'amsiInitFailed'
        - CommandLine|contains|all:
              - '[Ref].Assembly.GetType'
              - 'SetValue($null,$true)'
              - 'NonPublic,Static'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
