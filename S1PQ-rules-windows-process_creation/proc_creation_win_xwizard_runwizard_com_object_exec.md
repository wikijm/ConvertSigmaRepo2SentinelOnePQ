```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline="RunWizard" and tgt.process.cmdline matches "\\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\\}"))
```


# Original Sigma Rule:
```yaml
title: COM Object Execution via Xwizard.EXE
id: 53d4bb30-3f36-4e8a-b078-69d36c4a79ff
status: test
description: |
    Detects the execution of Xwizard tool with the "RunWizard" flag and a GUID like argument.
    This utility can be abused in order to run custom COM object created in the registry.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
    - https://www.elastic.co/guide/en/security/current/execution-of-com-object-via-xwizard.html
    - https://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
author: Ensar Şamil, @sblmsrsn, @oscd_initiative, Nasreddine Bencherchali (Nextron Systems)
date: 2020-10-07
modified: 2024-08-15
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'RunWizard'
        CommandLine|re: '\{[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\}'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
