```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8")
```


# Original Sigma Rule:
```yaml
title: HackTool - Sliver C2 Implant Activity Pattern
id: 42333b2c-b425-441c-b70e-99404a17170f
status: test
description: Detects process activity patterns as seen being used by Sliver C2 framework implants
references:
    - https://github.com/BishopFox/sliver/blob/79f2d48fcdfc2bee4713b78d431ea4b27f733f30/implant/sliver/shell/shell_windows.go#L36
    - https://www.microsoft.com/security/blog/2022/08/24/looking-for-the-sliver-lining-hunting-for-emerging-command-and-control-frameworks/
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-08-25
modified: 2023-03-05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-NoExit -Command [Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
