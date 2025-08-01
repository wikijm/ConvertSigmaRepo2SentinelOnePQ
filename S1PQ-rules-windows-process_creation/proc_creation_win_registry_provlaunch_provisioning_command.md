```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "SOFTWARE\Microsoft\Provisioning\Commands\")
```


# Original Sigma Rule:
```yaml
title: Potential Provisioning Registry Key Abuse For Binary Proxy Execution
id: 2a4b3e61-9d22-4e4a-b60f-6e8f0cde6f25
related:
    - id: 7f5d1c9a-3e83-48df-95a7-2b98aae6c13c # CLI Generic
      type: similar
    - id: f9999590-1f94-4a34-a91e-951e47bedefd # CLI Abuse
      type: similar
    - id: 7021255e-5db3-4946-a8b9-0ba7a4644a69 # Registry
      type: similar
status: test
description: Detects potential abuse of the provisioning registry key for indirect command execution through "Provlaunch.exe".
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Provlaunch/
    - https://twitter.com/0gtweet/status/1674399582162153472
author: Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel
date: 2023-08-08
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'SOFTWARE\Microsoft\Provisioning\Commands\'
    condition: selection
falsepositives:
    - Unknown
level: high
```
