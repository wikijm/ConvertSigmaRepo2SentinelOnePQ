```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "\System\CurrentControlSet\Control\Lsa" and tgt.process.cmdline contains "NoLMHash" and tgt.process.cmdline contains " 0"))
```


# Original Sigma Rule:
```yaml
title: Enable LM Hash Storage - ProcCreation
id: 98dedfdd-8333-49d4-9f23-d7018cccae53
related:
    - id: c420410f-c2d8-4010-856b-dffe21866437 # Registry
      type: similar
status: test
description: |
    Detects changes to the "NoLMHash" registry value in order to allow Windows to store LM Hashes.
    By setting this registry value to "0" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
    - https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password
    - https://www.sans.org/blog/protecting-privileged-domain-accounts-lm-hashes-the-good-the-bad-and-the-ugly/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-12-15
modified: 2023-12-22
tags:
    - attack.defense-evasion
    - attack.t1112
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - '\System\CurrentControlSet\Control\Lsa'
            - 'NoLMHash'
            - ' 0'
    condition: selection
falsepositives:
    - Unknown
level: high
```
