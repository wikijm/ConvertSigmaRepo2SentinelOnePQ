```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "\Outlook\Security\EnableUnsafeClientMailRules")
```


# Original Sigma Rule:
```yaml
title: Outlook EnableUnsafeClientMailRules Setting Enabled
id: 55f0a3a1-846e-40eb-8273-677371b8d912
related:
    - id: 6763c6c8-bd01-4687-bc8d-4fa52cf8ba08 # Registry variation
      type: similar
status: test
description: Detects an attacker trying to enable the outlook security setting "EnableUnsafeClientMailRules" which allows outlook to run applications or execute macros
references:
    - https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html
    - https://speakerdeck.com/heirhabarov/hunting-for-persistence-via-microsoft-exchange-server-or-outlook?slide=44
    - https://support.microsoft.com/en-us/topic/how-to-control-the-rule-actions-to-start-an-application-or-run-a-macro-in-outlook-2016-and-outlook-2013-e4964b72-173c-959d-5d7b-ead562979048
author: Markus Neis, Nasreddine Bencherchali (Nextron Systems)
date: 2018-12-27
modified: 2023-02-09
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '\Outlook\Security\EnableUnsafeClientMailRules'
    condition: selection
falsepositives:
    - Unknown
level: high
```
