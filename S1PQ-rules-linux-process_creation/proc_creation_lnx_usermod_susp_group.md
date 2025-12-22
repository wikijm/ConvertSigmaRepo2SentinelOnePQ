```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (tgt.process.image.path contains "/usermod" and (tgt.process.cmdline contains "-aG root" or tgt.process.cmdline contains "-aG sudoers")))
```


# Original Sigma Rule:
```yaml
title: User Added To Root/Sudoers Group Using Usermod
id: 6a50f16c-3b7b-42d1-b081-0fdd3ba70a73
status: test
description: Detects usage of the "usermod" binary to add users add users to the root or suoders groups
references:
    - https://pberba.github.io/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/
    - https://www.configserverfirewall.com/ubuntu-linux/ubuntu-add-user-to-root-group/
author: TuanLe (GTSC)
date: 2022-12-21
tags:
    - attack.privilege-escalation
    - attack.persistence
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/usermod'
        CommandLine|contains:
            - '-aG root'
            - '-aG sudoers'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
