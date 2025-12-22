```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/dscl" and (tgt.process.cmdline contains " -append " and tgt.process.cmdline contains " /Groups/admin " and tgt.process.cmdline contains " GroupMembership ")))
```


# Original Sigma Rule:
```yaml
title: User Added To Admin Group Via Dscl
id: b743623c-2776-40e0-87b1-682b975d0ca5
related:
    - id: 0c1ffcf9-efa9-436e-ab68-23a9496ebf5b
      type: obsolete
status: test
description: Detects attempts to create and add an account to the admin group via "dscl"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-2---create-local-account-with-admin-privileges---macos
    - https://ss64.com/osx/dscl.html
author: Sohan G (D4rkCiph3r)
date: 2023-03-19
tags:
    - attack.persistence
    - attack.defense-evasion
    - attack.initial-access
    - attack.privilege-escalation
    - attack.t1078.003
logsource:
    category: process_creation
    product: macos
detection:
    selection: # adds to admin group
        Image|endswith: '/dscl'
        CommandLine|contains|all:
            - ' -append '
            - ' /Groups/admin '
            - ' GroupMembership '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
