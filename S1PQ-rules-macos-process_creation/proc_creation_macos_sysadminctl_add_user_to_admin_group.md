```sql
// Translated content (automatically translated on 19-09-2025 01:13:47):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/sysadminctl" and (tgt.process.cmdline contains " -addUser " and tgt.process.cmdline contains " -admin ")))
```


# Original Sigma Rule:
```yaml
title: User Added To Admin Group Via Sysadminctl
id: 652c098d-dc11-4ba6-8566-c20e89042f2b
related:
    - id: 0c1ffcf9-efa9-436e-ab68-23a9496ebf5b
      type: obsolete
status: test
description: Detects attempts to create and add an account to the admin group via "sysadminctl"
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1078.003/T1078.003.md#atomic-test-3---create-local-account-with-admin-privileges-using-sysadminctl-utility---macos
    - https://ss64.com/osx/sysadminctl.html
author: Sohan G (D4rkCiph3r)
date: 2023-03-19
tags:
    - attack.initial-access
    - attack.privilege-escalation
    - attack.t1078.003
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        # Creates and adds new user to admin group
        Image|endswith: '/sysadminctl'
        CommandLine|contains|all:
            - ' -addUser '
            - ' -admin '
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
```
