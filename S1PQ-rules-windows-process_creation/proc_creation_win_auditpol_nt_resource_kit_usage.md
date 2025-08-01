```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "/logon:none" or tgt.process.cmdline contains "/system:none" or tgt.process.cmdline contains "/sam:none" or tgt.process.cmdline contains "/privilege:none" or tgt.process.cmdline contains "/object:none" or tgt.process.cmdline contains "/process:none" or tgt.process.cmdline contains "/policy:none"))
```


# Original Sigma Rule:
```yaml
title: Audit Policy Tampering Via NT Resource Kit Auditpol
id: c6c56ada-612b-42d1-9a29-adad3c5c2c1e
related:
    - id: 0a13e132-651d-11eb-ae93-0242ac130002 # New auditpol version
      type: similar
status: test
description: |
    Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability.
    This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Windows%202000%20Resource%20Kit%20Tools/AuditPol
author: Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-18
modified: 2023-02-21
tags:
    - attack.defense-evasion
    - attack.t1562.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '/logon:none'
            - '/system:none'
            - '/sam:none'
            - '/privilege:none'
            - '/object:none'
            - '/process:none'
            - '/policy:none'
    condition: selection
falsepositives:
    - The old auditpol utility isn't available by default on recent versions of Windows as it was replaced by a newer version. The FP rate should be very low except for tools that use a similar flag structure
level: high
```
