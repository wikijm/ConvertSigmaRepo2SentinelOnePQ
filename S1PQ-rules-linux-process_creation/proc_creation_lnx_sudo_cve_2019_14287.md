```sql
// Translated content (automatically translated on 10-11-2025 00:58:31):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.cmdline contains " -u#")
```


# Original Sigma Rule:
```yaml
title: Sudo Privilege Escalation CVE-2019-14287
id: f74107df-b6c6-4e80-bf00-4170b658162b
status: test
description: Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287
references:
    - https://www.openwall.com/lists/oss-security/2019/10/14/1
    - https://access.redhat.com/security/cve/cve-2019-14287
    - https://twitter.com/matthieugarin/status/1183970598210412546
author: Florian Roth (Nextron Systems)
date: 2019-10-15
modified: 2022-10-05
tags:
    - attack.defense-evasion
    - attack.privilege-escalation
    - attack.t1068
    - attack.t1548.003
    - cve.2019-14287
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains: ' -u#'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
