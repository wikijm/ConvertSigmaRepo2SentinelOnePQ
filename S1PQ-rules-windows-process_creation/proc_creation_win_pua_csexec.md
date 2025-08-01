```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\csexec.exe" or tgt.process.displayName="csexec"))
```


# Original Sigma Rule:
```yaml
title: PUA - CsExec Execution
id: d08a2711-ee8b-4323-bdec-b7d85e892b31
status: test
description: Detects the use of the lesser known remote execution tool named CsExec a PsExec alternative
references:
    - https://github.com/malcomvetter/CSExec
    - https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/
author: Florian Roth (Nextron Systems)
date: 2022-08-22
modified: 2023-02-21
tags:
    - attack.resource-development
    - attack.t1587.001
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\csexec.exe'
    selection_pe:
        Description: 'csexec'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high
```
