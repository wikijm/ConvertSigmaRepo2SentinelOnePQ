```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.displayName="University of California, Berkeley")
```


# Original Sigma Rule:
```yaml
title: Potential BOINC Software Execution (UC-Berkeley Signature)
id: 0090b851-3543-42db-828c-02fee986ff0b
status: test
description: |
    Detects the use of software that is related to the University of California, Berkeley via metadata information.
    This indicates it may be related to BOINC software and can be used maliciously if unauthorized.
references:
    - https://boinc.berkeley.edu/
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1553
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: 'University of California, Berkeley'
    condition: selection
falsepositives:
    - This software can be used for legitimate purposes when installed intentionally.
level: informational
```
