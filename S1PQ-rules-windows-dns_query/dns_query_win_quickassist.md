```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (src.process.image.path contains "\QuickAssist.exe" and event.dns.request contains "remoteassistance.support.services.microsoft.com"))
```


# Original Sigma Rule:
```yaml
title: DNS Query Request By QuickAssist.EXE
id: 882e858a-3233-4ba8-855e-2f3d3575803d
status: experimental
description: |
    Detects DNS queries initiated by "QuickAssist.exe" to Microsoft Quick Assist primary endpoint that is used to establish a session.
references:
    - https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/
    - https://www.linkedin.com/posts/kevin-beaumont-security_ive-been-assisting-a-few-orgs-hit-with-successful-activity-7268055739116445701-xxjZ/
    - https://x.com/cyb3rops/status/1862406110365245506
    - https://learn.microsoft.com/en-us/windows/client-management/client-tools/quick-assist
author: Muhammad Faisal (@faisalusuf)
date: 2024-12-19
tags:
    - attack.command-and-control
    - attack.initial-access
    - attack.lateral-movement
    - attack.t1071.001
    - attack.t1210
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        Image|endswith: '\QuickAssist.exe'
        QueryName|endswith: 'remoteassistance.support.services.microsoft.com'
    condition: selection
falsepositives:
    - Legitimate use of Quick Assist in the environment.
level: low
```
