```sql
// Translated content (automatically translated on 02-08-2025 02:10:48):
event.category="DNS" and (endpoint.os="windows" and (event.dns.request contains "UWhRCA" and event.dns.request contains "BAAAA"))
```


# Original Sigma Rule:
```yaml
title: Suspicious DNS Query Indicating Kerberos Coercion via DNS Object SPN Spoofing
id: e7a21b5f-d8c4-4ae5-b8d9-93c5d3f28e1c
related:
    - id: b07e58cf-cacc-4135-8473-ccb2eba63dd2 # Potential Kerberos Coercion via DNS Object Spoofing
      type: similar
    - id: 5588576c-5898-4fac-bcdd-7475a60e8f43 # Suspicious DNS Query Indicating Kerberos Coercion via DNS Object Spoofing - Network
      type: similar
status: experimental
description: |
    Detects DNS queries containing patterns associated with Kerberos coercion attacks via DNS object spoofing.
    The pattern "1UWhRCAAAAA..BAAAA" is a base64-encoded signature that corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure.
    Attackers can use this technique to coerce authentication from victim systems to attacker-controlled hosts.
    It is one of the strong indicators of a Kerberos coercion attack, where adversaries manipulate DNS records
    to spoof Service Principal Names (SPNs) and redirect authentication requests like CVE-2025-33073.
references:
    - https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
    - https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-06-20
tags:
    - attack.credential-access
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1557.001
    - attack.t1187
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains|all:
            - 'UWhRCA'
            - 'BAAAA'
    condition: selection
falsepositives:
    - Unknown
level: high
```
