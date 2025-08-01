```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "UWhRCA" and tgt.process.cmdline contains "BAAAA"))
```


# Original Sigma Rule:
```yaml
title: Attempts of Kerberos Coercion Via DNS SPN Spoofing
id: 0ed99dda-6a35-11ef-8c99-0242ac120002
related:
    - id: b07e58cf-cacc-4135-8473-ccb2eba63dd2
      type: similar
status: experimental
description: |
    Detects the presence of "UWhRC....AAYBAAAA" pattern in command line.
    The pattern "1UWhRCAAAAA..BAAAA" is a base64-encoded signature that corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure.
    Attackers can use this technique to coerce authentication from victim systems to attacker-controlled hosts.
    It is one of the strong indicators of a Kerberos coercion attack, where adversaries manipulate DNS records
    to spoof Service Principal Names (SPNs) and redirect authentication requests like in CVE-2025-33073.
    If you see this pattern in the command line, it is likely an attempt to add spoofed Service Principal Names (SPNs) to DNS records,
    or checking for the presence of such records through the `nslookup` command.
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
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'UWhRCA'
            - 'BAAAA'
    condition: selection
falsepositives:
    - Unknown
level: high
```
