```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "123456789" or tgt.process.cmdline contains "123123qwE" or tgt.process.cmdline contains "Asd123.aaaa" or tgt.process.cmdline contains "Decryptme" or tgt.process.cmdline contains "P@ssw0rd!" or tgt.process.cmdline contains "Pass8080" or tgt.process.cmdline contains "password123" or tgt.process.cmdline contains "test@202"))
```


# Original Sigma Rule:
```yaml
title: Weak or Abused Passwords In CLI
id: 91edcfb1-2529-4ac2-9ecc-7617f895c7e4
status: test
description: |
    Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI.
    An example would be a threat actor creating a new user via the net command and providing the password inline
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/espionage-asia-governments
    - https://thedfirreport.com/2022/09/26/bumblebee-round-two/
    - https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-14
modified: 2024-02-23
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # Add more passwords
            - '123456789'
            - '123123qwE'
            - 'Asd123.aaaa'
            - 'Decryptme'
            - 'P@ssw0rd!'
            - 'Pass8080'
            - 'password123' # Also covers PASSWORD123123! as seen in https://www.microsoft.com/en-us/security/blog/2022/10/25/dev-0832-vice-society-opportunistic-ransomware-campaigns-impacting-us-education-sector/
            - 'test@202' # Covers multiple years
    condition: selection
falsepositives:
    - Legitimate usage of the passwords by users via commandline (should be discouraged)
    - Other currently unknown false positives
level: medium
```
