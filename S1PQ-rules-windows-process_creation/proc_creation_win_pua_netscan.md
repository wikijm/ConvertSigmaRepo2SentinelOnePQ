```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\netscan.exe" or tgt.process.displayName="Network Scanner" or tgt.process.displayName="Application for scanning networks"))
```


# Original Sigma Rule:
```yaml
title: PUA - SoftPerfect Netscan Execution
id: ca387a8e-1c84-4da3-9993-028b45342d30
status: test
description: |
    Detects usage of SoftPerfect's "netscan.exe". An application for scanning networks.
    It is actively used in-the-wild by threat actors to inspect and understand the network architecture of a victim.
references:
    - https://www.protect.airbus.com/blog/uncovering-cyber-intruders-netscan/
    - https://secjoes-reports.s3.eu-central-1.amazonaws.com/Sockbot%2Bin%2BGoLand.pdf
    - https://www.sentinelone.com/labs/black-basta-ransomware-attacks-deploy-custom-edr-evasion-tools-tied-to-fin7-threat-actor/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/yanluowang-ransomware-attacks-continue
    - https://research.nccgroup.com/2022/07/13/climbing-mount-everest-black-byte-bytes-back/
    - https://www.bleepingcomputer.com/news/security/microsoft-exchange-servers-hacked-to-deploy-hive-ransomware/
    - https://www.softperfect.com/products/networkscanner/
author: '@d4ns4n_ (Wuerth-Phoenix)'
date: 2024-04-25
tags:
    - attack.discovery
    - attack.t1046
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\netscan.exe'
        - Product: 'Network Scanner'
        - Description: 'Application for scanning networks'
    condition: selection
falsepositives:
    - Legitimate administrator activity
level: medium
```
