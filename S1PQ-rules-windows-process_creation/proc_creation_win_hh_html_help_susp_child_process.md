```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\hh.exe" and (tgt.process.image.path contains "\\CertReq.exe" or tgt.process.image.path contains "\\CertUtil.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\installutil.exe" or tgt.process.image.path contains "\\MSbuild.exe" or tgt.process.image.path contains "\\MSHTA.EXE" or tgt.process.image.path contains "\\msiexec.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe")))
```


# Original Sigma Rule:
```yaml
title: HTML Help HH.EXE Suspicious Child Process
id: 52cad028-0ff0-4854-8f67-d25dfcbc78b4
status: test
description: Detects a suspicious child process of a Microsoft HTML Help (HH.exe)
references:
    - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-27939090904026cc396b0b629c8e4314acd6f5dac40a676edbc87f4567b47eb7
    - https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
    - https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37
author: Maxim Pavlunin, Nasreddine Bencherchali (Nextron Systems)
date: 2020-04-01
modified: 2023-04-12
tags:
    - attack.defense-evasion
    - attack.execution
    - attack.initial-access
    - attack.t1047
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1218
    - attack.t1218.001
    - attack.t1218.010
    - attack.t1218.011
    - attack.t1566
    - attack.t1566.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\hh.exe'
        Image|endswith:
            - '\CertReq.exe'
            - '\CertUtil.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\installutil.exe'
            - '\MSbuild.exe'
            - '\MSHTA.EXE'
            - '\msiexec.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
