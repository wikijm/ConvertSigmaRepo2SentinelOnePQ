```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\diskshadow.exe" and (tgt.process.image.path contains "\certutil.exe" or tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\mshta.exe" or tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe" or tgt.process.image.path contains "\regsvr32.exe" or tgt.process.image.path contains "\rundll32.exe" or tgt.process.image.path contains "\wscript.exe")))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Child Process Of DiskShadow.EXE
id: 9f546b25-5f12-4c8d-8532-5893dcb1e4b8
related:
    - id: fa1a7e52-3d02-435b-81b8-00da14dd66c1 # Diskshadow Script Mode - Execution From Potential Suspicious Location
      type: similar
    - id: 1dde5376-a648-492e-9e54-4241dd9b0c7f # Diskshadow Script Mode - Uncommon Script Extension Execution
      type: similar
    - id: 56b1dde8-b274-435f-a73a-fb75eb81262a # Diskshadow Child Process Spawned
      type: similar
    - id: 0c2f8629-7129-4a8a-9897-7e0768f13ff2 # Diskshadow Script Mode Execution
      type: similar
status: test
description: Detects potentially suspicious child processes of "Diskshadow.exe". This could be an attempt to bypass parent/child relationship detection or application whitelisting rules.
references:
    - https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
    - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/ntds.dit-enumeration
    - https://medium.com/@cyberjyot/lolbin-execution-via-diskshadow-f6ff681a27a4
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow
    - https://www.lifars.com/wp-content/uploads/2022/01/GriefRansomware_Whitepaper-2.pdf
    - https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware
    - https://research.checkpoint.com/2022/evilplayout-attack-against-irans-state-broadcaster/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-09-15
tags:
    - attack.defense-evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\diskshadow.exe'
        Image|endswith:
            # Note: add or remove additional binaries according to your org needs
            - '\certutil.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - False postitve can occur in cases where admin scripts levreage the "exec" flag to execute applications
level: medium
```
