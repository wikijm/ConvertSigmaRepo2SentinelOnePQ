```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\keytool.exe" and (tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\scrcons.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\hh.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\forfiles.exe" or tgt.process.image.path contains "\\scriptrunner.exe" or tgt.process.image.path contains "\\mftrace.exe" or tgt.process.image.path contains "\\AppVLP.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\query.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Shells Spawn by Java Utility Keytool
id: 90fb5e62-ca1f-4e22-b42e-cc521874c938
status: test
description: Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)
references:
    - https://redcanary.com/blog/intelligence-insights-december-2021
    - https://www.synacktiv.com/en/publications/how-to-exploit-cve-2021-40539-on-manageengine-adselfservice-plus.html
author: Andreas Hunkeler (@Karneades)
date: 2021-12-22
modified: 2023-01-21
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\keytool.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\scrcons.exe'
            - '\regsvr32.exe'
            - '\hh.exe'
            - '\wmic.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
            - '\mftrace.exe'
            - '\AppVLP.exe'
            - '\systeminfo.exe'
            - '\reg.exe'
            - '\query.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
