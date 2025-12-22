```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\\java.exe" and (tgt.process.image.path contains "\\AppVLP.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\curl.exe" or tgt.process.image.path contains "\\forfiles.exe" or tgt.process.image.path contains "\\hh.exe" or tgt.process.image.path contains "\\mftrace.exe" or tgt.process.image.path contains "\\mshta.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\query.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\regsvr32.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\schtasks.exe" or tgt.process.image.path contains "\\scrcons.exe" or tgt.process.image.path contains "\\scriptrunner.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\systeminfo.exe" or tgt.process.image.path contains "\\whoami.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Processes Spawned by Java.EXE
id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
related:
    - id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
      type: similar
status: test
description: Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j)
references:
    - https://web.archive.org/web/20231230220738/https://www.lunasec.io/docs/blog/log4j-zero-day/
author: Andreas Hunkeler (@Karneades), Florian Roth
date: 2021-12-17
modified: 2024-01-18
tags:
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\java.exe'
        Image|endswith:
            - '\AppVLP.exe'
            - '\bitsadmin.exe'
            - '\certutil.exe'
            - '\cscript.exe'
            - '\curl.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\mftrace.exe'
            - '\mshta.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\query.exe'
            - '\reg.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\scriptrunner.exe'
            - '\sh.exe'
            - '\systeminfo.exe'
            - '\whoami.exe'
            - '\wmic.exe'        # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: high
```
