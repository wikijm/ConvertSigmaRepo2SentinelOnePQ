```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\pcalua.exe" and tgt.process.cmdline contains " -a"))
```


# Original Sigma Rule:
```yaml
title: Use of Pcalua For Execution
id: 0955e4e1-c281-4fb9-9ee1-5ee7b4b754d2
related:
    - id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
      type: obsolete
status: test
description: Detects execition of commands and binaries from the context of The program compatibility assistant (Pcalua.exe). This can be used as a LOLBIN in order to bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Pcalua/
    - https://pentestlab.blog/2020/07/06/indirect-command-execution/
author: Nasreddine Bencherchali (Nextron Systems), E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2022-06-14
modified: 2023-01-04
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\pcalua.exe'
        CommandLine|contains: ' -a' # No space after the flag because it accepts anything as long as there a "-a"
    condition: selection
falsepositives:
    - Legitimate use by a via a batch script or by an administrator.
level: medium
```
