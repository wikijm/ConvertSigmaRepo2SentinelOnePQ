```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "nhostsvc.exe" or src.process.image.path contains "nhstw32.exe" or src.process.image.path contains "ngstw32.exe" or src.process.image.path contains "Netop Ondemand.exe" or src.process.image.path contains "nldrw32.exe" or src.process.image.path contains "rmserverconsolemediator.exe" or src.process.image.path contains "ImperoInit.exe" or src.process.image.path="*Connect.Backdrop.cloud*.exe" or src.process.image.path contains "ImperoClientSVC.exe") or (tgt.process.image.path contains "nhostsvc.exe" or tgt.process.image.path contains "nhstw32.exe" or tgt.process.image.path contains "ngstw32.exe" or tgt.process.image.path contains "Netop Ondemand.exe" or tgt.process.image.path contains "nldrw32.exe" or tgt.process.image.path contains "rmserverconsolemediator.exe" or tgt.process.image.path contains "ImperoInit.exe" or tgt.process.image.path="*Connect.Backdrop.cloud*.exe" or tgt.process.image.path contains "ImperoClientSVC.exe")))
```


# Original Sigma Rule:
```yaml
title: Potential Netop Remote Control (Impero Connect) RMM Tool Process Activity
id: 49c92cec-cc90-4a41-97cf-91e8e47a051a
status: experimental
description: |
    Detects potential processes activity of Netop Remote Control (Impero Connect) RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.execution
    - attack.t1219
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith:
            - nhostsvc.exe
            - nhstw32.exe
            - ngstw32.exe
            - Netop Ondemand.exe
            - nldrw32.exe
            - rmserverconsolemediator.exe
            - ImperoInit.exe
            - Connect.Backdrop.cloud*.exe
            - ImperoClientSVC.exe
    selection_image:
        Image|endswith:
            - nhostsvc.exe
            - nhstw32.exe
            - ngstw32.exe
            - Netop Ondemand.exe
            - nldrw32.exe
            - rmserverconsolemediator.exe
            - ImperoInit.exe
            - Connect.Backdrop.cloud*.exe
            - ImperoClientSVC.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of Netop Remote Control (Impero Connect)
level: medium
```
