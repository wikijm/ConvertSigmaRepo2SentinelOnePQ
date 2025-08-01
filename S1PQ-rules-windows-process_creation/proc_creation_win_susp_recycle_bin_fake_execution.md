```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "RECYCLERS.BIN\" or tgt.process.image.path contains "RECYCLER.BIN\"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process Execution From Fake Recycle.Bin Folder
id: 5ce0f04e-3efc-42af-839d-5b3a543b76c0
related:
    - id: cd8b36ac-8e4a-4c2f-a402-a29b8fbd5bca
      type: derived
status: test
description: Detects process execution from a fake recycle bin folder, often used to avoid security solution.
references:
    - https://www.mandiant.com/resources/blog/infected-usb-steal-secrets
    - https://unit42.paloaltonetworks.com/cloaked-ursa-phishing/
author: X__Junior (Nextron Systems)
date: 2023-07-12
modified: 2023-12-11
tags:
    - attack.persistence
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            # e.g. C:\$RECYCLER.BIN
            - 'RECYCLERS.BIN\'
            - 'RECYCLER.BIN\'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
