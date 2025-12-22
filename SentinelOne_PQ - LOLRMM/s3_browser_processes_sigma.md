```sql
// Translated content (automatically translated on 22-12-2025 00:58:15):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path="*s3browser*.exe" or tgt.process.image.path="*s3browser*.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential S3 Browser RMM Tool Process Activity
id: 45e32160-b7aa-4cc3-9bd8-5e2e6cce0b57
status: experimental
description: |
    Detects potential processes activity of S3 Browser RMM tool
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
        ParentImage|endswith: s3browser*.exe
    selection_image:
        Image|endswith: s3browser*.exe
    condition: 1 of selection_*
falsepositives:
    - Legitimate use of S3 Browser
level: medium
```
