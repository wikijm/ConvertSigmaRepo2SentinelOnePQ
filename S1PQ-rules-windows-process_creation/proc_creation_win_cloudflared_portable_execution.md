```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\cloudflared.exe" and (not (tgt.process.image.path contains ":\Program Files (x86)\cloudflared\" or tgt.process.image.path contains ":\Program Files\cloudflared\"))))
```


# Original Sigma Rule:
```yaml
title: Cloudflared Portable Execution
id: fadb84f0-4e84-4f6d-a1ce-9ef2bffb6ccd
status: test
description: |
    Detects the execution of the "cloudflared" binary from a non standard location.
references:
    - https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/
    - https://github.com/cloudflare/cloudflared
    - https://www.intrinsec.com/akira_ransomware/
    - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
    - https://github.com/cloudflare/cloudflared/releases
author: Nasreddine Bencherchali (Nextron Systems)
tags:
    - attack.command-and-control
    - attack.t1090.001
date: 2023-12-20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cloudflared.exe'
    filter_main_admin_location:
        Image|contains:
            - ':\Program Files (x86)\cloudflared\'
            - ':\Program Files\cloudflared\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Legitimate usage of Cloudflared portable versions
level: medium
```
