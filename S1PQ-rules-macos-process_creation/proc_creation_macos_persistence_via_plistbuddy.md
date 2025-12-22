```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (tgt.process.image.path contains "/PlistBuddy" and (tgt.process.cmdline contains "RunAtLoad" and tgt.process.cmdline contains "true") and (tgt.process.cmdline contains "LaunchAgents" or tgt.process.cmdline contains "LaunchDaemons")))
```


# Original Sigma Rule:
```yaml
title: Potential Persistence Via PlistBuddy
id: 65d506d3-fcfe-4071-b4b2-bcefe721bbbb
status: test
description: Detects potential persistence activity using LaunchAgents or LaunchDaemons via the PlistBuddy utility
references:
    - https://redcanary.com/blog/clipping-silver-sparrows-wings/
    - https://www.manpagez.com/man/8/PlistBuddy/
author: Sohan G (D4rkCiph3r)
date: 2023-02-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1543.001
    - attack.t1543.004
logsource:
    category: process_creation
    product: macos
detection:
    selection:
        Image|endswith: '/PlistBuddy'
        CommandLine|contains|all:
            - 'RunAtLoad'
            - 'true'
        CommandLine|contains:
            - 'LaunchAgents'
            - 'LaunchDaemons'
    condition: selection
falsepositives:
    - Unknown
level: high
```
