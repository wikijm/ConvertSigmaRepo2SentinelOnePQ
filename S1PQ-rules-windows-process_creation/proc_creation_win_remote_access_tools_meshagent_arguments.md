```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "--meshServiceName")
```


# Original Sigma Rule:
```yaml
title: Remote Access Tool - Potential MeshAgent Execution - Windows
id: 2fbbe9ff-0afc-470b-bdc0-592198339968
related:
    - id: 22c45af6-f590-4d44-bab3-b5b2d2a2b6d9
      type: similar
status: experimental
description: |
    Detects potential execution of MeshAgent which is a tool used for remote access.
    Historical data shows that threat actors rename MeshAgent binary to evade detection.
    Matching command lines with the '--meshServiceName' argument can indicate that the MeshAgent is being used for remote access.
references:
    - https://www.huntress.com/blog/know-thy-enemy-a-novel-november-case-on-persistent-remote-access
    - https://thecyberexpress.com/ukraine-hit-by-meshagent-malware-campaign/
    - https://wazuh.com/blog/how-to-detect-meshagent-with-wazuh/
    - https://www.security.com/threat-intelligence/medusa-ransomware-attacks
author: Norbert Jaśniewicz (AlphaSOC)
date: 2025-05-19
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '--meshServiceName'
    condition: selection
falsepositives:
    - Environments that legitimately use MeshAgent
level: medium
```
