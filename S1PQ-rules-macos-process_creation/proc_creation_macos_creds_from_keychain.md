```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((tgt.process.image.path="/usr/bin/security" and (tgt.process.cmdline contains "find-certificate" or tgt.process.cmdline contains " export ")) or (tgt.process.cmdline contains " dump-keychain " or tgt.process.cmdline contains " login-keychain ")))
```


# Original Sigma Rule:
```yaml
title: Credentials from Password Stores - Keychain
id: b120b587-a4c2-4b94-875d-99c9807d6955
status: test
description: Detects passwords dumps from Keychain
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1555.001/T1555.001.md
    - https://gist.github.com/Capybara/6228955
author: Tim Ismilyaev, oscd.community, Florian Roth (Nextron Systems)
date: 2020-10-19
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1555.001
logsource:
    category: process_creation
    product: macos
detection:
    selection1:
        Image: '/usr/bin/security'
        CommandLine|contains:
            - 'find-certificate'
            - ' export '
    selection2:
        CommandLine|contains:
            - ' dump-keychain '
            - ' login-keychain '
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```
