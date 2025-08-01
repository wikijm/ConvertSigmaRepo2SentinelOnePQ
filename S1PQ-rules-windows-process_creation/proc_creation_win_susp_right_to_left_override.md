```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and tgt.process.cmdline contains "‮")
```


# Original Sigma Rule:
```yaml
title: Potential Defense Evasion Via Right-to-Left Override
id: ad691d92-15f2-4181-9aa4-723c74f9ddc3
related:
    - id: e0552b19-5a83-4222-b141-b36184bb8d79
      type: derived
    - id: 584bca0f-3608-4402-80fd-4075ff6072e3
      type: derived
status: test
description: |
    Detects the presence of the "u202+E" character, which causes a terminal, browser, or operating system to render text in a right-to-left sequence.
    This is used as an obfuscation and masquerading techniques.
references:
    - https://redcanary.com/blog/right-to-left-override/
    - https://www.malwarebytes.com/blog/news/2014/01/the-rtlo-method
    - https://unicode-explorer.com/c/202E
author: Micah Babinski, @micahbabinski
date: 2023-02-15
tags:
    - attack.defense-evasion
    - attack.t1036.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: "\u202e"
    condition: selection
falsepositives:
    - Commandlines that contains scriptures such as arabic or hebrew might make use of this character
level: high
```
