```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and ((src.process.image.path contains "Microsoft Word" or src.process.image.path contains "Microsoft Excel" or src.process.image.path contains "Microsoft PowerPoint" or src.process.image.path contains "Microsoft OneNote") and (tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/curl" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/fish" or tgt.process.image.path contains "/osacompile" or tgt.process.image.path contains "/osascript" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/zsh" or tgt.process.image.path contains "/python" or tgt.process.image.path contains "/python3" or tgt.process.image.path contains "/wget")))
```


# Original Sigma Rule:
```yaml
title: Suspicious Microsoft Office Child Process - MacOS
id: 69483748-1525-4a6c-95ca-90dc8d431b68
status: test
description: Detects suspicious child processes spawning from microsoft office suite applications such as word or excel. This could indicates malicious macro execution
references:
    - https://redcanary.com/blog/applescript/
    - https://objective-see.org/blog/blog_0x4B.html
author: Sohan G (D4rkCiph3r)
date: 2023-01-31
modified: 2023-02-04
tags:
    - attack.execution
    - attack.persistence
    - attack.t1059.002
    - attack.t1137.002
    - attack.t1204.002
logsource:
    product: macos
    category: process_creation
detection:
    selection:
        ParentImage|contains:
            - 'Microsoft Word'
            - 'Microsoft Excel'
            - 'Microsoft PowerPoint'
            - 'Microsoft OneNote'
        Image|endswith:
            - '/bash'
            - '/curl'
            - '/dash'
            - '/fish'
            - '/osacompile'
            - '/osascript'
            - '/sh'
            - '/zsh'
            - '/python'
            - '/python3'
            - '/wget'
    condition: selection
falsepositives:
    - Unknown
level: high
```
