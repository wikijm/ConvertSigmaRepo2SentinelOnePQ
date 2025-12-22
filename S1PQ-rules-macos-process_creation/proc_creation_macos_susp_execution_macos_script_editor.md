```sql
// Translated content (automatically translated on 22-12-2025 01:26:43):
event.type="Process Creation" and (endpoint.os="osx" and (src.process.image.path contains "/Script Editor" and ((tgt.process.image.path contains "/curl" or tgt.process.image.path contains "/bash" or tgt.process.image.path contains "/sh" or tgt.process.image.path contains "/zsh" or tgt.process.image.path contains "/dash" or tgt.process.image.path contains "/fish" or tgt.process.image.path contains "/osascript" or tgt.process.image.path contains "/mktemp" or tgt.process.image.path contains "/chmod" or tgt.process.image.path contains "/php" or tgt.process.image.path contains "/nohup" or tgt.process.image.path contains "/openssl" or tgt.process.image.path contains "/plutil" or tgt.process.image.path contains "/PlistBuddy" or tgt.process.image.path contains "/xattr" or tgt.process.image.path contains "/sqlite" or tgt.process.image.path contains "/funzip" or tgt.process.image.path contains "/popen") or (tgt.process.image.path contains "python" or tgt.process.image.path contains "perl"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Execution via macOS Script Editor
id: 6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4
status: test
description: Detects when the macOS Script Editor utility spawns an unusual child process.
author: Tim Rauch (rule), Elastic (idea)
references:
    - https://github.com/elastic/protections-artifacts/commit/746086721fd385d9f5c6647cada1788db4aea95f#diff-7f541fbc4a4a28a92970e8bf53effea5bd934604429112c920affb457f5b2685
    - https://wojciechregula.blog/post/macos-red-teaming-initial-access-via-applescript-url/
date: 2022-10-21
modified: 2022-12-28
logsource:
    category: process_creation
    product: macos
tags:
    - attack.t1566
    - attack.t1566.002
    - attack.initial-access
    - attack.t1059
    - attack.t1059.002
    - attack.t1204
    - attack.t1204.001
    - attack.execution
    - attack.persistence
    - attack.t1553
    - attack.defense-evasion
detection:
    selection_parent:
        ParentImage|endswith: '/Script Editor'
    selection_img:
        - Image|endswith:
              - '/curl'
              - '/bash'
              - '/sh'
              - '/zsh'
              - '/dash'
              - '/fish'
              - '/osascript'
              - '/mktemp'
              - '/chmod'
              - '/php'
              - '/nohup'
              - '/openssl'
              - '/plutil'
              - '/PlistBuddy'
              - '/xattr'
              - '/sqlite'
              - '/funzip'
              - '/popen'
        - Image|contains:
              - 'python'
              - 'perl'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
