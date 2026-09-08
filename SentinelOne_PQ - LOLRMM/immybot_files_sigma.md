```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files\\ImmyBot\*" or tgt.file.path contains "C:\\Program Files (x86)\\ImmyBot\*" or tgt.file.path contains "C:\\ProgramData\\ImmyBot\\Logs\*" or tgt.file.path contains "C:\\ProgramData\\ImmyBot\\Scripts\*" or tgt.file.path contains "C:\\ProgramData\\ImmyBotAgentService\\config.json" or tgt.file.path contains "C:\\Windows\\Temp\\ImmyBot\*"))
```


# Original Sigma Rule:
```yaml
title: Potential ImmyBot RMM Tool File Activity
id: 86e417fd-8e4d-51a5-b6f4-68e57e4f8da5
status: experimental
description: |
    Detects potential files activity of ImmyBot RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\Program Files\ImmyBot\*'
            - 'C:\Program Files (x86)\ImmyBot\*'
            - 'C:\ProgramData\ImmyBot\Logs\*'
            - 'C:\ProgramData\ImmyBot\Scripts\*'
            - 'C:\ProgramData\ImmyBotAgentService\config.json'
            - 'C:\Windows\Temp\ImmyBot\*'
    condition: selection
falsepositives:
    - Legitimate use of ImmyBot
level: medium
```
