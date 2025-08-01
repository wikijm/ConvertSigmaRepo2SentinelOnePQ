```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\explorer.exe" or src.process.cmdline contains ".lnk") and ((tgt.process.cmdline contains "                 " or tgt.process.cmdline contains "\u0009" or tgt.process.cmdline contains "\u000A" or tgt.process.cmdline contains "\u0011" or tgt.process.cmdline contains "\u0012" or tgt.process.cmdline contains "\u0013" or tgt.process.cmdline contains "\u000B" or tgt.process.cmdline contains "\u000C" or tgt.process.cmdline contains "\u000D") or tgt.process.cmdline matches "\\n\\n\\n\\n\\n\\n")))
```


# Original Sigma Rule:
```yaml
title: Suspicious LNK Command-Line Padding with Whitespace Characters
id: dd8756e7-a3a0-4768-b47e-8f545d1a751c
status: experimental
description: |
    Detects exploitation of LNK file command-line length discrepancy, where attackers hide malicious commands beyond the 260-character UI limit while the actual command-line argument field supports 4096 characters using whitespace padding (e.g., 0x20, 0x09-0x0D).
    Adversaries insert non-printable whitespace characters (e.g., Line Feed \x0A, Carriage Return \x0D) to pad the visible section of the LNK file, pushing malicious commands past the UI-visible boundary.
    The hidden payload, executed at runtime but invisible in Windows Explorer properties, enables stealthy execution and evasion—commonly used for social engineering attacks.
    This rule flags suspicious use of such padding observed in real-world attacks.
references:
    - https://syedhasan010.medium.com/forensics-analysis-of-an-lnk-file-da68a98b8415
    - https://thehackernews.com/2025/03/unpatched-windows-zero-day-flaw.html
    - https://www.trendmicro.com/en_us/research/25/c/windows-shortcut-zero-day-exploit.html
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-03-19
tags:
    - attack.initial-access
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - ParentImage|endswith: '\explorer.exe'
        - ParentCommandLine|contains: '.lnk'
    selection_cmd:
        - CommandLine|contains:
              - '                 '  # Padding of SPACE (0x20)
            # - '	'  # Horizontal Tab (0x9)
              - '\u0009'
              - '\u000A' # Line Feed
              - '\u0011'
              - '\u0012'
              - '\u0013'
              - '\u000B' # Vertical Tab
              - '\u000C'  # \x0C
              - '\u000D'  # \x0D
        - CommandLine|re: '\n\n\n\n\n\n' # In some cases \u000[ABCD] are represented as a newline in the eventlog
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
