```sql
// Translated content (automatically translated on 02-08-2025 00:52:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "ˣ" or tgt.process.cmdline contains "˪" or tgt.process.cmdline contains "ˢ" or tgt.process.cmdline contains "∕" or tgt.process.cmdline contains "⁄" or tgt.process.cmdline contains "―" or tgt.process.cmdline contains "—" or tgt.process.cmdline contains " " or tgt.process.cmdline contains "¯" or tgt.process.cmdline contains "®" or tgt.process.cmdline contains "¶"))
```


# Original Sigma Rule:
```yaml
title: Potential CommandLine Obfuscation Using Unicode Characters
id: e0552b19-5a83-4222-b141-b36184bb8d79
related:
    - id: 584bca0f-3608-4402-80fd-4075ff6072e3
      type: similar
    - id: ad691d92-15f2-4181-9aa4-723c74f9ddc3 # RTLO
      type: similar
    - id: 2c0d2d7b-30d6-4d14-9751-7b9113042ab9
      type: obsolete
status: test
description: |
    Detects potential CommandLine obfuscation using unicode characters.
    Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.
references:
    - https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1027/T1027.md#atomic-test-6---dlp-evasion-via-sensitive-data-in-vba-macro-over-http
author: frack113, Florian Roth (Nextron Systems)
date: 2022-01-15
modified: 2024-09-05
tags:
    - attack.defense-evasion
    - attack.t1027
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # spacing modifier letters that get auto-replaced
            - 'ˣ' # 0x02E3
            - '˪' # 0x02EA
            - 'ˢ' # 0x02E2
            # Forward slash alternatives
            - '∕' # 0x22FF
            - '⁄' # 0x206F
            # Hyphen alternatives
            - '―' # 0x2015
            - '—' # 0x2014
            # Whitespace that don't work as path separator
            - ' ' # 0x00A0
            # Other
            - '¯'
            - '®'
            - '¶'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
