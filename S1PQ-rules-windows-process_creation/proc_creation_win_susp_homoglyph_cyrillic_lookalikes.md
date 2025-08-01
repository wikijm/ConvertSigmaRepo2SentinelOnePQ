```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "А" or tgt.process.cmdline contains "В" or tgt.process.cmdline contains "Е" or tgt.process.cmdline contains "К" or tgt.process.cmdline contains "М" or tgt.process.cmdline contains "Н" or tgt.process.cmdline contains "О" or tgt.process.cmdline contains "Р" or tgt.process.cmdline contains "С" or tgt.process.cmdline contains "Т" or tgt.process.cmdline contains "Х" or tgt.process.cmdline contains "Ѕ" or tgt.process.cmdline contains "І" or tgt.process.cmdline contains "Ј" or tgt.process.cmdline contains "Ү" or tgt.process.cmdline contains "Ӏ" or tgt.process.cmdline contains "Ԍ" or tgt.process.cmdline contains "Ԛ" or tgt.process.cmdline contains "Ԝ" or tgt.process.cmdline contains "Α" or tgt.process.cmdline contains "Β" or tgt.process.cmdline contains "Ε" or tgt.process.cmdline contains "Ζ" or tgt.process.cmdline contains "Η" or tgt.process.cmdline contains "Ι" or tgt.process.cmdline contains "Κ" or tgt.process.cmdline contains "Μ" or tgt.process.cmdline contains "Ν" or tgt.process.cmdline contains "Ο" or tgt.process.cmdline contains "Ρ" or tgt.process.cmdline contains "Τ" or tgt.process.cmdline contains "Υ" or tgt.process.cmdline contains "Χ") or (tgt.process.cmdline contains "а" or tgt.process.cmdline contains "е" or tgt.process.cmdline contains "о" or tgt.process.cmdline contains "р" or tgt.process.cmdline contains "с" or tgt.process.cmdline contains "х" or tgt.process.cmdline contains "ѕ" or tgt.process.cmdline contains "і" or tgt.process.cmdline contains "ӏ" or tgt.process.cmdline contains "ј" or tgt.process.cmdline contains "һ" or tgt.process.cmdline contains "ԁ" or tgt.process.cmdline contains "ԛ" or tgt.process.cmdline contains "ԝ" or tgt.process.cmdline contains "ο")))
```


# Original Sigma Rule:
```yaml
title: Potential Homoglyph Attack Using Lookalike Characters
id: 32e280f1-8ad4-46ef-9e80-910657611fbc
status: test
description: |
    Detects the presence of unicode characters which are homoglyphs, or identical in appearance, to ASCII letter characters.
    This is used as an obfuscation and masquerading techniques. Only "perfect" homoglyphs are included; these are characters that
    are indistinguishable from ASCII characters and thus may make excellent candidates for homoglyph attack characters.
references:
    - https://redcanary.com/threat-detection-report/threats/socgholish/#threat-socgholish
    - http://www.irongeek.com/homoglyph-attack-generator.php
author: Micah Babinski, @micahbabinski
date: 2023-05-07
tags:
    - attack.defense-evasion
    - attack.t1036
    - attack.t1036.003
   # - attack.t1036.008
logsource:
    category: process_creation
    product: windows
detection:
    selection_upper:
        CommandLine|contains:
            - "\u0410" # А/A
            - "\u0412" # В/B
            - "\u0415" # Е/E
            - "\u041a" # К/K
            - "\u041c" # М/M
            - "\u041d" # Н/H
            - "\u041e" # О/O
            - "\u0420" # Р/P
            - "\u0421" # С/C
            - "\u0422" # Т/T
            - "\u0425" # Х/X
            - "\u0405" # Ѕ/S
            - "\u0406" # І/I
            - "\u0408" # Ј/J
            - "\u04ae" # Ү/Y
            - "\u04c0" # Ӏ/I
            - "\u050C" # Ԍ/G
            - "\u051a" # Ԛ/Q
            - "\u051c" # Ԝ/W
            - "\u0391" # Α/A
            - "\u0392" # Β/B
            - "\u0395" # Ε/E
            - "\u0396" # Ζ/Z
            - "\u0397" # Η/H
            - "\u0399" # Ι/I
            - "\u039a" # Κ/K
            - "\u039c" # Μ/M
            - "\u039d" # Ν/N
            - "\u039f" # Ο/O
            - "\u03a1" # Ρ/P
            - "\u03a4" # Τ/T
            - "\u03a5" # Υ/Y
            - "\u03a7" # Χ/X
    selection_lower:
        CommandLine|contains:
            - "\u0430" # а/a
            - "\u0435" # е/e
            - "\u043e" # о/o
            - "\u0440" # р/p
            - "\u0441" # с/c
            - "\u0445" # х/x
            - "\u0455" # ѕ/s
            - "\u0456" # і/i
            - "\u04cf" # ӏ/l
            - "\u0458" # ј/j
            - "\u04bb" # һ/h
            - "\u0501" # ԁ/d
            - "\u051b" # ԛ/q
            - "\u051d" # ԝ/w
            - "\u03bf" # ο/o
    condition: 1 of selection_*
falsepositives:
    - Commandlines with legitimate Cyrillic text; will likely require tuning (or not be usable) in countries where these alphabets are in use.
level: medium
```
