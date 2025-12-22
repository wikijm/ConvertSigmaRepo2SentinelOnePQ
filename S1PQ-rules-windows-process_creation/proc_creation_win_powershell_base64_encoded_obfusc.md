```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "IAAtAGIAeABvAHIAIAAwAHgA" or tgt.process.cmdline contains "AALQBiAHgAbwByACAAMAB4A" or tgt.process.cmdline contains "gAC0AYgB4AG8AcgAgADAAeA" or tgt.process.cmdline contains "AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg" or tgt.process.cmdline contains "AuAEkAbgB2AG8AawBlACgAKQAgAHwAI" or tgt.process.cmdline contains "ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC" or tgt.process.cmdline contains "AHsAMQB9AHsAMAB9ACIAIAAtAGYAI" or tgt.process.cmdline contains "B7ADEAfQB7ADAAfQAiACAALQBmAC" or tgt.process.cmdline contains "AewAxAH0AewAwAH0AIgAgAC0AZgAg" or tgt.process.cmdline contains "AHsAMAB9AHsAMwB9ACIAIAAtAGYAI" or tgt.process.cmdline contains "B7ADAAfQB7ADMAfQAiACAALQBmAC" or tgt.process.cmdline contains "AewAwAH0AewAzAH0AIgAgAC0AZgAg" or tgt.process.cmdline contains "AHsAMgB9AHsAMAB9ACIAIAAtAGYAI" or tgt.process.cmdline contains "B7ADIAfQB7ADAAfQAiACAALQBmAC" or tgt.process.cmdline contains "AewAyAH0AewAwAH0AIgAgAC0AZgAg" or tgt.process.cmdline contains "AHsAMQB9AHsAMAB9ACcAIAAtAGYAI" or tgt.process.cmdline contains "B7ADEAfQB7ADAAfQAnACAALQBmAC" or tgt.process.cmdline contains "AewAxAH0AewAwAH0AJwAgAC0AZgAg" or tgt.process.cmdline contains "AHsAMAB9AHsAMwB9ACcAIAAtAGYAI" or tgt.process.cmdline contains "B7ADAAfQB7ADMAfQAnACAALQBmAC" or tgt.process.cmdline contains "AewAwAH0AewAzAH0AJwAgAC0AZgAg" or tgt.process.cmdline contains "AHsAMgB9AHsAMAB9ACcAIAAtAGYAI" or tgt.process.cmdline contains "B7ADIAfQB7ADAAfQAnACAALQBmAC" or tgt.process.cmdline contains "AewAyAH0AewAwAH0AJwAgAC0AZgAg"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Obfuscated PowerShell Code
id: 8d01b53f-456f-48ee-90f6-bc28e67d4e35
status: test
description: Detects suspicious UTF16 and base64 encoded and often obfuscated PowerShell code often used in command lines
references:
    - https://app.any.run/tasks/fcadca91-3580-4ede-aff4-4d2bf809bf99/
author: Florian Roth (Nextron Systems)
date: 2022-07-11
modified: 2023-02-14
tags:
    - attack.defense-evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            #  -bxor 0x
            - 'IAAtAGIAeABvAHIAIAAwAHgA'
            - 'AALQBiAHgAbwByACAAMAB4A'
            - 'gAC0AYgB4AG8AcgAgADAAeA'
            # .Invoke() |
            - 'AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg'
            - 'AuAEkAbgB2AG8AawBlACgAKQAgAHwAI'
            - 'ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC'
            # {1}{0}" -f
            # {0}{3}" -f
            # {2}{0}" -f
            - 'AHsAMQB9AHsAMAB9ACIAIAAtAGYAI'
            - 'B7ADEAfQB7ADAAfQAiACAALQBmAC'
            - 'AewAxAH0AewAwAH0AIgAgAC0AZgAg'
            - 'AHsAMAB9AHsAMwB9ACIAIAAtAGYAI'
            - 'B7ADAAfQB7ADMAfQAiACAALQBmAC'
            - 'AewAwAH0AewAzAH0AIgAgAC0AZgAg'
            - 'AHsAMgB9AHsAMAB9ACIAIAAtAGYAI'
            - 'B7ADIAfQB7ADAAfQAiACAALQBmAC'
            - 'AewAyAH0AewAwAH0AIgAgAC0AZgAg'
            # {1}{0}' -f
            # {0}{3}' -f
            # {2}{0}' -f
            - 'AHsAMQB9AHsAMAB9ACcAIAAtAGYAI'
            - 'B7ADEAfQB7ADAAfQAnACAALQBmAC'
            - 'AewAxAH0AewAwAH0AJwAgAC0AZgAg'
            - 'AHsAMAB9AHsAMwB9ACcAIAAtAGYAI'
            - 'B7ADAAfQB7ADMAfQAnACAALQBmAC'
            - 'AewAwAH0AewAzAH0AJwAgAC0AZgAg'
            - 'AHsAMgB9AHsAMAB9ACcAIAAtAGYAI'
            - 'B7ADIAfQB7ADAAfQAnACAALQBmAC'
            - 'AewAyAH0AewAwAH0AJwAgAC0AZgAg'
    condition: selection
falsepositives:
    - Unknown
level: high
```
