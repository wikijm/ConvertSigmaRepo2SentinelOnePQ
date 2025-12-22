```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.cmdline contains "OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ" or tgt.process.cmdline contains "oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA" or tgt.process.cmdline contains "6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA" or tgt.process.cmdline contains "OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ" or tgt.process.cmdline contains "oAOgAoACIATABvACIAKwAiAGEAZAAiACkA" or tgt.process.cmdline contains "6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA" or tgt.process.cmdline contains "OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ" or tgt.process.cmdline contains "oAOgAoACIATABvAGEAIgArACIAZAAiACkA" or tgt.process.cmdline contains "6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA" or tgt.process.cmdline contains "OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ" or tgt.process.cmdline contains "oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA" or tgt.process.cmdline contains "6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA" or tgt.process.cmdline contains "OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ" or tgt.process.cmdline contains "oAOgAoACcATABvACcAKwAnAGEAZAAnACkA" or tgt.process.cmdline contains "6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA" or tgt.process.cmdline contains "OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ" or tgt.process.cmdline contains "oAOgAoACcATABvAGEAJwArACcAZAAnACkA" or tgt.process.cmdline contains "6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA"))
```


# Original Sigma Rule:
```yaml
title: Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call
id: 9c0295ce-d60d-40bd-bd74-84673b7592b1
related:
    - id: 62b7ccc9-23b4-471e-aa15-6da3663c4d59
      type: similar
status: test
description: Detects suspicious base64 encoded and obfuscated "LOAD" keyword used in .NET "reflection.assembly"
references:
    - https://github.com/Neo23x0/Raccine/blob/20a569fa21625086433dcce8bb2765d0ea08dcb6/yara/mal_revil.yar
    - https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
    - https://learn.microsoft.com/en-us/dotnet/api/system.appdomain.load?view=net-7.0
author: pH-T (Nextron Systems)
date: 2022-03-01
modified: 2023-04-06
tags:
    - attack.execution
    - attack.defense-evasion
    - attack.t1059.001
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # ::("L"+"oad")
            - 'OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ'
            - 'oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA'
            - '6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA'
            # ::("Lo"+"ad")
            - 'OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ'
            - 'oAOgAoACIATABvACIAKwAiAGEAZAAiACkA'
            - '6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA'
            # ::("Loa"+"d")
            - 'OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ'
            - 'oAOgAoACIATABvAGEAIgArACIAZAAiACkA'
            - '6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA'
            # ::('L'+'oad')
            - 'OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ'
            - 'oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA'
            - '6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA'
            # ::('Lo'+'ad')
            - 'OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ'
            - 'oAOgAoACcATABvACcAKwAnAGEAZAAnACkA'
            - '6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA'
            # ::('Loa'+'d')
            - 'OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ'
            - 'oAOgAoACcATABvAGEAJwArACcAZAAnACkA'
            - '6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
