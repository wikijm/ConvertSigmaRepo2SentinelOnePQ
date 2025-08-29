```sql
// Translated content (automatically translated on 29-08-2025 01:56:24):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline matches "\\w+`(\\w+|-|.)`[\\w+|\\s]" or tgt.process.cmdline matches ""(\\{\\d\\})+"\\s*-f" or tgt.process.cmdline matches "(?i)\\$\\{`?e`?n`?v`?:`?p`?a`?t`?h`?\\}") and (not tgt.process.cmdline contains "${env:path}")))
```


# Original Sigma Rule:
```yaml
title: Powershell Token Obfuscation - Process Creation
id: deb9b646-a508-44ee-b7c9-d8965921c6b6
related:
    - id: f3a98ce4-6164-4dd4-867c-4d83de7eca51
      type: similar
status: test
description: Detects TOKEN OBFUSCATION technique from Invoke-Obfuscation
references:
    - https://github.com/danielbohannon/Invoke-Obfuscation
author: frack113
date: 2022-12-27
modified: 2024-08-11
tags:
    - attack.defense-evasion
    - attack.t1027.009
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Examples:
        #   IN`V`o`Ke-eXp`ResSIOn (Ne`W-ob`ject Net.WebClient).DownloadString
        #   &('In'+'voke-Expressi'+'o'+'n') (.('New-Ob'+'jec'+'t') Net.WebClient).DownloadString
        #   &("{2}{3}{0}{4}{1}"-f 'e','Expression','I','nvok','-') (&("{0}{1}{2}"-f'N','ew-O','bject') Net.WebClient).DownloadString
        - CommandLine|re: '\w+`(\w+|-|.)`[\w+|\s]'
        # - CommandLine|re: '\((\'(\w|-|\.)+\'\+)+\'(\w|-|\.)+\'\)' TODO: fixme
        - CommandLine|re: '"(\{\d\})+"\s*-f'
        #   ${e`Nv:pATh}
        - CommandLine|re: '(?i)\$\{`?e`?n`?v`?:`?p`?a`?t`?h`?\}'
    filter_main_envpath:
        CommandLine|contains: '${env:path}'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
```
