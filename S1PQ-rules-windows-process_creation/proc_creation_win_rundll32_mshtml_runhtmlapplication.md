```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "\\..\\" and tgt.process.cmdline contains "mshtml") and (tgt.process.cmdline contains "#135" or tgt.process.cmdline contains "RunHTMLApplication")))
```


# Original Sigma Rule:
```yaml
title: Mshtml.DLL RunHTMLApplication Suspicious Usage
id: 4782eb5a-a513-4523-a0ac-f3082b26ac5c
related:
    - id: 9f06447a-a33a-4cbe-a94f-a3f43184a7a3
      type: obsolete
    - id: 73fcad2e-ff14-4c38-b11d-4172c8ac86c7
      type: obsolete
status: test
description: |
    Detects execution of commands that leverage the "mshtml.dll" RunHTMLApplication export to run arbitrary code via different protocol handlers (vbscript, javascript, file, http...)
references:
    - https://twitter.com/n1nj4sec/status/1421190238081277959
    - https://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_TROJAN.WIN32.POWESSERE.G_MITIGATION_BYPASS_PART2.txt
    - http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt
author: Nasreddine Bencherchali (Nextron Systems),  Florian Roth (Nextron Systems), Josh Nickels, frack113, Zaw Min Htun (ZETA)
date: 2022-08-14
modified: 2024-02-23
tags:
    - attack.defense-evasion
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\..\'
            - 'mshtml'
        CommandLine|contains:
            - '#135'
            - 'RunHTMLApplication'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
