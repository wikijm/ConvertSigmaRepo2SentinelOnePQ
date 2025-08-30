```sql
// Translated content (automatically translated on 30-08-2025 01:50:47):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains "QWRkLU1wUHJlZmVyZW5jZS" or tgt.process.cmdline contains "FkZC1NcFByZWZlcmVuY2Ug" or tgt.process.cmdline contains "BZGQtTXBQcmVmZXJlbmNlI" or tgt.process.cmdline contains "U2V0LU1wUHJlZmVyZW5jZS" or tgt.process.cmdline contains "NldC1NcFByZWZlcmVuY2Ug" or tgt.process.cmdline contains "TZXQtTXBQcmVmZXJlbmNlI" or tgt.process.cmdline contains "YWRkLW1wcHJlZmVyZW5jZS" or tgt.process.cmdline contains "FkZC1tcHByZWZlcmVuY2Ug" or tgt.process.cmdline contains "hZGQtbXBwcmVmZXJlbmNlI" or tgt.process.cmdline contains "c2V0LW1wcHJlZmVyZW5jZS" or tgt.process.cmdline contains "NldC1tcHByZWZlcmVuY2Ug" or tgt.process.cmdline contains "zZXQtbXBwcmVmZXJlbmNlI") or (tgt.process.cmdline contains "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" or tgt.process.cmdline contains "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" or tgt.process.cmdline contains "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" or tgt.process.cmdline contains "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" or tgt.process.cmdline contains "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" or tgt.process.cmdline contains "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" or tgt.process.cmdline contains "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" or tgt.process.cmdline contains "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" or tgt.process.cmdline contains "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA" or tgt.process.cmdline contains "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" or tgt.process.cmdline contains "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" or tgt.process.cmdline contains "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA")))
```


# Original Sigma Rule:
```yaml
title: Powershell Base64 Encoded MpPreference Cmdlet
id: c6fb44c6-71f5-49e6-9462-1425d328aee3
status: test
description: Detects base64 encoded "MpPreference" PowerShell cmdlet code that tries to modifies or tamper with Windows Defender AV
references:
    - https://learn.microsoft.com/en-us/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://twitter.com/AdamTheAnalyst/status/1483497517119590403
author: Florian Roth (Nextron Systems)
date: 2022-03-04
modified: 2023-01-30
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|base64offset|contains:
              - 'Add-MpPreference '
              - 'Set-MpPreference '
              - 'add-mppreference '
              - 'set-mppreference '
        - CommandLine|contains:
              # UTF16-LE
              - 'QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA'
              - 'EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA'
              - 'BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA'
              - 'UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA'
              - 'MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA'
              - 'TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA'
              - 'YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA'
              - 'EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA'
              - 'hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA'
              - 'cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA'
              - 'MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA'
              - 'zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA'
    condition: selection
falsepositives:
    - Unknown
level: high
```
