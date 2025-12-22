```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "Add-MpPreference " or tgt.process.cmdline contains "Set-MpPreference ") and (tgt.process.cmdline contains "DisableArchiveScanning " or tgt.process.cmdline contains "DisableRealtimeMonitoring " or tgt.process.cmdline contains "DisableIOAVProtection " or tgt.process.cmdline contains "DisableBehaviorMonitoring " or tgt.process.cmdline contains "DisableBlockAtFirstSeen " or tgt.process.cmdline contains "DisableCatchupFullScan " or tgt.process.cmdline contains "DisableCatchupQuickScan ") and (tgt.process.cmdline contains "$true" or tgt.process.cmdline contains " 1 ")) or ((tgt.process.cmdline contains "ZGlzYWJsZWFyY2hpdmVzY2FubmluZy" or tgt.process.cmdline contains "Rpc2FibGVhcmNoaXZlc2Nhbm5pbmcg" or tgt.process.cmdline contains "kaXNhYmxlYXJjaGl2ZXNjYW5uaW5nI" or tgt.process.cmdline contains "RGlzYWJsZUFyY2hpdmVTY2FubmluZy" or tgt.process.cmdline contains "Rpc2FibGVBcmNoaXZlU2Nhbm5pbmcg" or tgt.process.cmdline contains "EaXNhYmxlQXJjaGl2ZVNjYW5uaW5nI" or tgt.process.cmdline contains "ZGlzYWJsZWJlaGF2aW9ybW9uaXRvcmluZy" or tgt.process.cmdline contains "Rpc2FibGViZWhhdmlvcm1vbml0b3Jpbmcg" or tgt.process.cmdline contains "kaXNhYmxlYmVoYXZpb3Jtb25pdG9yaW5nI" or tgt.process.cmdline contains "RGlzYWJsZUJlaGF2aW9yTW9uaXRvcmluZy" or tgt.process.cmdline contains "Rpc2FibGVCZWhhdmlvck1vbml0b3Jpbmcg" or tgt.process.cmdline contains "EaXNhYmxlQmVoYXZpb3JNb25pdG9yaW5nI" or tgt.process.cmdline contains "ZGlzYWJsZWJsb2NrYXRmaXJzdHNlZW4g" or tgt.process.cmdline contains "Rpc2FibGVibG9ja2F0Zmlyc3RzZWVuI" or tgt.process.cmdline contains "kaXNhYmxlYmxvY2thdGZpcnN0c2Vlbi" or tgt.process.cmdline contains "RGlzYWJsZUJsb2NrQXRGaXJzdFNlZW4g" or tgt.process.cmdline contains "Rpc2FibGVCbG9ja0F0Rmlyc3RTZWVuI" or tgt.process.cmdline contains "EaXNhYmxlQmxvY2tBdEZpcnN0U2Vlbi" or tgt.process.cmdline contains "ZGlzYWJsZWNhdGNodXBmdWxsc2Nhbi" or tgt.process.cmdline contains "Rpc2FibGVjYXRjaHVwZnVsbHNjYW4g" or tgt.process.cmdline contains "kaXNhYmxlY2F0Y2h1cGZ1bGxzY2FuI" or tgt.process.cmdline contains "RGlzYWJsZUNhdGNodXBGdWxsU2Nhbi" or tgt.process.cmdline contains "Rpc2FibGVDYXRjaHVwRnVsbFNjYW4g" or tgt.process.cmdline contains "EaXNhYmxlQ2F0Y2h1cEZ1bGxTY2FuI" or tgt.process.cmdline contains "ZGlzYWJsZWNhdGNodXBxdWlja3NjYW4g" or tgt.process.cmdline contains "Rpc2FibGVjYXRjaHVwcXVpY2tzY2FuI" or tgt.process.cmdline contains "kaXNhYmxlY2F0Y2h1cHF1aWNrc2Nhbi" or tgt.process.cmdline contains "RGlzYWJsZUNhdGNodXBRdWlja1NjYW4g" or tgt.process.cmdline contains "Rpc2FibGVDYXRjaHVwUXVpY2tTY2FuI" or tgt.process.cmdline contains "EaXNhYmxlQ2F0Y2h1cFF1aWNrU2Nhbi" or tgt.process.cmdline contains "ZGlzYWJsZWlvYXZwcm90ZWN0aW9uI" or tgt.process.cmdline contains "Rpc2FibGVpb2F2cHJvdGVjdGlvbi" or tgt.process.cmdline contains "kaXNhYmxlaW9hdnByb3RlY3Rpb24g" or tgt.process.cmdline contains "RGlzYWJsZUlPQVZQcm90ZWN0aW9uI" or tgt.process.cmdline contains "Rpc2FibGVJT0FWUHJvdGVjdGlvbi" or tgt.process.cmdline contains "EaXNhYmxlSU9BVlByb3RlY3Rpb24g" or tgt.process.cmdline contains "ZGlzYWJsZXJlYWx0aW1lbW9uaXRvcmluZy" or tgt.process.cmdline contains "Rpc2FibGVyZWFsdGltZW1vbml0b3Jpbmcg" or tgt.process.cmdline contains "kaXNhYmxlcmVhbHRpbWVtb25pdG9yaW5nI" or tgt.process.cmdline contains "RGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZy" or tgt.process.cmdline contains "Rpc2FibGVSZWFsdGltZU1vbml0b3Jpbmcg" or tgt.process.cmdline contains "EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nI") or (tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAUgBlAGEAbAB0AGkAbQBlAE0AbwBuAGkAdABvAHIAaQBuAGcAIA" or tgt.process.cmdline contains "EAGkAcwBhAGIAbABlAFIAZQBhAGwAdABpAG0AZQBNAG8AbgBpAHQAbwByAGkAbgBnACAA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBJAE8AQQBWAFAAcgBvAHQAZQBjAHQAaQBvAG4AIA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUASQBPAEEAVgBQAHIAbwB0AGUAYwB0AGkAbwBuACAA" or tgt.process.cmdline contains "EAGkAcwBhAGIAbABlAEkATwBBAFYAUAByAG8AdABlAGMAdABpAG8AbgAgA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBCAGUAaABhAHYAaQBvAHIATQBvAG4AaQB0AG8AcgBpAG4AZwAgA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAQgBlAGgAYQB2AGkAbwByAE0AbwBuAGkAdABvAHIAaQBuAGcAIA" or tgt.process.cmdline contains "EAGkAcwBhAGIAbABlAEIAZQBoAGEAdgBpAG8AcgBNAG8AbgBpAHQAbwByAGkAbgBnACAA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBCAGwAbwBjAGsAQQB0AEYAaQByAHMAdABTAGUAZQBuACAA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAQgBsAG8AYwBrAEEAdABGAGkAcgBzAHQAUwBlAGUAbgAgA" or tgt.process.cmdline contains "EAGkAcwBhAGIAbABlAEIAbABvAGMAawBBAHQARgBpAHIAcwB0AFMAZQBlAG4AIA" or tgt.process.cmdline contains "ZABpAHMAYQBiAGwAZQByAGUAYQBsAHQAaQBtAGUAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAcgBlAGEAbAB0AGkAbQBlAG0AbwBuAGkAdABvAHIAaQBuAGcAIA" or tgt.process.cmdline contains "kAGkAcwBhAGIAbABlAHIAZQBhAGwAdABpAG0AZQBtAG8AbgBpAHQAbwByAGkAbgBnACAA" or tgt.process.cmdline contains "ZABpAHMAYQBiAGwAZQBpAG8AYQB2AHAAcgBvAHQAZQBjAHQAaQBvAG4AIA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAaQBvAGEAdgBwAHIAbwB0AGUAYwB0AGkAbwBuACAA" or tgt.process.cmdline contains "kAGkAcwBhAGIAbABlAGkAbwBhAHYAcAByAG8AdABlAGMAdABpAG8AbgAgA" or tgt.process.cmdline contains "ZABpAHMAYQBiAGwAZQBiAGUAaABhAHYAaQBvAHIAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAYgBlAGgAYQB2AGkAbwByAG0AbwBuAGkAdABvAHIAaQBuAGcAIA" or tgt.process.cmdline contains "kAGkAcwBhAGIAbABlAGIAZQBoAGEAdgBpAG8AcgBtAG8AbgBpAHQAbwByAGkAbgBnACAA" or tgt.process.cmdline contains "ZABpAHMAYQBiAGwAZQBiAGwAbwBjAGsAYQB0AGYAaQByAHMAdABzAGUAZQBuACAA" or tgt.process.cmdline contains "QAaQBzAGEAYgBsAGUAYgBsAG8AYwBrAGEAdABmAGkAcgBzAHQAcwBlAGUAbgAgA" or tgt.process.cmdline contains "kAGkAcwBhAGIAbABlAGIAbABvAGMAawBhAHQAZgBpAHIAcwB0AHMAZQBlAG4AIA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBDAGEAdABjAGgAdQBwAEYAdQBsAGwAUwBjAGEAbgA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBDAGEAdABjAGgAdQBwAFEAdQBpAGMAawBTAGMAYQBuAA" or tgt.process.cmdline contains "RABpAHMAYQBiAGwAZQBBAHIAYwBoAGkAdgBlAFMAYwBhAG4AbgBpAG4AZwA"))))
```


# Original Sigma Rule:
```yaml
title: Powershell Defender Disable Scan Feature
id: 1ec65a5f-9473-4f12-97da-622044d6df21
status: test
description: Detects requests to disable Microsoft Defender features using PowerShell commands
references:
    - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
    - https://www.virustotal.com/gui/file/d609799091731d83d75ec5d1f030571af20c45efeeb94840b67ea09a3283ab65/behavior/C2AE
    - https://www.virustotal.com/gui/search/content%253A%2522Set-MpPreference%2520-Disable%2522/files
author: Florian Roth (Nextron Systems)
date: 2022-03-03
modified: 2024-01-02
tags:
    - attack.defense-evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_cli_cmdlet:
        CommandLine|contains:
            - 'Add-MpPreference '
            - 'Set-MpPreference '
    selection_cli_option:
        CommandLine|contains:
            - 'DisableArchiveScanning '
            - 'DisableRealtimeMonitoring '
            - 'DisableIOAVProtection '
            - 'DisableBehaviorMonitoring '
            - 'DisableBlockAtFirstSeen '
            - 'DisableCatchupFullScan '
            - 'DisableCatchupQuickScan '
    selection_cli_value:
        CommandLine|contains:
            - '$true'
            - ' 1 '
    selection_encoded_modifier:
        CommandLine|base64offset|contains:
            # Note: Since this is calculating offsets casing is important
            - 'disablearchivescanning '
            - 'DisableArchiveScanning '
            - 'disablebehaviormonitoring '
            - 'DisableBehaviorMonitoring '
            - 'disableblockatfirstseen '
            - 'DisableBlockAtFirstSeen '
            - 'disablecatchupfullscan '
            - 'DisableCatchupFullScan '
            - 'disablecatchupquickscan '
            - 'DisableCatchupQuickScan '
            - 'disableioavprotection '
            - 'DisableIOAVProtection '
            - 'disablerealtimemonitoring '
            - 'DisableRealtimeMonitoring '
    selection_encoded_direct:
        CommandLine|contains:
            - 'RABpAHMAYQBiAGwAZQBSAGUAYQBsAHQAaQBtAGUATQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAUgBlAGEAbAB0AGkAbQBlAE0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'EAGkAcwBhAGIAbABlAFIAZQBhAGwAdABpAG0AZQBNAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'RABpAHMAYQBiAGwAZQBJAE8AQQBWAFAAcgBvAHQAZQBjAHQAaQBvAG4AIA'
            - 'QAaQBzAGEAYgBsAGUASQBPAEEAVgBQAHIAbwB0AGUAYwB0AGkAbwBuACAA'
            - 'EAGkAcwBhAGIAbABlAEkATwBBAFYAUAByAG8AdABlAGMAdABpAG8AbgAgA'
            - 'RABpAHMAYQBiAGwAZQBCAGUAaABhAHYAaQBvAHIATQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAQgBlAGgAYQB2AGkAbwByAE0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'EAGkAcwBhAGIAbABlAEIAZQBoAGEAdgBpAG8AcgBNAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'RABpAHMAYQBiAGwAZQBCAGwAbwBjAGsAQQB0AEYAaQByAHMAdABTAGUAZQBuACAA'
            - 'QAaQBzAGEAYgBsAGUAQgBsAG8AYwBrAEEAdABGAGkAcgBzAHQAUwBlAGUAbgAgA'
            - 'EAGkAcwBhAGIAbABlAEIAbABvAGMAawBBAHQARgBpAHIAcwB0AFMAZQBlAG4AIA'
            - 'ZABpAHMAYQBiAGwAZQByAGUAYQBsAHQAaQBtAGUAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAcgBlAGEAbAB0AGkAbQBlAG0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'kAGkAcwBhAGIAbABlAHIAZQBhAGwAdABpAG0AZQBtAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'ZABpAHMAYQBiAGwAZQBpAG8AYQB2AHAAcgBvAHQAZQBjAHQAaQBvAG4AIA'
            - 'QAaQBzAGEAYgBsAGUAaQBvAGEAdgBwAHIAbwB0AGUAYwB0AGkAbwBuACAA'
            - 'kAGkAcwBhAGIAbABlAGkAbwBhAHYAcAByAG8AdABlAGMAdABpAG8AbgAgA'
            - 'ZABpAHMAYQBiAGwAZQBiAGUAaABhAHYAaQBvAHIAbQBvAG4AaQB0AG8AcgBpAG4AZwAgA'
            - 'QAaQBzAGEAYgBsAGUAYgBlAGgAYQB2AGkAbwByAG0AbwBuAGkAdABvAHIAaQBuAGcAIA'
            - 'kAGkAcwBhAGIAbABlAGIAZQBoAGEAdgBpAG8AcgBtAG8AbgBpAHQAbwByAGkAbgBnACAA'
            - 'ZABpAHMAYQBiAGwAZQBiAGwAbwBjAGsAYQB0AGYAaQByAHMAdABzAGUAZQBuACAA'
            - 'QAaQBzAGEAYgBsAGUAYgBsAG8AYwBrAGEAdABmAGkAcgBzAHQAcwBlAGUAbgAgA'
            - 'kAGkAcwBhAGIAbABlAGIAbABvAGMAawBhAHQAZgBpAHIAcwB0AHMAZQBlAG4AIA'
            - 'RABpAHMAYQBiAGwAZQBDAGEAdABjAGgAdQBwAEYAdQBsAGwAUwBjAGEAbgA'
            - 'RABpAHMAYQBiAGwAZQBDAGEAdABjAGgAdQBwAFEAdQBpAGMAawBTAGMAYQBuAA'
            - 'RABpAHMAYQBiAGwAZQBBAHIAYwBoAGkAdgBlAFMAYwBhAG4AbgBpAG4AZwA'
    condition: all of selection_cli_* or 1 of selection_encoded_*
falsepositives:
    - Possible administrative activity
    - Other Cmdlets that may use the same parameters
level: high
```
