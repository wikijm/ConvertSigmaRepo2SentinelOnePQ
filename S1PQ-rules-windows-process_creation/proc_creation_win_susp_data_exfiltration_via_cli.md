```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((((tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\cmd.exe") and (tgt.process.cmdline contains "curl " or tgt.process.cmdline contains "Invoke-RestMethod" or tgt.process.cmdline contains "Invoke-WebRequest" or tgt.process.cmdline contains "irm " or tgt.process.cmdline contains "iwr " or tgt.process.cmdline contains "wget ") and (tgt.process.cmdline contains " -ur" and tgt.process.cmdline contains " -me" and tgt.process.cmdline contains " -b" and tgt.process.cmdline contains " POST ")) or ((tgt.process.image.path contains "\\curl.exe" and tgt.process.cmdline contains "--ur") and (tgt.process.cmdline contains " -d " or tgt.process.cmdline contains " --data ")) or (tgt.process.image.path contains "\\wget.exe" and (tgt.process.cmdline contains "--post-data" or tgt.process.cmdline contains "--post-file"))) and ((tgt.process.cmdline matches "net\\s+view" or tgt.process.cmdline matches "sc\\s+query") or (tgt.process.cmdline contains "Get-Content" or tgt.process.cmdline contains "GetBytes" or tgt.process.cmdline contains "hostname" or tgt.process.cmdline contains "ifconfig" or tgt.process.cmdline contains "ipconfig" or tgt.process.cmdline contains "netstat" or tgt.process.cmdline contains "nltest" or tgt.process.cmdline contains "qprocess" or tgt.process.cmdline contains "systeminfo" or tgt.process.cmdline contains "tasklist" or tgt.process.cmdline contains "ToBase64String" or tgt.process.cmdline contains "whoami") or (tgt.process.cmdline contains "type " and tgt.process.cmdline contains " > " and tgt.process.cmdline contains " C:\\"))))
```


# Original Sigma Rule:
```yaml
title: Potential Data Exfiltration Activity Via CommandLine Tools
id: 7d1aaf3d-4304-425c-b7c3-162055e0b3ab
status: test
description: Detects the use of various CLI utilities exfiltrating data via web requests
references:
    - https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-02
modified: 2025-10-19
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_iwr:
        Image|endswith:
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
        CommandLine|contains:
            - 'curl '
            - 'Invoke-RestMethod'
            - 'Invoke-WebRequest'
            - 'irm '
            - 'iwr '
            - 'wget '
        CommandLine|contains|all:
            - ' -ur' # Shortest possible version of the -uri flag
            - ' -me' # Shortest possible version of the -method flag
            - ' -b'
            - ' POST '
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains: '--ur' # Shortest possible version of the --uri flag
    selection_curl_data:
        CommandLine|contains:
            - ' -d ' # Shortest possible version of the --data flag
            - ' --data '
    selection_wget:
        Image|endswith: '\wget.exe'
        CommandLine|contains:
            - '--post-data'
            - '--post-file'
    payloads:
        - CommandLine|re:
              - 'net\s+view'
              - 'sc\s+query'
        - CommandLine|contains:
              - 'Get-Content'
              - 'GetBytes'
              - 'hostname'
              - 'ifconfig'
              - 'ipconfig'
              - 'netstat'
              - 'nltest'
              - 'qprocess'
              - 'systeminfo'
              - 'tasklist'
              - 'ToBase64String'
              - 'whoami'
        - CommandLine|contains|all:
              - 'type '
              - ' > '
              - ' C:\'
    condition: (selection_iwr or all of selection_curl* or selection_wget) and payloads
falsepositives:
    - Unlikely
level: high
```
