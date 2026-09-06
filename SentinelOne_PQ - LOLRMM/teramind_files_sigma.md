```sql
// Translated content (automatically translated on 06-09-2026 01:47:37):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\ProgramData\\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\*" or tgt.file.path contains "C:\\ProgramData\\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\\config" or tgt.file.path contains "C:\\ProgramData\\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\\updates\\rundll32.exe.config" or tgt.file.path contains "C:\\ProgramData\\Teramind Agent\*" or tgt.file.path contains "C:\\ProgramData\\Teramind Agent\\config" or tgt.file.path contains "C:\\ProgramData\\Teramind Agent\\<version>\\{6D99445F-F40F-45CB-B433-06302DAE6C70}\\tmagentsvc.exe" or tgt.file.path contains "C:\\ProgramData\\Package Cache\\.unverified\\agent" or tgt.file.path="*teramind_agent_*_bundle_noredist_setup.msi" or tgt.file.path="*teramind_agent_*_x64.msi" or tgt.file.path="*teramind_agent_*_ARM64.msi" or tgt.file.path contains "tmagent-i(__<hash>).pkg" or tgt.file.path="*teramind_agent_*_hidden-do(<domain>).pkg" or tgt.file.path contains "/usr/local/teramind/agent/bin/tmsysd" or tgt.file.path contains "/usr/local/teramind/agent/etc/" or tgt.file.path contains "/Applications/Teramind Agent.app" or tgt.file.path contains "/Applications/tmagent.app" or tgt.file.path contains "tmui" or tgt.file.path contains "Teramind.Setup.Updater.exe" or tgt.file.path contains "tmdiag.zip"))
```


# Original Sigma Rule:
```yaml
title: Potential Teramind RMM Tool File Activity
id: 1205c0b6-c1be-51b5-852f-7758d26f8cd7
status: experimental
description: |
    Detects potential files activity of Teramind RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2026-05-18
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\ProgramData\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\*'
            - 'C:\ProgramData\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\config'
            - 'C:\ProgramData\{4CEC2908-5CE4-48F0-A717-8FC833D8017A}\updates\rundll32.exe.config'
            - 'C:\ProgramData\Teramind Agent\*'
            - 'C:\ProgramData\Teramind Agent\config'
            - 'C:\ProgramData\Teramind Agent\<version>\{6D99445F-F40F-45CB-B433-06302DAE6C70}\tmagentsvc.exe'
            - 'C:\ProgramData\Package Cache\.unverified\agent'
            - 'teramind_agent_*_bundle_noredist_setup.msi'
            - 'teramind_agent_*_x64.msi'
            - 'teramind_agent_*_ARM64.msi'
            - 'tmagent-i(__<hash>).pkg'
            - 'teramind_agent_*_hidden-do(<domain>).pkg'
            - '/usr/local/teramind/agent/bin/tmsysd'
            - '/usr/local/teramind/agent/etc/'
            - '/Applications/Teramind Agent.app'
            - '/Applications/tmagent.app'
            - 'tmui'
            - 'Teramind.Setup.Updater.exe'
            - 'tmdiag.zip'
    condition: selection
falsepositives:
    - Legitimate use of Teramind
level: medium
```
