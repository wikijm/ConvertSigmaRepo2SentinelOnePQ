```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -s cmd" or tgt.process.cmdline contains " /s cmd" or tgt.process.cmdline contains " –s cmd" or tgt.process.cmdline contains " —s cmd" or tgt.process.cmdline contains " ―s cmd" or tgt.process.cmdline contains " -s -i cmd" or tgt.process.cmdline contains " -s /i cmd" or tgt.process.cmdline contains " -s –i cmd" or tgt.process.cmdline contains " -s —i cmd" or tgt.process.cmdline contains " -s ―i cmd" or tgt.process.cmdline contains " /s -i cmd" or tgt.process.cmdline contains " /s /i cmd" or tgt.process.cmdline contains " /s –i cmd" or tgt.process.cmdline contains " /s —i cmd" or tgt.process.cmdline contains " /s ―i cmd" or tgt.process.cmdline contains " –s -i cmd" or tgt.process.cmdline contains " –s /i cmd" or tgt.process.cmdline contains " –s –i cmd" or tgt.process.cmdline contains " –s —i cmd" or tgt.process.cmdline contains " –s ―i cmd" or tgt.process.cmdline contains " —s -i cmd" or tgt.process.cmdline contains " —s /i cmd" or tgt.process.cmdline contains " —s –i cmd" or tgt.process.cmdline contains " —s —i cmd" or tgt.process.cmdline contains " —s ―i cmd" or tgt.process.cmdline contains " ―s -i cmd" or tgt.process.cmdline contains " ―s /i cmd" or tgt.process.cmdline contains " ―s –i cmd" or tgt.process.cmdline contains " ―s —i cmd" or tgt.process.cmdline contains " ―s ―i cmd" or tgt.process.cmdline contains " -i -s cmd" or tgt.process.cmdline contains " -i /s cmd" or tgt.process.cmdline contains " -i –s cmd" or tgt.process.cmdline contains " -i —s cmd" or tgt.process.cmdline contains " -i ―s cmd" or tgt.process.cmdline contains " /i -s cmd" or tgt.process.cmdline contains " /i /s cmd" or tgt.process.cmdline contains " /i –s cmd" or tgt.process.cmdline contains " /i —s cmd" or tgt.process.cmdline contains " /i ―s cmd" or tgt.process.cmdline contains " –i -s cmd" or tgt.process.cmdline contains " –i /s cmd" or tgt.process.cmdline contains " –i –s cmd" or tgt.process.cmdline contains " –i —s cmd" or tgt.process.cmdline contains " –i ―s cmd" or tgt.process.cmdline contains " —i -s cmd" or tgt.process.cmdline contains " —i /s cmd" or tgt.process.cmdline contains " —i –s cmd" or tgt.process.cmdline contains " —i —s cmd" or tgt.process.cmdline contains " —i ―s cmd" or tgt.process.cmdline contains " ―i -s cmd" or tgt.process.cmdline contains " ―i /s cmd" or tgt.process.cmdline contains " ―i –s cmd" or tgt.process.cmdline contains " ―i —s cmd" or tgt.process.cmdline contains " ―i ―s cmd" or tgt.process.cmdline contains " -s pwsh" or tgt.process.cmdline contains " /s pwsh" or tgt.process.cmdline contains " –s pwsh" or tgt.process.cmdline contains " —s pwsh" or tgt.process.cmdline contains " ―s pwsh" or tgt.process.cmdline contains " -s -i pwsh" or tgt.process.cmdline contains " -s /i pwsh" or tgt.process.cmdline contains " -s –i pwsh" or tgt.process.cmdline contains " -s —i pwsh" or tgt.process.cmdline contains " -s ―i pwsh" or tgt.process.cmdline contains " /s -i pwsh" or tgt.process.cmdline contains " /s /i pwsh" or tgt.process.cmdline contains " /s –i pwsh" or tgt.process.cmdline contains " /s —i pwsh" or tgt.process.cmdline contains " /s ―i pwsh" or tgt.process.cmdline contains " –s -i pwsh" or tgt.process.cmdline contains " –s /i pwsh" or tgt.process.cmdline contains " –s –i pwsh" or tgt.process.cmdline contains " –s —i pwsh" or tgt.process.cmdline contains " –s ―i pwsh" or tgt.process.cmdline contains " —s -i pwsh" or tgt.process.cmdline contains " —s /i pwsh" or tgt.process.cmdline contains " —s –i pwsh" or tgt.process.cmdline contains " —s —i pwsh" or tgt.process.cmdline contains " —s ―i pwsh" or tgt.process.cmdline contains " ―s -i pwsh" or tgt.process.cmdline contains " ―s /i pwsh" or tgt.process.cmdline contains " ―s –i pwsh" or tgt.process.cmdline contains " ―s —i pwsh" or tgt.process.cmdline contains " ―s ―i pwsh" or tgt.process.cmdline contains " -i -s pwsh" or tgt.process.cmdline contains " -i /s pwsh" or tgt.process.cmdline contains " -i –s pwsh" or tgt.process.cmdline contains " -i —s pwsh" or tgt.process.cmdline contains " -i ―s pwsh" or tgt.process.cmdline contains " /i -s pwsh" or tgt.process.cmdline contains " /i /s pwsh" or tgt.process.cmdline contains " /i –s pwsh" or tgt.process.cmdline contains " /i —s pwsh" or tgt.process.cmdline contains " /i ―s pwsh" or tgt.process.cmdline contains " –i -s pwsh" or tgt.process.cmdline contains " –i /s pwsh" or tgt.process.cmdline contains " –i –s pwsh" or tgt.process.cmdline contains " –i —s pwsh" or tgt.process.cmdline contains " –i ―s pwsh" or tgt.process.cmdline contains " —i -s pwsh" or tgt.process.cmdline contains " —i /s pwsh" or tgt.process.cmdline contains " —i –s pwsh" or tgt.process.cmdline contains " —i —s pwsh" or tgt.process.cmdline contains " —i ―s pwsh" or tgt.process.cmdline contains " ―i -s pwsh" or tgt.process.cmdline contains " ―i /s pwsh" or tgt.process.cmdline contains " ―i –s pwsh" or tgt.process.cmdline contains " ―i —s pwsh" or tgt.process.cmdline contains " ―i ―s pwsh" or tgt.process.cmdline contains " -s powershell" or tgt.process.cmdline contains " /s powershell" or tgt.process.cmdline contains " –s powershell" or tgt.process.cmdline contains " —s powershell" or tgt.process.cmdline contains " ―s powershell" or tgt.process.cmdline contains " -s -i powershell" or tgt.process.cmdline contains " -s /i powershell" or tgt.process.cmdline contains " -s –i powershell" or tgt.process.cmdline contains " -s —i powershell" or tgt.process.cmdline contains " -s ―i powershell" or tgt.process.cmdline contains " /s -i powershell" or tgt.process.cmdline contains " /s /i powershell" or tgt.process.cmdline contains " /s –i powershell" or tgt.process.cmdline contains " /s —i powershell" or tgt.process.cmdline contains " /s ―i powershell" or tgt.process.cmdline contains " –s -i powershell" or tgt.process.cmdline contains " –s /i powershell" or tgt.process.cmdline contains " –s –i powershell" or tgt.process.cmdline contains " –s —i powershell" or tgt.process.cmdline contains " –s ―i powershell" or tgt.process.cmdline contains " —s -i powershell" or tgt.process.cmdline contains " —s /i powershell" or tgt.process.cmdline contains " —s –i powershell" or tgt.process.cmdline contains " —s —i powershell" or tgt.process.cmdline contains " —s ―i powershell" or tgt.process.cmdline contains " ―s -i powershell" or tgt.process.cmdline contains " ―s /i powershell" or tgt.process.cmdline contains " ―s –i powershell" or tgt.process.cmdline contains " ―s —i powershell" or tgt.process.cmdline contains " ―s ―i powershell" or tgt.process.cmdline contains " -i -s powershell" or tgt.process.cmdline contains " -i /s powershell" or tgt.process.cmdline contains " -i –s powershell" or tgt.process.cmdline contains " -i —s powershell" or tgt.process.cmdline contains " -i ―s powershell" or tgt.process.cmdline contains " /i -s powershell" or tgt.process.cmdline contains " /i /s powershell" or tgt.process.cmdline contains " /i –s powershell" or tgt.process.cmdline contains " /i —s powershell" or tgt.process.cmdline contains " /i ―s powershell" or tgt.process.cmdline contains " –i -s powershell" or tgt.process.cmdline contains " –i /s powershell" or tgt.process.cmdline contains " –i –s powershell" or tgt.process.cmdline contains " –i —s powershell" or tgt.process.cmdline contains " –i ―s powershell" or tgt.process.cmdline contains " —i -s powershell" or tgt.process.cmdline contains " —i /s powershell" or tgt.process.cmdline contains " —i –s powershell" or tgt.process.cmdline contains " —i —s powershell" or tgt.process.cmdline contains " —i ―s powershell" or tgt.process.cmdline contains " ―i -s powershell" or tgt.process.cmdline contains " ―i /s powershell" or tgt.process.cmdline contains " ―i –s powershell" or tgt.process.cmdline contains " ―i —s powershell" or tgt.process.cmdline contains " ―i ―s powershell") and (tgt.process.cmdline contains "psexec" or tgt.process.cmdline contains "paexec" or tgt.process.cmdline contains "accepteula")))
```


# Original Sigma Rule:
```yaml
title: PsExec/PAExec Escalation to LOCAL SYSTEM
id: 8834e2f7-6b4b-4f09-8906-d2276470ee23
related:
    - id: 207b0396-3689-42d9-8399-4222658efc99 # Generic rule based on similar cli flags
      type: similar
status: test
description: Detects suspicious commandline flags used by PsExec and PAExec to escalate a command line to LOCAL_SYSTEM rights
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.poweradmin.com/paexec/
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-11-23
modified: 2024-03-05
tags:
    - attack.resource-development
    - attack.t1587.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_sys: # Escalation to LOCAL_SYSTEM
        CommandLine|contains|windash:
            # Note that you don't need to add the ".exe" part when using psexec/paexec
            # The "-" can also be replaced with "/"
            # The order of args isn't important
            # "cmd" can be replaced by "powershell", "pwsh" or any other console like software
            - ' -s cmd'
            - ' -s -i cmd'
            - ' -i -s cmd'
            # Pwsh (For PowerShell 7)
            - ' -s pwsh'
            - ' -s -i pwsh'
            - ' -i -s pwsh'
            # PowerShell (For PowerShell 5)
            - ' -s powershell'
            - ' -s -i powershell'
            - ' -i -s powershell'
    selection_other:
        CommandLine|contains:
            - 'psexec'
            - 'paexec'
            - 'accepteula'
    condition: all of selection_*
falsepositives:
    - Admins that use PsExec or PAExec to escalate to the SYSTEM account for maintenance purposes (rare)
    - Users that debug Microsoft Intune issues using the commands mentioned in the official documentation; see https://learn.microsoft.com/en-us/mem/intune/apps/intune-management-extension
level: high
```