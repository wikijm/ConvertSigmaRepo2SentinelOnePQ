```sql
// Translated content (automatically translated on 06-10-2024 07:02:16):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.cmdline contains " -s cmd" or tgt.process.cmdline contains " /s cmd" or tgt.process.cmdline contains " –s cmd" or tgt.process.cmdline contains " —s cmd" or tgt.process.cmdline contains " ―s cmd" or tgt.process.cmdline contains " -s -i cmd" or tgt.process.cmdline contains " -s /i cmd" or tgt.process.cmdline contains " -s –i cmd" or tgt.process.cmdline contains " -s —i cmd" or tgt.process.cmdline contains " -s ―i cmd" or tgt.process.cmdline contains " /s -i cmd" or tgt.process.cmdline contains " /s /i cmd" or tgt.process.cmdline contains " /s –i cmd" or tgt.process.cmdline contains " /s —i cmd" or tgt.process.cmdline contains " /s ―i cmd" or tgt.process.cmdline contains " –s -i cmd" or tgt.process.cmdline contains " –s /i cmd" or tgt.process.cmdline contains " –s –i cmd" or tgt.process.cmdline contains " –s —i cmd" or tgt.process.cmdline contains " –s ―i cmd" or tgt.process.cmdline contains " —s -i cmd" or tgt.process.cmdline contains " —s /i cmd" or tgt.process.cmdline contains " —s –i cmd" or tgt.process.cmdline contains " —s —i cmd" or tgt.process.cmdline contains " —s ―i cmd" or tgt.process.cmdline contains " ―s -i cmd" or tgt.process.cmdline contains " ―s /i cmd" or tgt.process.cmdline contains " ―s –i cmd" or tgt.process.cmdline contains " ―s —i cmd" or tgt.process.cmdline contains " ―s ―i cmd" or tgt.process.cmdline contains " -i -s cmd" or tgt.process.cmdline contains " -i /s cmd" or tgt.process.cmdline contains " -i –s cmd" or tgt.process.cmdline contains " -i —s cmd" or tgt.process.cmdline contains " -i ―s cmd" or tgt.process.cmdline contains " /i -s cmd" or tgt.process.cmdline contains " /i /s cmd" or tgt.process.cmdline contains " /i –s cmd" or tgt.process.cmdline contains " /i —s cmd" or tgt.process.cmdline contains " /i ―s cmd" or tgt.process.cmdline contains " –i -s cmd" or tgt.process.cmdline contains " –i /s cmd" or tgt.process.cmdline contains " –i –s cmd" or tgt.process.cmdline contains " –i —s cmd" or tgt.process.cmdline contains " –i ―s cmd" or tgt.process.cmdline contains " —i -s cmd" or tgt.process.cmdline contains " —i /s cmd" or tgt.process.cmdline contains " —i –s cmd" or tgt.process.cmdline contains " —i —s cmd" or tgt.process.cmdline contains " —i ―s cmd" or tgt.process.cmdline contains " ―i -s cmd" or tgt.process.cmdline contains " ―i /s cmd" or tgt.process.cmdline contains " ―i –s cmd" or tgt.process.cmdline contains " ―i —s cmd" or tgt.process.cmdline contains " ―i ―s cmd" or tgt.process.cmdline contains " -s pwsh" or tgt.process.cmdline contains " /s pwsh" or tgt.process.cmdline contains " –s pwsh" or tgt.process.cmdline contains " —s pwsh" or tgt.process.cmdline contains " ―s pwsh" or tgt.process.cmdline contains " -s -i pwsh" or tgt.process.cmdline contains " -s /i pwsh" or tgt.process.cmdline contains " -s –i pwsh" or tgt.process.cmdline contains " -s —i pwsh" or tgt.process.cmdline contains " -s ―i pwsh" or tgt.process.cmdline contains " /s -i pwsh" or tgt.process.cmdline contains " /s /i pwsh" or tgt.process.cmdline contains " /s –i pwsh" or tgt.process.cmdline contains " /s —i pwsh" or tgt.process.cmdline contains " /s ―i pwsh" or tgt.process.cmdline contains " –s -i pwsh" or tgt.process.cmdline contains " –s /i pwsh" or tgt.process.cmdline contains " –s –i pwsh" or tgt.process.cmdline contains " –s —i pwsh" or tgt.process.cmdline contains " –s ―i pwsh" or tgt.process.cmdline contains " —s -i pwsh" or tgt.process.cmdline contains " —s /i pwsh" or tgt.process.cmdline contains " —s –i pwsh" or tgt.process.cmdline contains " —s —i pwsh" or tgt.process.cmdline contains " —s ―i pwsh" or tgt.process.cmdline contains " ―s -i pwsh" or tgt.process.cmdline contains " ―s /i pwsh" or tgt.process.cmdline contains " ―s –i pwsh" or tgt.process.cmdline contains " ―s —i pwsh" or tgt.process.cmdline contains " ―s ―i pwsh" or tgt.process.cmdline contains " -i -s pwsh" or tgt.process.cmdline contains " -i /s pwsh" or tgt.process.cmdline contains " -i –s pwsh" or tgt.process.cmdline contains " -i —s pwsh" or tgt.process.cmdline contains " -i ―s pwsh" or tgt.process.cmdline contains " /i -s pwsh" or tgt.process.cmdline contains " /i /s pwsh" or tgt.process.cmdline contains " /i –s pwsh" or tgt.process.cmdline contains " /i —s pwsh" or tgt.process.cmdline contains " /i ―s pwsh" or tgt.process.cmdline contains " –i -s pwsh" or tgt.process.cmdline contains " –i /s pwsh" or tgt.process.cmdline contains " –i –s pwsh" or tgt.process.cmdline contains " –i —s pwsh" or tgt.process.cmdline contains " –i ―s pwsh" or tgt.process.cmdline contains " —i -s pwsh" or tgt.process.cmdline contains " —i /s pwsh" or tgt.process.cmdline contains " —i –s pwsh" or tgt.process.cmdline contains " —i —s pwsh" or tgt.process.cmdline contains " —i ―s pwsh" or tgt.process.cmdline contains " ―i -s pwsh" or tgt.process.cmdline contains " ―i /s pwsh" or tgt.process.cmdline contains " ―i –s pwsh" or tgt.process.cmdline contains " ―i —s pwsh" or tgt.process.cmdline contains " ―i ―s pwsh" or tgt.process.cmdline contains " -s powershell" or tgt.process.cmdline contains " /s powershell" or tgt.process.cmdline contains " –s powershell" or tgt.process.cmdline contains " —s powershell" or tgt.process.cmdline contains " ―s powershell" or tgt.process.cmdline contains " -s -i powershell" or tgt.process.cmdline contains " -s /i powershell" or tgt.process.cmdline contains " -s –i powershell" or tgt.process.cmdline contains " -s —i powershell" or tgt.process.cmdline contains " -s ―i powershell" or tgt.process.cmdline contains " /s -i powershell" or tgt.process.cmdline contains " /s /i powershell" or tgt.process.cmdline contains " /s –i powershell" or tgt.process.cmdline contains " /s —i powershell" or tgt.process.cmdline contains " /s ―i powershell" or tgt.process.cmdline contains " –s -i powershell" or tgt.process.cmdline contains " –s /i powershell" or tgt.process.cmdline contains " –s –i powershell" or tgt.process.cmdline contains " –s —i powershell" or tgt.process.cmdline contains " –s ―i powershell" or tgt.process.cmdline contains " —s -i powershell" or tgt.process.cmdline contains " —s /i powershell" or tgt.process.cmdline contains " —s –i powershell" or tgt.process.cmdline contains " —s —i powershell" or tgt.process.cmdline contains " —s ―i powershell" or tgt.process.cmdline contains " ―s -i powershell" or tgt.process.cmdline contains " ―s /i powershell" or tgt.process.cmdline contains " ―s –i powershell" or tgt.process.cmdline contains " ―s —i powershell" or tgt.process.cmdline contains " ―s ―i powershell" or tgt.process.cmdline contains " -i -s powershell" or tgt.process.cmdline contains " -i /s powershell" or tgt.process.cmdline contains " -i –s powershell" or tgt.process.cmdline contains " -i —s powershell" or tgt.process.cmdline contains " -i ―s powershell" or tgt.process.cmdline contains " /i -s powershell" or tgt.process.cmdline contains " /i /s powershell" or tgt.process.cmdline contains " /i –s powershell" or tgt.process.cmdline contains " /i —s powershell" or tgt.process.cmdline contains " /i ―s powershell" or tgt.process.cmdline contains " –i -s powershell" or tgt.process.cmdline contains " –i /s powershell" or tgt.process.cmdline contains " –i –s powershell" or tgt.process.cmdline contains " –i —s powershell" or tgt.process.cmdline contains " –i ―s powershell" or tgt.process.cmdline contains " —i -s powershell" or tgt.process.cmdline contains " —i /s powershell" or tgt.process.cmdline contains " —i –s powershell" or tgt.process.cmdline contains " —i —s powershell" or tgt.process.cmdline contains " —i ―s powershell" or tgt.process.cmdline contains " ―i -s powershell" or tgt.process.cmdline contains " ―i /s powershell" or tgt.process.cmdline contains " ―i –s powershell" or tgt.process.cmdline contains " ―i —s powershell" or tgt.process.cmdline contains " ―i ―s powershell") and (not (tgt.process.cmdline contains "paexec" or tgt.process.cmdline contains "PsExec" or tgt.process.cmdline contains "accepteula"))))
```


# Original Sigma Rule:
```yaml
title: Potential Privilege Escalation To LOCAL SYSTEM
id: 207b0396-3689-42d9-8399-4222658efc99
related:
    - id: 8834e2f7-6b4b-4f09-8906-d2276470ee23 # PsExec specific rule
      type: similar
status: test
description: Detects unknown program using commandline flags usually used by tools such as PsExec and PAExec to start programs with SYSTEM Privileges
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
    - https://www.poweradmin.com/paexec/
    - https://www.fireeye.com/blog/threat-research/2020/10/kegtap-and-singlemalt-with-a-ransomware-chaser.html
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-05-22
modified: 2024-03-05
tags:
    - attack.resource-development
    - attack.t1587.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Escalation to LOCAL_SYSTEM
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
    filter_main_exclude_coverage:
        # This filter exclude strings covered by 8834e2f7-6b4b-4f09-8906-d2276470ee23
        CommandLine|contains:
            - 'paexec'
            - 'PsExec'
            - 'accepteula'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Weird admins that rename their tools
    - Software companies that bundle PsExec/PAExec with their software and rename it, so that it is less embarrassing
level: high
```