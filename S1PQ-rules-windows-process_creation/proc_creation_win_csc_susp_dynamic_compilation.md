```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (tgt.process.image.path contains "\csc.exe" and ((tgt.process.cmdline contains ":\Perflogs\" or tgt.process.cmdline contains ":\Users\Public\" or tgt.process.cmdline contains "\AppData\Local\Temp\" or tgt.process.cmdline contains "\Temporary Internet" or tgt.process.cmdline contains "\Windows\Temp\") or ((tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Favorites\") or (tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Favourites\") or (tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Contacts\") or (tgt.process.cmdline contains ":\Users\" and tgt.process.cmdline contains "\Pictures\")) or tgt.process.cmdline matches "([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\\\[Aa]pp[Dd]ata\\\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\\\[^\\\\]{1,256}$") and (not ((src.process.image.path contains "C:\Program Files (x86)\" or src.process.image.path contains "C:\Program Files\") or src.process.image.path="C:\Windows\System32\sdiagnhost.exe" or src.process.image.path="C:\Windows\System32\inetsrv\w3wp.exe")) and (not ((src.process.image.path in ("C:\ProgramData\chocolatey\choco.exe","C:\ProgramData\chocolatey\tools\shimgen.exe")) or src.process.cmdline contains "\ProgramData\Microsoft\Windows Defender Advanced Threat Protection" or (src.process.cmdline contains "JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw" or src.process.cmdline contains "cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA" or src.process.cmdline contains "nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA")))))
```


# Original Sigma Rule:
```yaml
title: Dynamic .NET Compilation Via Csc.EXE
id: dcaa3f04-70c3-427a-80b4-b870d73c94c4
status: test
description: Detects execution of "csc.exe" to compile .NET code. Attackers often leverage this to compile code on the fly and use it in other stages.
references:
    - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
    - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
    - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
    - https://twitter.com/gN3mes1s/status/1206874118282448897
    - https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1027.004/T1027.004.md#atomic-test-1---compile-after-delivery-using-cscexe
author: Florian Roth (Nextron Systems), X__Junior (Nextron Systems)
date: 2019-08-24
modified: 2024-05-27
tags:
    - attack.defense-evasion
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\csc.exe'
    selection_susp_location_1:
        CommandLine|contains:
            - ':\Perflogs\'
            - ':\Users\Public\'
            - '\AppData\Local\Temp\' # User execution
            - '\Temporary Internet'
            - '\Windows\Temp\' # Admin execution
    selection_susp_location_2:
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Favorites\'
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Favourites\'
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Contacts\'
        - CommandLine|contains|all:
              - ':\Users\'
              - '\Pictures\'
    selection_susp_location_3:
        CommandLine|re: '([Pp]rogram[Dd]ata|%([Ll]ocal)?[Aa]pp[Dd]ata%|\\[Aa]pp[Dd]ata\\([Ll]ocal([Ll]ow)?|[Rr]oaming))\\[^\\]{1,256}$'
    filter_main_programfiles:
        # Note: this is a generic filter. You could baseline execution in your env for a more robust rule
        ParentImage|startswith:
            - 'C:\Program Files (x86)\' # https://twitter.com/gN3mes1s/status/1206874118282448897
            - 'C:\Program Files\' # https://twitter.com/gN3mes1s/status/1206874118282448897
    filter_main_sdiagnhost:
        ParentImage: 'C:\Windows\System32\sdiagnhost.exe' # https://twitter.com/gN3mes1s/status/1206874118282448897
    filter_main_w3p:
        ParentImage: 'C:\Windows\System32\inetsrv\w3wp.exe' # https://twitter.com/gabriele_pippi/status/1206907900268072962
    filter_optional_chocolatey:
        ParentImage: # Chocolatey https://chocolatey.org/
            - 'C:\ProgramData\chocolatey\choco.exe'
            - 'C:\ProgramData\chocolatey\tools\shimgen.exe'
    filter_optional_defender:
        ParentCommandLine|contains: '\ProgramData\Microsoft\Windows Defender Advanced Threat Protection'
    filter_optional_ansible:
        # Note: As ansible is widely used we exclude it with this generic filter.
        # A better option would be to filter based on script content basis or other marker while hunting
        ParentCommandLine|contains:
            # '{"failed":true,"msg":"Ansible requires PowerShell v3.0 or newer"}'
            - 'JwB7ACIAZgBhAGkAbABlAGQAIgA6AHQAcgB1AGUALAAiAG0AcwBnACIAOgAiAEEAbgBzAGkAYgBsAGUAIAByAGUAcQB1AGkAcgBlAHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAdgAzAC4AMAAgAG8AcgAgAG4AZQB3AGUAcgAiAH0AJw'
            - 'cAewAiAGYAYQBpAGwAZQBkACIAOgB0AHIAdQBlACwAIgBtAHMAZwAiADoAIgBBAG4AcwBpAGIAbABlACAAcgBlAHEAdQBpAHIAZQBzACAAUABvAHcAZQByAFMAaABlAGwAbAAgAHYAMwAuADAAIABvAHIAIABuAGUAdwBlAHIAIgB9ACcA'
            - 'nAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQBzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbwByACAAbgBlAHcAZQByACIAfQAnA'
    condition: selection_img and 1 of selection_susp_location_* and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Legitimate software from program files - https://twitter.com/gN3mes1s/status/1206874118282448897
    - Legitimate Microsoft software - https://twitter.com/gabriele_pippi/status/1206907900268072962
    - Ansible
level: medium
```
