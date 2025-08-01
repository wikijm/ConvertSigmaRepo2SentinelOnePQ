```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.image.path contains "\WerFault.exe" and tgt.process.cmdline contains "WerFault.exe") or (tgt.process.image.path contains "\rundll32.exe" and tgt.process.cmdline contains "rundll32.exe") or (tgt.process.image.path contains "\regsvcs.exe" and tgt.process.cmdline contains "regsvcs.exe") or (tgt.process.image.path contains "\regasm.exe" and tgt.process.cmdline contains "regasm.exe") or (tgt.process.image.path contains "\regsvr32.exe" and tgt.process.cmdline contains "regsvr32.exe")) and (not ((src.process.image.path contains "\AppData\Local\Microsoft\EdgeUpdate\Install\{" and tgt.process.image.path contains "\rundll32.exe" and tgt.process.cmdline contains "rundll32.exe") or ((src.process.image.path contains "\AppData\Local\BraveSoftware\Brave-Browser\Application\" or src.process.image.path contains "\AppData\Local\Google\Chrome\Application\") and src.process.image.path contains "\Installer\setup.exe" and src.process.cmdline contains "--uninstall " and tgt.process.image.path contains "\rundll32.exe" and tgt.process.cmdline contains "rundll32.exe")))))
```


# Original Sigma Rule:
```yaml
title: Bad Opsec Defaults Sacrificial Processes With Improper Arguments
id: a7c3d773-caef-227e-a7e7-c2f13c622329
related:
    - id: f5647edc-a7bf-4737-ab50-ef8c60dc3add
      type: obsolete
status: test
description: |
    Detects attackers using tooling with bad opsec defaults.
    E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run.
    One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples.
references:
    - https://blog.malwarebytes.com/malwarebytes-news/2020/10/kraken-attack-abuses-wer-service/
    - https://www.cobaltstrike.com/help-opsec
    - https://twitter.com/CyberRaiju/status/1251492025678983169
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool
    - https://learn.microsoft.com/en-us/dotnet/framework/tools/regsvcs-exe-net-services-installation-tool
author: Oleg Kolesnikov @securonix invrep_de, oscd.community, Florian Roth (Nextron Systems), Christian Burkard (Nextron Systems)
date: 2020-10-23
modified: 2024-08-15
tags:
    - attack.defense-evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_werfault:
        Image|endswith: '\WerFault.exe'
        CommandLine|endswith: 'WerFault.exe'
    selection_rundll32:
        Image|endswith: '\rundll32.exe'
        CommandLine|endswith: 'rundll32.exe'
    selection_regsvcs:
        Image|endswith: '\regsvcs.exe'
        CommandLine|endswith: 'regsvcs.exe'
    selection_regasm:
        Image|endswith: '\regasm.exe'
        CommandLine|endswith: 'regasm.exe'
    selection_regsvr32:
        Image|endswith: '\regsvr32.exe'
        CommandLine|endswith: 'regsvr32.exe'
    filter_optional_edge_update:
        ParentImage|contains: '\AppData\Local\Microsoft\EdgeUpdate\Install\{'
        Image|endswith: '\rundll32.exe'
        CommandLine|endswith: 'rundll32.exe'
    filter_optional_chromium_installer:
        # As reported in https://github.com/SigmaHQ/sigma/issues/4570 and others
        ParentImage|contains:
            - '\AppData\Local\BraveSoftware\Brave-Browser\Application\'
            - '\AppData\Local\Google\Chrome\Application\'
        ParentImage|endswith: '\Installer\setup.exe'
        ParentCommandLine|contains: '--uninstall '
        Image|endswith: '\rundll32.exe'
        CommandLine|endswith: 'rundll32.exe'
    condition: 1 of selection_* and not 1 of filter_optional_*
falsepositives:
    - Unlikely
level: high
```
