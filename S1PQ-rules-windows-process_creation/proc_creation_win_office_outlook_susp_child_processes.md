```sql
// Translated content (automatically translated on 24-07-2025 02:21:27):
event.type="Process Creation" and (endpoint.os="windows" and (src.process.image.path contains "\OUTLOOK.EXE" and (tgt.process.image.path contains "\AppVLP.exe" or tgt.process.image.path contains "\bash.exe" or tgt.process.image.path contains "\cmd.exe" or tgt.process.image.path contains "\cscript.exe" or tgt.process.image.path contains "\forfiles.exe" or tgt.process.image.path contains "\hh.exe" or tgt.process.image.path contains "\mftrace.exe" or tgt.process.image.path contains "\msbuild.exe" or tgt.process.image.path contains "\msdt.exe" or tgt.process.image.path contains "\mshta.exe" or tgt.process.image.path contains "\msiexec.exe" or tgt.process.image.path contains "\powershell.exe" or tgt.process.image.path contains "\pwsh.exe" or tgt.process.image.path contains "\regsvr32.exe" or tgt.process.image.path contains "\schtasks.exe" or tgt.process.image.path contains "\scrcons.exe" or tgt.process.image.path contains "\scriptrunner.exe" or tgt.process.image.path contains "\sh.exe" or tgt.process.image.path contains "\svchost.exe" or tgt.process.image.path contains "\wmic.exe" or tgt.process.image.path contains "\wscript.exe"))) | columns tgt.process.cmdline,src.process.cmdline
```


# Original Sigma Rule:
```yaml
title: Suspicious Outlook Child Process
id: 208748f7-881d-47ac-a29c-07ea84bf691d
related:
    - id: 438025f9-5856-4663-83f7-52f878a70a50 # Office Child Processes
      type: derived
    - id: e212d415-0e93-435f-9e1a-f29005bb4723 # Outlook Remote Child Process
      type: derived
status: test
description: Detects a suspicious process spawning from an Outlook process.
references:
    - https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Michael Haag, Florian Roth (Nextron Systems), Markus Neis, Elastic, FPT.EagleEye Team
date: 2022-02-28
modified: 2023-02-04
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\OUTLOOK.EXE'
        Image|endswith:
            - '\AppVLP.exe'
            - '\bash.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\forfiles.exe'
            - '\hh.exe'
            - '\mftrace.exe'
            - '\msbuild.exe'        # https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/windows/defense_evasion_execution_msbuild_started_by_office_app.toml
            - '\msdt.exe'           # CVE-2022-30190
            - '\mshta.exe'
            - '\msiexec.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\regsvr32.exe'
            - '\schtasks.exe'
            - '\scrcons.exe'
            - '\scriptrunner.exe'
            - '\sh.exe'
            - '\svchost.exe'        # https://www.vmray.com/analyses/2d2fa29185ad/report/overview.html
            - '\wmic.exe'           # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\wscript.exe'
            # Several FPs with rundll32.exe
            # We started excluding specific use cases and ended up commenting out the rundll32.exe sub processes completely
            # - '\rundll32.exe'
            # filter_outlook_photoviewer:  # https://twitter.com/Luke_Hamp/status/1495919717760237568
            #   ParentImage|endswith: '\OUTLOOK.EXE'
            #   Image|endswith: '\rundll32.exe'
            #   CommandLine|contains: '\PhotoViewer.dll'
            # filter_outlook_printattachments:  # https://twitter.com/KickaKamil/status/1496238278659485696
            #   ParentImage|endswith: '\OUTLOOK.EXE'
            #   Image|endswith: '\rundll32.exe'
            #   CommandLine|contains|all:
            #     - 'shell32.dll,Control_RunDLL'
            #     - '\SYSTEM32\SPOOL\DRIVERS\'
    condition: selection # and not 1 of filter*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high
```
