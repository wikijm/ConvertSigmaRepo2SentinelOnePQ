```sql
// Translated content (automatically translated on 02-08-2025 02:18:11):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains "\conhost.exe" and (src.process.image.path contains "\explorer.exe" or src.process.image.path contains "\lsass.exe" or src.process.image.path contains "\regsvr32.exe" or src.process.image.path contains "\rundll32.exe" or src.process.image.path contains "\services.exe" or src.process.image.path contains "\smss.exe" or src.process.image.path contains "\spoolsv.exe" or src.process.image.path contains "\svchost.exe" or src.process.image.path contains "\userinit.exe" or src.process.image.path contains "\wininit.exe" or src.process.image.path contains "\winlogon.exe")) and (not (src.process.cmdline contains "-k apphost -s AppHostSvc" or src.process.cmdline contains "-k imgsvc" or src.process.cmdline contains "-k localService -p -s RemoteRegistry" or src.process.cmdline contains "-k LocalSystemNetworkRestricted -p -s NgcSvc" or src.process.cmdline contains "-k NetSvcs -p -s NcaSvc" or src.process.cmdline contains "-k netsvcs -p -s NetSetupSvc" or src.process.cmdline contains "-k netsvcs -p -s wlidsvc" or src.process.cmdline contains "-k NetworkService -p -s DoSvc" or src.process.cmdline contains "-k wsappx -p -s AppXSvc" or src.process.cmdline contains "-k wsappx -p -s ClipSVC" or src.process.cmdline contains "-k wusvcs -p -s WaaSMedicSvc")) and (not (src.process.cmdline contains "C:\Program Files (x86)\Dropbox\Client\" or src.process.cmdline contains "C:\Program Files\Dropbox\Client\"))))
```


# Original Sigma Rule:
```yaml
title: Conhost Spawned By Uncommon Parent Process
id: cbb9e3d1-2386-4e59-912e-62f1484f7a89
status: test
description: Detects when the Console Window Host (conhost.exe) process is spawned by an uncommon parent process, which could be indicative of potential code injection activity.
references:
    - https://www.elastic.co/guide/en/security/current/conhost-spawned-by-suspicious-parent-process.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-28
modified: 2025-03-06
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\conhost.exe'
        ParentImage|endswith:
            - '\explorer.exe'
            # - '\csrss.exe'  # Legitimate parent as seen in EchoTrail https://www.echotrail.io/insights/search/csrss.exe
            # - '\ctfmon.exe'  # Seen several times in a testing environment
            # - '\dllhost.exe'  # FP on clean system from grandparent 'svchost.exe -k DcomLaunch -p'
            - '\lsass.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\services.exe'
            - '\smss.exe'
            - '\spoolsv.exe'
            - '\svchost.exe'
            - '\userinit.exe'
            # - '\wermgr.exe'  # Legitimate parent as seen in EchoTrail https://www.echotrail.io/insights/search/wermgr.exe
            - '\wininit.exe'
            - '\winlogon.exe'
    filter_main_svchost:
        ParentCommandLine|contains:
            - '-k apphost -s AppHostSvc'
            - '-k imgsvc'
            - '-k localService -p -s RemoteRegistry'
            - '-k LocalSystemNetworkRestricted -p -s NgcSvc'
            - '-k NetSvcs -p -s NcaSvc'
            - '-k netsvcs -p -s NetSetupSvc'
            - '-k netsvcs -p -s wlidsvc'
            - '-k NetworkService -p -s DoSvc'
            - '-k wsappx -p -s AppXSvc'
            - '-k wsappx -p -s ClipSVC'
            - '-k wusvcs -p -s WaaSMedicSvc'
    filter_optional_dropbox:
        ParentCommandLine|contains:
            - 'C:\Program Files (x86)\Dropbox\Client\'
            - 'C:\Program Files\Dropbox\Client\'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
