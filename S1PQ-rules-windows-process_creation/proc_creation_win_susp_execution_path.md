```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((tgt.process.image.path contains ":\\Perflogs\\" or tgt.process.image.path contains ":\\Users\\All Users\\" or tgt.process.image.path contains ":\\Users\\Default\\" or tgt.process.image.path contains ":\\Users\\NetworkService\\" or tgt.process.image.path contains ":\\Windows\\addins\\" or tgt.process.image.path contains ":\\Windows\\debug\\" or tgt.process.image.path contains ":\\Windows\\Fonts\\" or tgt.process.image.path contains ":\\Windows\\Help\\" or tgt.process.image.path contains ":\\Windows\\IME\\" or tgt.process.image.path contains ":\\Windows\\Media\\" or tgt.process.image.path contains ":\\Windows\\repair\\" or tgt.process.image.path contains ":\\Windows\\security\\" or tgt.process.image.path contains ":\\Windows\\System32\\Tasks\\" or tgt.process.image.path contains ":\\Windows\\Tasks\\" or tgt.process.image.path contains "$Recycle.bin" or tgt.process.image.path contains "\\config\\systemprofile\\" or tgt.process.image.path contains "\\Intel\\Logs\\" or tgt.process.image.path contains "\\RSA\\MachineKeys\\") and (not (tgt.process.image.path contains "C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\" or (tgt.process.image.path contains "C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\" and tgt.process.image.path contains "\\CitrixReceiverUpdater.exe")))))
```


# Original Sigma Rule:
```yaml
title: Process Execution From A Potentially Suspicious Folder
id: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
status: test
description: Detects a potentially suspicious execution from an uncommon folder.
references:
    - https://github.com/mbevilacqua/appcompatprocessor/blob/6c847937c5a836e2ce2fe2b915f213c345a3c389/AppCompatSearch.txt
    - https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
    - https://github.com/ThreatHuntingProject/ThreatHunting/blob/cb22598bb70651f88e0285abc8d835757d2cb596/hunts/suspicious_process_creation_via_windows_event_logs.md
author: Florian Roth (Nextron Systems), Tim Shelton
date: 2019-01-16
modified: 2024-07-12
tags:
    - attack.defense-evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - ':\Perflogs\'
            - ':\Users\All Users\'
            - ':\Users\Default\'
            - ':\Users\NetworkService\'
            - ':\Windows\addins\'
            - ':\Windows\debug\'
            - ':\Windows\Fonts\'
            - ':\Windows\Help\'
            - ':\Windows\IME\'
            - ':\Windows\Media\'
            - ':\Windows\repair\'
            - ':\Windows\security\'
            - ':\Windows\System32\Tasks\'
            - ':\Windows\Tasks\'
            - '$Recycle.bin'
            - '\config\systemprofile\'
            - '\Intel\Logs\'
            - '\RSA\MachineKeys\'
    filter_optional_ibm:
        Image|startswith: 'C:\Users\Public\IBM\ClientSolutions\Start_Programs\'
    filter_optional_citrix:
        Image|startswith: 'C:\Windows\SysWOW64\config\systemprofile\Citrix\UpdaterBinaries\'
        Image|endswith: '\CitrixReceiverUpdater.exe'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: high
```
