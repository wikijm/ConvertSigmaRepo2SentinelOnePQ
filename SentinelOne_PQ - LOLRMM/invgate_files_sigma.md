```sql
// Translated content (automatically translated on 08-09-2026 01:56:19):
event.category="file" and (endpoint.os="windows" and (tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\InvGate-ED.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\DepHlp.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\files\\InvGateAssetsRD.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\files\\InvGateRD.exe" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\files\\sas.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\Software Matt.dll" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\InvClient-Log.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\logs\\InvClient-Log.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\logs\\InvClient-Log_SoftwareMet.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\logs\\InvClient-Log_Service.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\logs\*" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\build.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\invid" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\sm_rep.inv" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\sm_temp.inv" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\usbFiles\\usbLog.txt" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\4.002.004.ver" or tgt.file.path contains "C:\\Program Files (x86)\\Inventec\\InvGate.net Client\\5.001.004.ver" or tgt.file.path contains "C:\\Windows\\Installer\\{41F5BB80-6416-4AF4-B67B-FA36C29DB4C4}\\ARPPRODUCTICON.exe"))
```


# Original Sigma Rule:
```yaml
title: Potential InvGate RMM Tool File Activity
id: dbb8e27c-b01d-5e85-b1e7-5b8756c39bc0
status: experimental
description: |
    Detects potential files activity of InvGate RMM tool
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
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\InvGate-ED.exe'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\DepHlp.exe'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\files\InvGateAssetsRD.exe'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\files\InvGateRD.exe'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\files\sas.dll'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\Software Matt.dll'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\InvClient-Log.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\logs\InvClient-Log.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\logs\InvClient-Log_SoftwareMet.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\logs\InvClient-Log_Service.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\logs\*'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\build.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\invid'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\sm_rep.inv'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\sm_temp.inv'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\usbFiles\usbLog.txt'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\4.002.004.ver'
            - 'C:\Program Files (x86)\Inventec\InvGate.net Client\5.001.004.ver'
            - 'C:\Windows\Installer\{41F5BB80-6416-4AF4-B67B-FA36C29DB4C4}\ARPPRODUCTICON.exe'
    condition: selection
falsepositives:
    - Legitimate use of InvGate
level: medium
```
