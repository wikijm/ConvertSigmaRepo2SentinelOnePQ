```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((tgt.process.cmdline contains "javascript:" and tgt.process.cmdline contains ".RegisterXLL") or (tgt.process.cmdline contains "url.dll" and tgt.process.cmdline contains "OpenURL") or (tgt.process.cmdline contains "url.dll" and tgt.process.cmdline contains "OpenURLA") or (tgt.process.cmdline contains "url.dll" and tgt.process.cmdline contains "FileProtocolHandler") or (tgt.process.cmdline contains "zipfldr.dll" and tgt.process.cmdline contains "RouteTheCall") or (tgt.process.cmdline contains "shell32.dll" and tgt.process.cmdline contains "Control_RunDLL") or (tgt.process.cmdline contains "shell32.dll" and tgt.process.cmdline contains "ShellExec_RunDLL") or (tgt.process.cmdline contains "mshtml.dll" and tgt.process.cmdline contains "PrintHTML") or (tgt.process.cmdline contains "advpack.dll" and tgt.process.cmdline contains "LaunchINFSection") or (tgt.process.cmdline contains "advpack.dll" and tgt.process.cmdline contains "RegisterOCX") or (tgt.process.cmdline contains "ieadvpack.dll" and tgt.process.cmdline contains "LaunchINFSection") or (tgt.process.cmdline contains "ieadvpack.dll" and tgt.process.cmdline contains "RegisterOCX") or (tgt.process.cmdline contains "ieframe.dll" and tgt.process.cmdline contains "OpenURL") or (tgt.process.cmdline contains "shdocvw.dll" and tgt.process.cmdline contains "OpenURL") or (tgt.process.cmdline contains "syssetup.dll" and tgt.process.cmdline contains "SetupInfObjectInstallAction") or (tgt.process.cmdline contains "setupapi.dll" and tgt.process.cmdline contains "InstallHinfSection") or (tgt.process.cmdline contains "pcwutl.dll" and tgt.process.cmdline contains "LaunchApplication") or (tgt.process.cmdline contains "dfshim.dll" and tgt.process.cmdline contains "ShOpenVerbApplication") or (tgt.process.cmdline contains "dfshim.dll" and tgt.process.cmdline contains "ShOpenVerbShortcut") or (tgt.process.cmdline contains "scrobj.dll" and tgt.process.cmdline contains "GenerateTypeLib" and tgt.process.cmdline contains "http") or (tgt.process.cmdline contains "shimgvw.dll" and tgt.process.cmdline contains "ImageView_Fullscreen" and tgt.process.cmdline contains "http") or (tgt.process.cmdline contains "comsvcs.dll" and tgt.process.cmdline contains "MiniDump")) and (not (tgt.process.cmdline contains "shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver" or (src.process.image.path="C:\\Windows\\System32\\control.exe" and src.process.cmdline contains ".cpl" and (tgt.process.cmdline contains "Shell32.dll" and tgt.process.cmdline contains "Control_RunDLL" and tgt.process.cmdline contains ".cpl")) or (src.process.image.path="C:\\Windows\\System32\\control.exe" and tgt.process.cmdline contains "\"C:\\Windows\\system32\\rundll32.exe\" Shell32.dll,Control_RunDLL \"C:\\Windows\\System32\\" and tgt.process.cmdline contains ".cpl\",")))))
```


# Original Sigma Rule:
```yaml
title: Potentially Suspicious Rundll32 Activity
id: e593cf51-88db-4ee1-b920-37e89012a3c9
status: test
description: Detects suspicious execution of rundll32, with specific calls to some DLLs with known LOLBIN functionalities
references:
    - http://www.hexacorn.com/blog/2017/05/01/running-programs-via-proxy-jumping-on-a-edr-bypass-trampoline/
    - https://twitter.com/Hexacorn/status/885258886428725250
    - https://gist.github.com/ryhanson/227229866af52e2d963cf941af135a52
    - https://twitter.com/nas_bench/status/1433344116071583746 # dfshim.dll,ShOpenVerbShortcut
    - https://twitter.com/eral4m/status/1479106975967240209 # scrobj.dll,GenerateTypeLib
    - https://twitter.com/eral4m/status/1479080793003671557 # shimgvw.dll,ImageView_Fullscreen
author: juju4, Jonhnathan Ribeiro, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2019-01-16
modified: 2023-05-17
tags:
    - attack.defense-evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains|all:
              - 'javascript:'
              - '.RegisterXLL'
        - CommandLine|contains|all:
              - 'url.dll'
              - 'OpenURL'
        - CommandLine|contains|all:
              - 'url.dll'
              - 'OpenURLA'
        - CommandLine|contains|all:
              - 'url.dll'
              - 'FileProtocolHandler'
        - CommandLine|contains|all:
              - 'zipfldr.dll'
              - 'RouteTheCall'
        - CommandLine|contains|all:
              - 'shell32.dll'
              - 'Control_RunDLL'
        - CommandLine|contains|all:
              - 'shell32.dll'
              - 'ShellExec_RunDLL'
        - CommandLine|contains|all:
              - 'mshtml.dll'
              - 'PrintHTML'
        - CommandLine|contains|all:
              - 'advpack.dll'
              - 'LaunchINFSection'
        - CommandLine|contains|all:
              - 'advpack.dll'
              - 'RegisterOCX'
        - CommandLine|contains|all:
              - 'ieadvpack.dll'
              - 'LaunchINFSection'
        - CommandLine|contains|all:
              - 'ieadvpack.dll'
              - 'RegisterOCX'
        - CommandLine|contains|all:
              - 'ieframe.dll'
              - 'OpenURL'
        - CommandLine|contains|all:
              - 'shdocvw.dll'
              - 'OpenURL'
        - CommandLine|contains|all:
              - 'syssetup.dll'
              - 'SetupInfObjectInstallAction'
        - CommandLine|contains|all:
              - 'setupapi.dll'
              - 'InstallHinfSection'
        - CommandLine|contains|all:
              - 'pcwutl.dll'
              - 'LaunchApplication'
        - CommandLine|contains|all:
              - 'dfshim.dll'
              - 'ShOpenVerbApplication'
        - CommandLine|contains|all:
              - 'dfshim.dll'
              - 'ShOpenVerbShortcut'
        - CommandLine|contains|all:
              - 'scrobj.dll'
              - 'GenerateTypeLib'
              - 'http'
        - CommandLine|contains|all:
              - 'shimgvw.dll'
              - 'ImageView_Fullscreen'
              - 'http'
        - CommandLine|contains|all:
              - 'comsvcs.dll'
              - 'MiniDump'
    filter_main_screensaver:
        CommandLine|contains: 'shell32.dll,Control_RunDLL desk.cpl,screensaver,@screensaver'
    filter_main_parent_cpl:  # Settings
        ParentImage: 'C:\Windows\System32\control.exe'
        ParentCommandLine|contains: '.cpl'
        CommandLine|contains|all:
            - 'Shell32.dll'
            - 'Control_RunDLL'
            - '.cpl'
    filter_main_startmenu:
        ParentImage: 'C:\Windows\System32\control.exe'
        CommandLine|startswith: '"C:\Windows\system32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Windows\System32\'
        CommandLine|endswith: '.cpl",'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium
```
