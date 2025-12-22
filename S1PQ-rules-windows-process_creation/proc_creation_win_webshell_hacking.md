```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\caddy.exe" or src.process.image.path contains "\\httpd.exe" or src.process.image.path contains "\\nginx.exe" or src.process.image.path contains "\\php-cgi.exe" or src.process.image.path contains "\\w3wp.exe" or src.process.image.path contains "\\ws_tomcatservice.exe") or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (src.process.image.path contains "-tomcat-" or src.process.image.path contains "\\tomcat")) or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (tgt.process.cmdline contains "catalina.jar" or tgt.process.cmdline contains "CATALINA_HOME"))) and ((tgt.process.cmdline contains "rundll32" and tgt.process.cmdline contains "comsvcs") or (tgt.process.cmdline contains " -hp" and tgt.process.cmdline contains " a " and tgt.process.cmdline contains " -m") or (tgt.process.cmdline contains "net" and tgt.process.cmdline contains " user " and tgt.process.cmdline contains " /add") or (tgt.process.cmdline contains "net" and tgt.process.cmdline contains " localgroup " and tgt.process.cmdline contains " administrators " and tgt.process.cmdline contains "/add") or (tgt.process.image.path contains "\\ntdsutil.exe" or tgt.process.image.path contains "\\ldifde.exe" or tgt.process.image.path contains "\\adfind.exe" or tgt.process.image.path contains "\\procdump.exe" or tgt.process.image.path contains "\\Nanodump.exe" or tgt.process.image.path contains "\\vssadmin.exe" or tgt.process.image.path contains "\\fsutil.exe") or (tgt.process.cmdline contains " -decode " or tgt.process.cmdline contains " -NoP " or tgt.process.cmdline contains " -W Hidden " or tgt.process.cmdline contains " /decode " or tgt.process.cmdline contains " /ticket:" or tgt.process.cmdline contains " sekurlsa" or tgt.process.cmdline contains ".dmp full" or tgt.process.cmdline contains ".downloadfile(" or tgt.process.cmdline contains ".downloadstring(" or tgt.process.cmdline contains "FromBase64String" or tgt.process.cmdline contains "process call create" or tgt.process.cmdline contains "reg save " or tgt.process.cmdline contains "whoami /priv"))))
```


# Original Sigma Rule:
```yaml
title: Webshell Hacking Activity Patterns
id: 4ebc877f-4612-45cb-b3a5-8e3834db36c9
status: test
description: |
    Detects certain parent child patterns found in cases in which a web shell is used to perform certain credential dumping or exfiltration activities on a compromised system
references:
    - https://youtu.be/7aemGhaE9ds?t=641
author: Florian Roth (Nextron Systems)
date: 2022-03-17
modified: 2023-11-09
tags:
    - attack.persistence
    - attack.discovery
    - attack.t1505.003
    - attack.t1018
    - attack.t1033
    - attack.t1087
logsource:
    category: process_creation
    product: windows
detection:
   # Webserver
    selection_webserver_image:
        ParentImage|endswith:
            - '\caddy.exe'
            - '\httpd.exe'
            - '\nginx.exe'
            - '\php-cgi.exe'
            - '\w3wp.exe'
            - '\ws_tomcatservice.exe'
    selection_webserver_characteristics_tomcat1:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
        ParentImage|contains:
            - '-tomcat-'
            - '\tomcat'
    selection_webserver_characteristics_tomcat2:
        ParentImage|endswith:
            - '\java.exe'
            - '\javaw.exe'
        CommandLine|contains:
            - 'catalina.jar'
            - 'CATALINA_HOME'
    # Suspicious child processes
    selection_child_1:
        # Process dumping
        CommandLine|contains|all:
            - 'rundll32'
            - 'comsvcs'
    selection_child_2:
        # Winrar exfil
        CommandLine|contains|all:
            - ' -hp'
            - ' a '
            - ' -m'
    selection_child_3:
        # User add
        CommandLine|contains|all:
            - 'net'
            - ' user '
            - ' /add'
    selection_child_4:
        CommandLine|contains|all:
            - 'net'
            - ' localgroup '
            - ' administrators '
            - '/add'
    selection_child_5:
        Image|endswith:
            # Credential stealing
            - '\ntdsutil.exe'
            # AD recon
            - '\ldifde.exe'
            - '\adfind.exe'
            # Process dumping
            - '\procdump.exe'
            - '\Nanodump.exe'
            # Destruction / ransom groups
            - '\vssadmin.exe'
            - '\fsutil.exe'
    selection_child_6:
        # SUspicious patterns
        CommandLine|contains:
            - ' -decode '  # Used with certutil
            - ' -NoP '  # Often used in malicious PowerShell commands
            - ' -W Hidden '  # Often used in malicious PowerShell commands
            - ' /decode '  # Used with certutil
            - ' /ticket:'  # Rubeus
            - ' sekurlsa'  # Mimikatz
            - '.dmp full'  # Process dumping method apart from procdump
            - '.downloadfile('  # PowerShell download command
            - '.downloadstring('  # PowerShell download command
            - 'FromBase64String' # PowerShell encoded payload
            - 'process call create' # WMIC process creation
            - 'reg save '  # save registry SAM - syskey extraction
            - 'whoami /priv'
    condition: 1 of selection_webserver_* and 1 of selection_child_*
falsepositives:
    - Unlikely
level: high
```
