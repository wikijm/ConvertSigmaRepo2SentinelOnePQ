```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\caddy.exe" or src.process.image.path contains "\\httpd.exe" or src.process.image.path contains "\\nginx.exe" or src.process.image.path contains "\\php-cgi.exe" or src.process.image.path contains "\\w3wp.exe" or src.process.image.path contains "\\ws_tomcatservice.exe") or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (src.process.image.path contains "-tomcat-" or src.process.image.path contains "\\tomcat")) or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (tgt.process.cmdline contains "CATALINA_HOME" or tgt.process.cmdline contains "catalina.jar"))) and (tgt.process.cmdline contains "perl --help" or tgt.process.cmdline contains "perl -h" or tgt.process.cmdline contains "python --help" or tgt.process.cmdline contains "python -h" or tgt.process.cmdline contains "python3 --help" or tgt.process.cmdline contains "python3 -h" or tgt.process.cmdline contains "wget --help")))
```


# Original Sigma Rule:
```yaml
title: Webshell Tool Reconnaissance Activity
id: f64e5c19-879c-4bae-b471-6d84c8339677
status: test
description: |
    Detects processes spawned from web servers (PHP, Tomcat, IIS, etc.) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands
references:
    - https://ragged-lab.blogspot.com/2020/07/webshells-automating-reconnaissance.html
author: Cian Heasley, Florian Roth (Nextron Systems)
date: 2020-07-22
modified: 2023-11-09
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: windows
detection:
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
            - 'CATALINA_HOME'
            - 'catalina.jar'
    selection_recon:
        CommandLine|contains:
            - 'perl --help'
            - 'perl -h'
            - 'python --help'
            - 'python -h'
            - 'python3 --help'
            - 'python3 -h'
            - 'wget --help'
    condition: 1 of selection_webserver_* and selection_recon
falsepositives:
    - Unknown
level: high
```
