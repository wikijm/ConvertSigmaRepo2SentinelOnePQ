```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and (((src.process.image.path contains "\\caddy.exe" or src.process.image.path contains "\\httpd.exe" or src.process.image.path contains "\\nginx.exe" or src.process.image.path contains "\\php-cgi.exe" or src.process.image.path contains "\\php.exe" or src.process.image.path contains "\\tomcat.exe" or src.process.image.path contains "\\UMWorkerProcess.exe" or src.process.image.path contains "\\w3wp.exe" or src.process.image.path contains "\\ws_TomcatService.exe") or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (src.process.image.path contains "-tomcat-" or src.process.image.path contains "\\tomcat")) or ((src.process.image.path contains "\\java.exe" or src.process.image.path contains "\\javaw.exe") and (src.process.cmdline contains "CATALINA_HOME" or src.process.cmdline contains "catalina.home" or src.process.cmdline contains "catalina.jar"))) and (tgt.process.image.path contains "\\arp.exe" or tgt.process.image.path contains "\\at.exe" or tgt.process.image.path contains "\\bash.exe" or tgt.process.image.path contains "\\bitsadmin.exe" or tgt.process.image.path contains "\\certutil.exe" or tgt.process.image.path contains "\\cmd.exe" or tgt.process.image.path contains "\\cscript.exe" or tgt.process.image.path contains "\\dsget.exe" or tgt.process.image.path contains "\\hostname.exe" or tgt.process.image.path contains "\\nbtstat.exe" or tgt.process.image.path contains "\\net.exe" or tgt.process.image.path contains "\\net1.exe" or tgt.process.image.path contains "\\netdom.exe" or tgt.process.image.path contains "\\netsh.exe" or tgt.process.image.path contains "\\nltest.exe" or tgt.process.image.path contains "\\ntdsutil.exe" or tgt.process.image.path contains "\\powershell_ise.exe" or tgt.process.image.path contains "\\powershell.exe" or tgt.process.image.path contains "\\pwsh.exe" or tgt.process.image.path contains "\\qprocess.exe" or tgt.process.image.path contains "\\query.exe" or tgt.process.image.path contains "\\qwinsta.exe" or tgt.process.image.path contains "\\reg.exe" or tgt.process.image.path contains "\\rundll32.exe" or tgt.process.image.path contains "\\sc.exe" or tgt.process.image.path contains "\\sh.exe" or tgt.process.image.path contains "\\wmic.exe" or tgt.process.image.path contains "\\wscript.exe" or tgt.process.image.path contains "\\wusa.exe") and (not ((src.process.image.path contains "\\java.exe" and tgt.process.cmdline contains "Windows\\system32\\cmd.exe /c C:\\ManageEngine\\ADManager \"Plus\\ES\\bin\\elasticsearch.bat -Enode.name=RMP-NODE1 -pelasticsearch-pid.txt") or (src.process.image.path contains "\\java.exe" and (tgt.process.cmdline contains "sc query" and tgt.process.cmdline contains "ADManager Plus"))))))
```


# Original Sigma Rule:
```yaml
title: Suspicious Process By Web Server Process
id: 8202070f-edeb-4d31-a010-a26c72ac5600
status: test
description: |
    Detects potentially suspicious processes being spawned by a web server process which could be the result of a successfully placed web shell or exploitation
references:
    - https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
author: Thomas Patzke, Florian Roth (Nextron Systems), Zach Stanford @svch0st, Tim Shelton, Nasreddine Bencherchali (Nextron Systems)
date: 2019-01-16
modified: 2024-11-26
tags:
    - attack.persistence
    - attack.initial-access
    - attack.t1505.003
    - attack.t1190
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
            - '\php.exe'
            - '\tomcat.exe'
            - '\UMWorkerProcess.exe'  # https://www.fireeye.com/blog/threat-research/2021/03/detection-response-to-exploitation-of-microsoft-exchange-zero-day-vulnerabilities.html
            - '\w3wp.exe'
            - '\ws_TomcatService.exe'
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
        ParentCommandLine|contains:
            - 'CATALINA_HOME'
            - 'catalina.home'
            - 'catalina.jar'
    selection_anomaly_children:
        Image|endswith:
            - '\arp.exe'
            - '\at.exe'
            - '\bash.exe'
            - '\bitsadmin.exe'
            - '\certutil.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\dsget.exe'
            - '\hostname.exe'
            - '\nbtstat.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\netdom.exe'
            - '\netsh.exe'
            - '\nltest.exe'
            - '\ntdsutil.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\qprocess.exe'
            - '\query.exe'
            - '\qwinsta.exe'
            - '\reg.exe'
            - '\rundll32.exe'
            - '\sc.exe'
            - '\sh.exe'
            - '\wmic.exe'
            - '\wscript.exe'
            - '\wusa.exe'
    filter_main_fp_1:
        ParentImage|endswith: '\java.exe'
        CommandLine|endswith: 'Windows\system32\cmd.exe /c C:\ManageEngine\ADManager "Plus\ES\bin\elasticsearch.bat -Enode.name=RMP-NODE1 -pelasticsearch-pid.txt'
    filter_main_fp_2:
        ParentImage|endswith: '\java.exe'
        CommandLine|contains|all:
            - 'sc query'
            - 'ADManager Plus'
    condition: 1 of selection_webserver_* and selection_anomaly_children and not 1 of filter_main_*
falsepositives:
    - Particular web applications may spawn a shell process legitimately
level: high
```
