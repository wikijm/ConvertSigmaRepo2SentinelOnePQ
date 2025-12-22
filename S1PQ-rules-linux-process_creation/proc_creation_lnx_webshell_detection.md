```sql
// Translated content (automatically translated on 22-12-2025 01:02:22):
event.type="Process Creation" and (endpoint.os="linux" and (((src.process.image.path contains "/httpd" or src.process.image.path contains "/lighttpd" or src.process.image.path contains "/nginx" or src.process.image.path contains "/apache2" or src.process.image.path contains "/node" or src.process.image.path contains "/caddy") or (src.process.cmdline contains "/bin/java" and src.process.cmdline contains "tomcat") or (src.process.cmdline contains "/bin/java" and src.process.cmdline contains "websphere")) and (tgt.process.image.path contains "/whoami" or tgt.process.image.path contains "/ifconfig" or tgt.process.image.path contains "/ip" or tgt.process.image.path contains "/bin/uname" or tgt.process.image.path contains "/bin/cat" or tgt.process.image.path contains "/bin/crontab" or tgt.process.image.path contains "/hostname" or tgt.process.image.path contains "/iptables" or tgt.process.image.path contains "/netstat" or tgt.process.image.path contains "/pwd" or tgt.process.image.path contains "/route")))
```


# Original Sigma Rule:
```yaml
title: Linux Webshell Indicators
id: 818f7b24-0fba-4c49-a073-8b755573b9c7
status: test
description: Detects suspicious sub processes of web server processes
references:
    - https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
    - https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2021-10-15
modified: 2022-12-28
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: linux
    category: process_creation
detection:
    selection_general:
        ParentImage|endswith:
            - '/httpd'
            - '/lighttpd'
            - '/nginx'
            - '/apache2'
            - '/node'
            - '/caddy'
    selection_tomcat:
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'tomcat'
    selection_websphere:  # ? just guessing
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'websphere'
    sub_processes:
        Image|endswith:
            - '/whoami'
            - '/ifconfig'
            - '/ip'
            - '/bin/uname'
            - '/bin/cat'
            - '/bin/crontab'
            - '/hostname'
            - '/iptables'
            - '/netstat'
            - '/pwd'
            - '/route'
    condition: 1 of selection_* and sub_processes
falsepositives:
    - Web applications that invoke Linux command line tools
level: high
```
