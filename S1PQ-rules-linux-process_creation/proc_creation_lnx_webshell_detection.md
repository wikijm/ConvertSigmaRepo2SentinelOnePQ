```sql
// Translated content (automatically translated on 07-09-2026 01:53:56):
event.type="Process Creation" and (endpoint.os="linux" and (((src.process.image.path contains "/httpd" or src.process.image.path contains "/lighttpd" or src.process.image.path contains "/nginx" or src.process.image.path contains "/apache2" or src.process.image.path contains "/node" or src.process.image.path contains "/caddy") or (src.process.cmdline contains "/bin/java" and src.process.cmdline contains "tomcat") or (src.process.cmdline contains "/bin/java" and src.process.cmdline contains "websphere")) and (tgt.process.image.path contains "/whoami" or tgt.process.image.path contains "/ifconfig" or tgt.process.image.path contains "/ip" or tgt.process.image.path contains "/bin/uname" or tgt.process.image.path contains "/bin/cat" or tgt.process.image.path contains "/bin/crontab" or tgt.process.image.path contains "/hostname" or tgt.process.image.path contains "/iptables" or tgt.process.image.path contains "/netstat" or tgt.process.image.path contains "/pwd" or tgt.process.image.path contains "/route") and (not (src.process.image.path contains "/node" and tgt.process.cmdline contains "ip neigh show"))))
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
modified: 2026-08-19
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: linux
    category: process_creation
detection:
    selection_parent_general:
        ParentImage|endswith:
            - '/httpd'
            - '/lighttpd'
            - '/nginx'
            - '/apache2'
            - '/node'
            - '/caddy'
    selection_parent_tomcat:
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'tomcat'
    selection_parent_websphere:  # ? just guessing
        ParentCommandLine|contains|all:
            - '/bin/java'
            - 'websphere'
    selection_child_processes:
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
    filter_optional_ip_neigh:
        ParentImage|endswith: '/node'
        CommandLine|contains: 'ip neigh show'
    condition: 1 of selection_parent_* and selection_child_processes and not 1 of filter_optional_*
falsepositives:
    - Web applications that invoke Linux command line tools
level: high
```
