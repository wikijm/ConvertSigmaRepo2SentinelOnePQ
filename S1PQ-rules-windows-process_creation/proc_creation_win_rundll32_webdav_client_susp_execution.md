```sql
// Translated content (automatically translated on 22-12-2025 02:21:40):
event.type="Process Creation" and (endpoint.os="windows" and ((src.process.image.path contains "\\svchost.exe" and src.process.cmdline contains "-s WebClient" and tgt.process.image.path contains "\\rundll32.exe" and tgt.process.cmdline contains "C:\\windows\\system32\\davclnt.dll,DavSetCookie" and tgt.process.cmdline matches "://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}") and (not (tgt.process.cmdline contains "://10." or tgt.process.cmdline contains "://192.168." or tgt.process.cmdline contains "://172.16." or tgt.process.cmdline contains "://172.17." or tgt.process.cmdline contains "://172.18." or tgt.process.cmdline contains "://172.19." or tgt.process.cmdline contains "://172.20." or tgt.process.cmdline contains "://172.21." or tgt.process.cmdline contains "://172.22." or tgt.process.cmdline contains "://172.23." or tgt.process.cmdline contains "://172.24." or tgt.process.cmdline contains "://172.25." or tgt.process.cmdline contains "://172.26." or tgt.process.cmdline contains "://172.27." or tgt.process.cmdline contains "://172.28." or tgt.process.cmdline contains "://172.29." or tgt.process.cmdline contains "://172.30." or tgt.process.cmdline contains "://172.31." or tgt.process.cmdline contains "://127." or tgt.process.cmdline contains "://169.254."))))
```


# Original Sigma Rule:
```yaml
title: Suspicious WebDav Client Execution Via Rundll32.EXE
id: 982e9f2d-1a85-4d5b-aea4-31f5e97c6555
status: test
description: |
    Detects "svchost.exe" spawning "rundll32.exe" with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server) or potentially a sign of exploitation of CVE-2023-23397
references:
    - https://twitter.com/aceresponder/status/1636116096506818562
    - https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
    - https://www.pwndefend.com/2023/03/15/the-long-game-persistent-hash-theft/
    - https://www.microsoft.com/en-us/security/blog/wp-content/uploads/2023/03/Figure-7-sample-webdav-process-create-event.png
    - https://www.microsoft.com/en-us/security/blog/2023/03/24/guidance-for-investigating-attacks-using-cve-2023-23397/
author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
date: 2023-03-16
modified: 2023-09-18
tags:
    - attack.exfiltration
    - attack.t1048.003
    - cve.2023-23397
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        ParentCommandLine|contains: '-s WebClient'
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'C:\windows\system32\davclnt.dll,DavSetCookie'
        CommandLine|re: '://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    filter_local_ips:
        CommandLine|contains:
            - '://10.' # 10.0.0.0/8
            - '://192.168.' # 192.168.0.0/16
            - '://172.16.' # 172.16.0.0/12
            - '://172.17.'
            - '://172.18.'
            - '://172.19.'
            - '://172.20.'
            - '://172.21.'
            - '://172.22.'
            - '://172.23.'
            - '://172.24.'
            - '://172.25.'
            - '://172.26.'
            - '://172.27.'
            - '://172.28.'
            - '://172.29.'
            - '://172.30.'
            - '://172.31.'
            - '://127.' # 127.0.0.0/8
            - '://169.254.' # 169.254.0.0/16
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
