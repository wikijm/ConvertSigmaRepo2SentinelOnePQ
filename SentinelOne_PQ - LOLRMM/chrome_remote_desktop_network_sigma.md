```sql
// Translated content (automatically translated on 09-09-2026 02:01:10):
(event.category in ("dns","url","ip")) and (endpoint.os="windows" and ((url.address contains ".remotedesktop.google.com" or url.address contains "remotedesktop-pa.googleapis.com" or url.address contains ".remotedesktop-pa.googleapis.com" or url.address contains "remotedesktop.google.com" or url.address contains "chromoting-client.talkgadget.google.com" or url.address contains "chromoting-host.talkgadget.google.com" or url.address contains "chromoting-oauth.talkgadget.google.com") or (event.dns.request contains ".remotedesktop.google.com" or event.dns.request contains "remotedesktop-pa.googleapis.com" or event.dns.request contains ".remotedesktop-pa.googleapis.com" or event.dns.request contains "remotedesktop.google.com" or event.dns.request contains "chromoting-client.talkgadget.google.com" or event.dns.request contains "chromoting-host.talkgadget.google.com" or event.dns.request contains "chromoting-oauth.talkgadget.google.com")))
```


# Original Sigma Rule:
```yaml
title: Potential Chrome Remote Desktop RMM Tool Network Activity
id: fb58cca5-8a73-401f-92ad-abf0e5c09e89
status: experimental
description: |
    Detects potential network activity of Chrome Remote Desktop RMM tool
references:
    - https://github.com/magicsword-io/LOLRMM
author: LOLRMM Project
date: 2025-12-01
modified: 2026-09-02
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        DestinationHostname|endswith:
            - '*.remotedesktop.google.com'
            - 'remotedesktop-pa.googleapis.com'
            - '*.remotedesktop-pa.googleapis.com'
            - 'remotedesktop.google.com'
            - 'chromoting-client.talkgadget.google.com'
            - 'chromoting-host.talkgadget.google.com'
            - 'chromoting-oauth.talkgadget.google.com'
    condition: selection
falsepositives:
    - Legitimate use of Chrome Remote Desktop
level: medium
```
