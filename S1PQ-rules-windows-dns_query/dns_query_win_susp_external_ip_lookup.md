```sql
// Translated content (automatically translated on 22-12-2025 02:20:29):
event.category="dns" and (endpoint.os="windows" and (((event.dns.request in ("www.ip.cn","l2.io")) or (event.dns.request contains "api.2ip.ua" or event.dns.request contains "api.bigdatacloud.net" or event.dns.request contains "api.ipify.org" or event.dns.request contains "bot.whatismyipaddress.com" or event.dns.request contains "canireachthe.net" or event.dns.request contains "checkip.amazonaws.com" or event.dns.request contains "checkip.dyndns.org" or event.dns.request contains "curlmyip.com" or event.dns.request contains "db-ip.com" or event.dns.request contains "edns.ip-api.com" or event.dns.request contains "eth0.me" or event.dns.request contains "freegeoip.app" or event.dns.request contains "geoipy.com" or event.dns.request contains "getip.pro" or event.dns.request contains "icanhazip.com" or event.dns.request contains "ident.me" or event.dns.request contains "ifconfig.io" or event.dns.request contains "ifconfig.me" or event.dns.request contains "ip-api.com" or event.dns.request contains "ip.360.cn" or event.dns.request contains "ip.anysrc.net" or event.dns.request contains "ip.taobao.com" or event.dns.request contains "ip.tyk.nu" or event.dns.request contains "ipaddressworld.com" or event.dns.request contains "ipapi.co" or event.dns.request contains "ipconfig.io" or event.dns.request contains "ipecho.net" or event.dns.request contains "ipinfo.io" or event.dns.request contains "ipip.net" or event.dns.request contains "ipof.in" or event.dns.request contains "ipv4.icanhazip.com" or event.dns.request contains "ipv4bot.whatismyipaddress.com" or event.dns.request contains "ipv6-test.com" or event.dns.request contains "ipwho.is" or event.dns.request contains "jsonip.com" or event.dns.request contains "myexternalip.com" or event.dns.request contains "seeip.org" or event.dns.request contains "wgetip.com" or event.dns.request contains "whatismyip.akamai.com" or event.dns.request contains "whois.pconline.com.cn" or event.dns.request contains "wtfismyip.com")) and (not (src.process.image.path contains "\\brave.exe" or (src.process.image.path in ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or (src.process.image.path in ("C:\\Program Files\\Mozilla Firefox\\firefox.exe","C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or (src.process.image.path in ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe","C:\\Program Files\\Internet Explorer\\iexplore.exe")) or src.process.image.path contains "\\maxthon.exe" or (src.process.image.path contains "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or src.process.image.path contains "\\WindowsApps\\MicrosoftEdge.exe" or (src.process.image.path in ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((src.process.image.path contains "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or src.process.image.path contains "C:\\Program Files\\Microsoft\\EdgeCore\\") and (src.process.image.path contains "\\msedge.exe" or src.process.image.path contains "\\msedgewebview2.exe")) or src.process.image.path contains "\\opera.exe" or src.process.image.path contains "\\safari.exe" or src.process.image.path contains "\\seamonkey.exe" or src.process.image.path contains "\\vivaldi.exe" or src.process.image.path contains "\\whale.exe"))))
```


# Original Sigma Rule:
```yaml
title: Suspicious DNS Query for IP Lookup Service APIs
id: ec82e2a5-81ea-4211-a1f8-37a0286df2c2
status: test
description: Detects DNS queries for IP lookup services such as "api.ipify.org" originating from a non browser process.
references:
    - https://www.binarydefense.com/analysis-of-hancitor-when-boring-begets-beacon
    - https://twitter.com/neonprimetime/status/1436376497980428318
    - https://www.trendmicro.com/en_us/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
author: Brandon George (blog post), Thomas Patzke
date: 2021-07-08
modified: 2024-03-22
tags:
    - attack.reconnaissance
    - attack.t1590
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        - QueryName:
              - 'www.ip.cn'
              - 'l2.io'
        - QueryName|contains:
              - 'api.2ip.ua'
              - 'api.bigdatacloud.net'
              - 'api.ipify.org'
              - 'bot.whatismyipaddress.com'
              - 'canireachthe.net'
              - 'checkip.amazonaws.com'
              - 'checkip.dyndns.org'
              - 'curlmyip.com'
              - 'db-ip.com'
              - 'edns.ip-api.com'
              - 'eth0.me'
              - 'freegeoip.app'
              - 'geoipy.com'
              - 'getip.pro'
              - 'icanhazip.com'
              - 'ident.me'
              - 'ifconfig.io'
              - 'ifconfig.me'
              - 'ip-api.com'
              - 'ip.360.cn'
              - 'ip.anysrc.net'
              - 'ip.taobao.com'
              - 'ip.tyk.nu'
              - 'ipaddressworld.com'
              - 'ipapi.co'
              - 'ipconfig.io'
              - 'ipecho.net'
              - 'ipinfo.io'
              - 'ipip.net'
              - 'ipof.in'
              - 'ipv4.icanhazip.com'
              - 'ipv4bot.whatismyipaddress.com'
              - 'ipv6-test.com'
              - 'ipwho.is'
              - 'jsonip.com'
              - 'myexternalip.com'
              - 'seeip.org'
              - 'wgetip.com'
              - 'whatismyip.akamai.com'
              - 'whois.pconline.com.cn'
              - 'wtfismyip.com'
    filter_optional_brave:
        Image|endswith: '\brave.exe'
    filter_optional_chrome:
        Image:
            - 'C:\Program Files\Google\Chrome\Application\chrome.exe'
            - 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
    filter_optional_firefox:
        Image:
            - 'C:\Program Files\Mozilla Firefox\firefox.exe'
            - 'C:\Program Files (x86)\Mozilla Firefox\firefox.exe'
    filter_optional_ie:
        Image:
            - 'C:\Program Files (x86)\Internet Explorer\iexplore.exe'
            - 'C:\Program Files\Internet Explorer\iexplore.exe'
    filter_optional_maxthon:
        Image|endswith: '\maxthon.exe'
    filter_optional_edge_1:
        - Image|startswith: 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\'
        - Image|endswith: '\WindowsApps\MicrosoftEdge.exe'
        - Image:
              - 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
              - 'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    filter_optional_edge_2:
        Image|startswith:
            - 'C:\Program Files (x86)\Microsoft\EdgeCore\'
            - 'C:\Program Files\Microsoft\EdgeCore\'
        Image|endswith:
            - '\msedge.exe'
            - '\msedgewebview2.exe'
    filter_optional_opera:
        Image|endswith: '\opera.exe'
    filter_optional_safari:
        Image|endswith: '\safari.exe'
    filter_optional_seamonkey:
        Image|endswith: '\seamonkey.exe'
    filter_optional_vivaldi:
        Image|endswith: '\vivaldi.exe'
    filter_optional_whale:
        Image|endswith: '\whale.exe'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Legitimate usage of IP lookup services such as ipify API
level: medium
```
