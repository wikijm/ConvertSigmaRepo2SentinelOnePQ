```sql
// Translated content (automatically translated on 22-12-2025 02:20:29):
event.category="dns" and (endpoint.os="windows" and (event.dns.request contains "azurewebsites.net" and (not ((src.process.image.path in ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe","C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe")) or (src.process.image.path in ("C:\\Program Files\\Mozilla Firefox\\firefox.exe","C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe")) or (src.process.image.path in ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe","C:\\Program Files\\Internet Explorer\\iexplore.exe")) or (src.process.image.path contains "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or src.process.image.path contains "\\WindowsApps\\MicrosoftEdge.exe" or (src.process.image.path in ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe","C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((src.process.image.path contains "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or src.process.image.path contains "C:\\Program Files\\Microsoft\\EdgeCore\\") and (src.process.image.path contains "\\msedge.exe" or src.process.image.path contains "\\msedgewebview2.exe")) or src.process.image.path contains "\\safari.exe" or (src.process.image.path contains "\\MsMpEng.exe" or src.process.image.path contains "\\MsSense.exe") or (src.process.image.path contains "\\brave.exe" and src.process.image.path contains "C:\\Program Files\\BraveSoftware\\") or (src.process.image.path contains "\\AppData\\Local\\Maxthon\\" and src.process.image.path contains "\\maxthon.exe") or (src.process.image.path contains "\\AppData\\Local\\Programs\\Opera\\" and src.process.image.path contains "\\opera.exe") or ((src.process.image.path contains "C:\\Program Files\\SeaMonkey\\" or src.process.image.path contains "C:\\Program Files (x86)\\SeaMonkey\\") and src.process.image.path contains "\\seamonkey.exe") or (src.process.image.path contains "\\AppData\\Local\\Vivaldi\\" and src.process.image.path contains "\\vivaldi.exe") or ((src.process.image.path contains "C:\\Program Files\\Naver\\Naver Whale\\" or src.process.image.path contains "C:\\Program Files (x86)\\Naver\\Naver Whale\\") and src.process.image.path contains "\\whale.exe") or src.process.image.path contains "\\Tor Browser\\" or ((src.process.image.path contains "C:\\Program Files\\Waterfox\\" or src.process.image.path contains "C:\\Program Files (x86)\\Waterfox\\") and src.process.image.path contains "\\Waterfox.exe") or (src.process.image.path contains "\\AppData\\Local\\Programs\\midori-ng\\" and src.process.image.path contains "\\Midori Next Generation.exe") or ((src.process.image.path contains "C:\\Program Files\\SlimBrowser\\" or src.process.image.path contains "C:\\Program Files (x86)\\SlimBrowser\\") and src.process.image.path contains "\\slimbrowser.exe") or (src.process.image.path contains "\\AppData\\Local\\Flock\\" and src.process.image.path contains "\\Flock.exe") or (src.process.image.path contains "\\AppData\\Local\\Phoebe\\" and src.process.image.path contains "\\Phoebe.exe") or ((src.process.image.path contains "C:\\Program Files\\Falkon\\" or src.process.image.path contains "C:\\Program Files (x86)\\Falkon\\") and src.process.image.path contains "\\falkon.exe") or ((src.process.image.path contains "C:\\Program Files (x86)\\Avant Browser\\" or src.process.image.path contains "C:\\Program Files\\Avant Browser\\") and src.process.image.path contains "\\avant.exe")))))
```


# Original Sigma Rule:
```yaml
title: DNS Query To AzureWebsites.NET By Non-Browser Process
id: e043f529-8514-4205-8ab0-7f7d2927b400
related:
    - id: 5c80b618-0dbb-46e6-acbb-03d90bcb6d83
      type: derived
status: test
description: |
    Detects a DNS query by a non browser process on the system to "azurewebsites.net". The latter was often used by threat actors as a malware hosting and exfiltration site.
references:
    - https://www.sentinelone.com/labs/wip26-espionage-threat-actors-abuse-cloud-infrastructure-in-targeted-telco-attacks/
    - https://symantec-enterprise-blogs.security.com/threat-intelligence/harvester-new-apt-attacks-asia
    - https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
    - https://intezer.com/blog/research/how-we-escaped-docker-in-azure-functions/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2024-06-24
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|endswith: 'azurewebsites.net'
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
    filter_optional_safari:
        Image|endswith: '\safari.exe'
    filter_optional_defender:
        Image|endswith:
            - '\MsMpEng.exe' # Microsoft Defender executable
            - '\MsSense.exe' # Windows Defender Advanced Threat Protection Service Executable
    filter_optional_brave:
        Image|endswith: '\brave.exe'
        Image|startswith: 'C:\Program Files\BraveSoftware\'
    filter_optional_maxthon:
        Image|contains: '\AppData\Local\Maxthon\'
        Image|endswith: '\maxthon.exe'
    filter_optional_opera:
        Image|contains: '\AppData\Local\Programs\Opera\'
        Image|endswith: '\opera.exe'
    filter_optional_seamonkey:
        Image|startswith:
            - 'C:\Program Files\SeaMonkey\'
            - 'C:\Program Files (x86)\SeaMonkey\'
        Image|endswith: '\seamonkey.exe'
    filter_optional_vivaldi:
        Image|contains: '\AppData\Local\Vivaldi\'
        Image|endswith: '\vivaldi.exe'
    filter_optional_whale:
        Image|startswith:
            - 'C:\Program Files\Naver\Naver Whale\'
            - 'C:\Program Files (x86)\Naver\Naver Whale\'
        Image|endswith: '\whale.exe'
    filter_optional_tor:
        Image|contains: '\Tor Browser\'
    filter_optional_whaterfox:
        Image|startswith:
            - 'C:\Program Files\Waterfox\'
            - 'C:\Program Files (x86)\Waterfox\'
        Image|endswith: '\Waterfox.exe'
    filter_optional_midori:
        Image|contains: '\AppData\Local\Programs\midori-ng\'
        Image|endswith: '\Midori Next Generation.exe'
    filter_optional_slimbrowser:
        Image|startswith:
            - 'C:\Program Files\SlimBrowser\'
            - 'C:\Program Files (x86)\SlimBrowser\'
        Image|endswith: '\slimbrowser.exe'
    filter_optional_flock:
        Image|contains: '\AppData\Local\Flock\'
        Image|endswith: '\Flock.exe'
    filter_optional_phoebe:
        Image|contains: '\AppData\Local\Phoebe\'
        Image|endswith: '\Phoebe.exe'
    filter_optional_falkon:
        Image|startswith:
            - 'C:\Program Files\Falkon\'
            - 'C:\Program Files (x86)\Falkon\'
        Image|endswith: '\falkon.exe'
    filter_optional_avant:
        Image|startswith:
            - 'C:\Program Files (x86)\Avant Browser\'
            - 'C:\Program Files\Avant Browser\'
        Image|endswith: '\avant.exe'
    condition: selection and not 1 of filter_optional_*
falsepositives:
    - Likely with other browser software. Apply additional filters for any other browsers you might use.
level: medium
```
