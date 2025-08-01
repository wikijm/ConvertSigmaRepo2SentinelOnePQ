```sql
// Translated content (automatically translated on 02-08-2025 00:59:06):
event.type="Process Creation" and (endpoint.os="linux" and tgt.process.image.path contains "/groupdel")
```


# Original Sigma Rule:
```yaml
title: Group Has Been Deleted Via Groupdel
id: 8a46f16c-8c4c-82d1-b121-0fdd3ba70a84
status: test
description: Detects execution of the "groupdel" binary. Which is used to delete a group. This is sometimes abused by threat actors in order to cover their tracks
references:
    - https://linuxize.com/post/how-to-delete-group-in-linux/
    - https://www.cyberciti.biz/faq/linux-remove-user-command/
    - https://www.cybrary.it/blog/0p3n/linux-commands-used-attackers/
    - https://linux.die.net/man/8/groupdel
author: Tuan Le (NCSGroup)
date: 2022-12-26
tags:
    - attack.impact
    - attack.t1531
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/groupdel'
    condition: selection
falsepositives:
    - Legitimate administrator activities
level: medium
```
