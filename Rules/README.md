# Rules
每日UTC 00:00自动更新

不在此自述文件中的则为手动更新。

## Block
包含绝大部分去广告列表，并且将拦截HTTPDNS
```
https://raw.githubusercontent.com/Uber-Eins/NetConfig/refs/heads/main/Rules/Block.list
```

上游:
```toml
urls = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Advertising/Advertising_All.list",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-surge.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Hijacking/Hijacking.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Privacy/Privacy.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/EasyPrivacy/EasyPrivacy_All.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list",
]
```