# FQDA



```
"type": "urn:ietf:params:acme:error:dns",
"detail": "During secondary validation: DNS problem: SERVFAIL looking up CAA for life.startops.com.cn - the domain's nameservers may be malfunctioning"
```

CAA 是一类 DNS 记录，网站所有者可以通过它规定哪些证书颁发机构（CA）有权为其域名颁发证书。

关于CAA记录可以参考: https://letsencrypt.org/zh-cn/docs/caa/

添加CAA记录 @ => 0 issue "letsencrypt.org"

该问题的大概意思是，CA去验证域名CAA记录时，未验证通过，需要授权 letsencrypt.org 授权颁发证书



