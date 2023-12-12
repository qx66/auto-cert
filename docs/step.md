


// 3 新建账户


POST /acme/new-account HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
"protected": base64url({
"alg": "ES256",
"jwk": {...},
"nonce": "6S8IqOGY7eL2lsGoTZYifg",
"url": "https://example.com/acme/new-account"
}),
"payload": base64url({
"termsOfServiceAgreed": true,
"contact": [
"mailto:cert-admin@example.org",
"mailto:admin@example.org"
]
}),
"signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
}




/*
POST /acme/acct/evOfKhNU60wg HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "ax5RnthDqp_Yf4_HZnFLmA",
"url": "https://example.com/acme/acct/evOfKhNU60wg"
}),
"payload": base64url({
"contact": [
"mailto:certificates@example.org",
"mailto:admin@example.org"
]
}),
"signature": "hDXzvcj8T6fbFbmn...rDzXzzvzpRy64N0o"
}
*/





// 停用账户
/*
POST /acme/acct/evOfKhNU60wg HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "ntuJWWSic4WVNSqeUmshgg",
"url": "https://example.com/acme/acct/evOfKhNU60wg"
}),
"payload": base64url({
"status": "deactivated"
}),
"signature": "earzVLd3m5M4xJzR...bVTqn7R08AKOVf3Y"
}
*/









/*
{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "JHb54aT_KTXBWQOzGYkt9A",
"url": "https://example.com/acme/revoke-cert"
}),
"payload": base64url({
"certificate": "MIIEDTCCAvegAwIBAgIRAP8...",
"reason": 4
}),
"signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
}
*/









/*
POST /acme/cert/mAt3xBGaobw HTTP/1.1
Host: example.com
Content-Type: application/jose+json
Accept: application/pem-certificate-chain

{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "uQpSjlRb4vQVCjVYAyyUWg",
"url": "https://example.com/acme/cert/mAt3xBGaobw"
}),
"payload": "",
"signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
}
*/








/*
一旦客户端认为自己满足了服务器的要求，就应向订单资源的最终确定 URL 发送 POST 请求、 就应向订单资源的最终确定 URL 发送 POST 请求。
POST 主体必须包括一个 CSR

{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
"url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
}),
"payload": base64url({
"csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
}),
"signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
}
*/







