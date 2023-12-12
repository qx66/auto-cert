package step

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"gopkg.in/square/go-jose.v2"
	"os"
	"strconv"
)

/*
消息签名:

1. 创建用于 JWS 有效负载内容
2. 编码有效负载值 BASE64URL(JWS Payload)

3. 创建包含所需报头参数集的 JSON 对象，这些参数集共同组成 JOSE 报文
4. 编码报头值 BASE64URL(UTF8(JWS Protected Header)) (Protected 值)

5. BASE64URL(UTF8(JWS Protected Header)).BASE64URL(JWS Payload)  计算签名
6. 对签名值进行 BASE64URL 签名

7. 如果使用的是 JWS JSON序列化，则对每个执行的数字签名重复此过程

8. 创建所需的序列化输出
*/

func base64urlDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

type nonceManager struct {
	nonce string
}

func (nonceManager *nonceManager) Nonce() (string, error) {
	return nonceManager.nonce, nil
}

// From lego (https://github.com/go-acme/lego)

func GetSignature(url, nonce, payload, kid string, privateKey *rsa.PrivateKey) (*jose.JSONWebSignature, error) {
	var alg jose.SignatureAlgorithm
	
	alg = jose.RS256
	
	// “jwk”和“kid”字段是互斥的。服务器必须拒绝包含两者的请求。
	protected := jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:   privateKey,
			KeyID: kid, // account url
		},
	}
	
	options := jose.SignerOptions{
		NonceSource: &nonceManager{
			nonce: nonce,
		},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}
	
	if kid == "" {
		options.EmbedJWK = true
	}
	
	signer, err := jose.NewSigner(protected, &options)
	if err != nil {
		return nil, fmt.Errorf("failed to create jose signer: %w", err)
	}
	
	signed, err := signer.Sign([]byte(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to sign content: %w", err)
	}
	
	return signed, nil
}

var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

func GenerateCSR(privateKey crypto.PrivateKey, domain string, san []string, mustStaple bool) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: san,
	}
	
	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}
	
	return x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
}

func GetKeyAuthorization(token string, key *rsa.PrivateKey) (string, error) {
	var publicKey crypto.PublicKey
	publicKey = key.Public()
	
	// Generate the Key Authorization for the challenge
	jwk := &jose.JSONWebKey{Key: publicKey}
	
	thumbBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	
	// unpad the base64URL
	keyThumb := base64.RawURLEncoding.EncodeToString(thumbBytes)
	
	return token + "." + keyThumb, nil
}

// GetRecord returns a DNS record which will fulfill the `dns-01` challenge.
func GetRecord(domain, keyAuth string) (fqdn, value string) {
	keyAuthShaBytes := sha256.Sum256([]byte(keyAuth))
	// base64URL encoding without padding
	value = base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size])
	fqdn = fmt.Sprintf("_acme-challenge.%s.", domain)
	
	if ok, _ := strconv.ParseBool(os.Getenv("LEGO_EXPERIMENTAL_CNAME_SUPPORT")); ok {
		r, err := dnsQuery(fqdn, dns.TypeCNAME, recursiveNameservers, true)
		// Check if the domain has CNAME then return that
		if err == nil && r.Rcode == dns.RcodeSuccess {
			fqdn = updateDomainWithCName(r, fqdn)
		}
	}
	
	return
}
