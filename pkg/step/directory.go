package step

// 1

import (
	"encoding/json"
	"io"
	"net/http"
)

// https://datatracker.ietf.org/doc/html/rfc8555#section-6.4.1

type DirectoryResponse struct {
	NewNonce   string                `json:"newNonce"`             // 业务流程（如申请、撤销）时候需要预请求获取一次性令牌的一个接口
	NewAccount string                `json:"newAccount,omitempty"` // 上传 account key 时候调用
	NewOrder   string                `json:"newOrder"`             // 下单的接口
	NewAuthz   string                `json:"newAuthz,omitempty"`   // If the ACME server does not implement pre-authorization, it MUST omit the "newAuthz" field of the directory.
	RevokeCert string                `json:"revokeCert"`           // 撤销证书的接口
	KeyChange  string                `json:"keyChange,omitempty"`  // 更换 KeyPair 的接口
	Meta       directoryResponseMeta `json:"meta,omitempty"`
}

type directoryResponseMeta struct {
	TermsOfService          string   `json:"termsOfService"`          // optional, 标识当前的 URL 服务条款
	Website                 string   `json:"website"`                 // optional, An HTTP or HTTPS URL locating a website providing more information about the ACME server.
	CaaIdentities           []string `json:"caaIdentities"`           // optional, 用于 【RFC6844】中定义的CAA记录验证
	ExternalAccountRequired bool     `json:"externalAccountRequired"` // optional, 如果该字段是 存在并设置为“true”，则 CA 要求所有 newAccount 请求包含“externalAccountBinding”字段 将新帐户与外部帐户关联。
}

func (directoryResponse DirectoryResponse) String() string {
	bytes, _ := json.Marshal(directoryResponse)
	return string(bytes)
}

// 获取 directory 信息

func Directory(directoryUrl string) (DirectoryResponse, error) {
	var directoryResponse DirectoryResponse
	
	resp, err := http.Get(directoryUrl)
	if err != nil {
		return directoryResponse, err
	}
	
	respBody := resp.Body
	
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return directoryResponse, err
	}
	
	err = json.Unmarshal(respBodyByte, &directoryResponse)
	if err != nil {
		return directoryResponse, err
	}
	
	return directoryResponse, nil
}
