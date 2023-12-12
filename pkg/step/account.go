package step

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type AcctRequestPayload struct {
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"` // 仅用于查找，不希望创建时，设置为 true
}

func (acctRequestPayload AcctRequestPayload) String() string {
	b, _ := json.Marshal(acctRequestPayload)
	return string(b)
}

// Response

type NewAccountResponse struct {
	Status                 string                                   `json:"status,omitempty"`                 // required, 此帐户的状态。可能的值为“有效”、“停用”和“已撤销”。价值 “停用”应用于指示客户端启动 停用而“已撤销”应用于指示服务器启动去激活。
	Contact                []string                                 `json:"contact,omitempty"`                // optional
	TermsOfServiceAgreed   bool                                     `json:"termsOfServiceAgreed,omitempty"`   // optional, 值为 true 表示客户同意服务条款。
	ExternalAccountBinding NewAccountResponseExternalAccountBinding `json:"externalAccountBinding,omitempty"` // optional
	Orders                 string                                   `json:"orders,omitempty"`                 // required, A URL from which a list of orders submitted by this account can be fetched via a POST-as-GET request
	InitialIp              string                                   `json:"initialIp,omitempty"`
	CreatedAt              string                                   `json:"createdAt,omitempty"`
	Key                    ResponseKey                              `json:"key,omitempty"`
}

type ResponseKey struct {
	Kty string `json:"kty,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type NewAccountResponseExternalAccountBinding struct {
}

func (newAccountResponse NewAccountResponse) String() string {
	b, _ := json.Marshal(newAccountResponse)
	return string(b)
}

// req => json.Marshal(struct)
// return => NewAccountResponse, Location, error
// https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.1

func NewAccount(url string, req []byte) (NewAccountResponse, string, string, error) {
	var newAccountResponse NewAccountResponse
	
	param := bytes.NewBuffer(req)
	
	//fmt.Println("param: ", param.String())
	resp, err := http.Post(url, "application/jose+json", param)
	if err != nil {
		return newAccountResponse, "", "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return newAccountResponse, "", "", err
	}
	
	if resp.StatusCode == 400 {
		return newAccountResponse, "", "", errors.New(string(respBodyByte))
	}
	
	location := resp.Header.Get("Location")
	replayNonce := resp.Header.Get("Replay-Nonce")
	
	err = json.Unmarshal(respBodyByte, &newAccountResponse)
	if err != nil {
		return newAccountResponse, "", "", err
	}
	
	return newAccountResponse, location, replayNonce, nil
}

func UpdateAccount(accountUrl string) {
	
}

func DeactivationAccount(accountUrl string) {
	
}

// 生成 payload

func GenerateAccountPayload(mailTo []string, termsOfServiceAgreed, onlyReturnExisting bool) (string, error) {
	payload := AcctRequestPayload{
		Contact:              mailTo,
		TermsOfServiceAgreed: termsOfServiceAgreed,
		OnlyReturnExisting:   onlyReturnExisting,
	}
	
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	
	return string(payloadByte), nil
}
