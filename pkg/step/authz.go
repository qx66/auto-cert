package step

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// 5 认证

type Authorization struct {
	Identifier Identifier  `json:"identifier"`         // required
	Status     string      `json:"status"`             // required
	Expires    string      `json:"expires,omitempty"`  // optional
	Challenges []Challenge `json:"challenges"`         // required
	Wildcard   bool        `json:"wildcard,omitempty"` // optional
}

type Challenge struct {
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Url       string    `json:"url"`
	Token     string    `json:"token"`
	Validated string    `json:"validated,omitempty"`
	Error     ACMEError `json:"error,omitempty"`
}

type ACMEError struct {
	Type   string `json:"type,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func GetOrderAuthorization(orderAuthorizationUrl string, req []byte) (Authorization, string, error) {
	var authorization Authorization
	param := bytes.NewBuffer(req)
	resp, err := http.Post(orderAuthorizationUrl, "application/jose+json", param)
	if err != nil {
		return authorization, "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return authorization, "", err
	}
	
	err = json.Unmarshal(respBodyByte, &authorization)
	if err != nil {
		return authorization, "", nil
	}
	replayNonce := resp.Header.Get("Replay-Nonce")
	return authorization, replayNonce, nil
}

func DeactivatingAuthorization(orderAuthorizationUrl string, req []byte) {

}

// DNS Challenge
// For example, if the domain name being validated is
//   "www.example.org", then the client would provision the following DNS
//   record: _acme-challenge.www.example.org. 300 IN TXT "gfj9Xq...Rg85nM"

// The client SHOULD de-provision the resource record(s) provisioned for
//   this challenge once the challenge is complete, i.e., once the
//   "status" field of the challenge has the value "valid" or "invalid".

func GetOrderAuthorizationChallenge(orderAuthorizationChallengeUrl string, req []byte) (Challenge, string, error) {
	var challenge Challenge
	param := bytes.NewBuffer(req)
	resp, err := http.Post(orderAuthorizationChallengeUrl, "application/jose+json", param)
	if err != nil {
		return challenge, "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return challenge, "", err
	}
	
	err = json.Unmarshal(respBodyByte, &challenge)
	if err != nil {
		return challenge, "", nil
	}
	
	replayNonce := resp.Header.Get("Replay-Nonce")
	
	return challenge, replayNonce, err
}
