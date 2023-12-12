package step

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// 4 新建订单

// payload

type NewOrderRequestPayload struct {
	Identifiers []Identifier `json:"identifiers"`         // required, array of object
	NotBefore   string       `json:"notBefore,omitempty"` // optional
	NotAfter    string       `json:"notAfter,omitempty"`  // optional
}

func GenerateNewOrderPayload(identifiers []Identifier) (string, error) {
	if len(identifiers) == 0 {
		return "", errors.New("identifiers 不能为空")
	}
	
	payload := NewOrderRequestPayload{
		Identifiers: identifiers,
	}
	
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	
	return string(payloadByte), nil
}

// response

type OrderResponse struct {
	Status         string       `json:"status"`                // required,	pending/ready/processing/valid/invalid
	Expires        string       `json:"expires"`               // optional,	订单失效时间, 由服务商或CA决定 If the client fails to complete the required  actions before the "expires" time, then the server SHOULD change the status of the order to "invalid" and MAY delete the order resource.
	NotBefore      string       `json:"notBefore"`             // optional
	NotAfter       string       `json:"notAfter"`              // optional
	Identifiers    []Identifier `json:"identifiers"`           // required
	Authorizations []string     `json:"authorizations"`        // required, 订单需要依次完成的授权验证资源（Auth-Z）的链接    不允许为空数组（必须至少有一个流程）
	Finalize       string       `json:"finalize"`              //  required, 授权验证完成后，调用finalize接口签发证书（包括CSR也是在这一步提交的）, Once the client believes it has fulfilled the server's requirements, it should send a POST request to the order resource's finalize URL. The POST body MUST include a CSR
	Certificate    string       `json:"certificate,omitempty"` // optional
}

func NewOrder(url string, req []byte) (OrderResponse, string, string, error) {
	var orderResponse OrderResponse
	
	param := bytes.NewBuffer(req)
	resp, err := http.Post(url, "application/jose+json", param)
	if err != nil {
		return orderResponse, "", "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return orderResponse, "", "", err
	}
	
	err = json.Unmarshal(respBodyByte, &orderResponse)
	if err != nil {
		return orderResponse, "", "", err
	}
	
	location := resp.Header.Get("Location")
	replayNonce := resp.Header.Get("Replay-Nonce")
	return orderResponse, location, replayNonce, nil
}

func GetOrder(orderUrl string, req []byte) (OrderResponse, string, error) {
	var orderResponse OrderResponse
	param := bytes.NewBuffer(req)
	resp, err := http.Post(orderUrl, "application/jose+json", param)
	if err != nil {
		return orderResponse, "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return orderResponse, "", err
	}
	
	err = json.Unmarshal(respBodyByte, &orderResponse)
	if err != nil {
		return orderResponse, "", err
	}
	
	replayNonce := resp.Header.Get("Replay-Nonce")
	return orderResponse, replayNonce, nil
}

// FinalizeOrder

type FinalizeOrderPayload struct {
	Csr string `json:"csr"`
}

func GenerateFinalizeOrderPayload(csr string) (string, error) {
	payload := FinalizeOrderPayload{
		Csr: csr,
	}
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	
	return string(payloadByte), nil
}

// require Order's status ready

func FinalizeOrder(finalizeOrderUrl string, req []byte) (OrderResponse, error) {
	var order OrderResponse
	
	param := bytes.NewBuffer(req)
	resp, err := http.Post(finalizeOrderUrl, "application/jose+json", param)
	if err != nil {
		return order, err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return order, err
	}
	
	err = json.Unmarshal(respBodyByte, &order)
	return order, err
}

//
// Each account object includes an "orders" URL from which a list of
// orders created by the account can be fetched via POST-as-GET request.
// The result of the request MUST be a JSON object whose "orders" field
// is an array of URLs, each identifying an order belonging to the account.

type OrdersResponse struct {
	orders []string
}

// Each account object includes an "orders" URL from which a list of orders created by the account can be fetched via POST-as-GET request.
// Link: <https://example.com/acme/directory>;rel="index"
//   Link: <https://example.com/acme/orders/rzGoeA?cursor=2>;rel="next"

/*
type GetOrdersResponse struct {
	Orders []string `json:"orders,omitempty"`
}

*/
