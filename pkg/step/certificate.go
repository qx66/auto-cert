package step

import (
	"bytes"
	"io"
	"net/http"
)

func DownloadCertificate(certificateUrl string, req []byte) (string, error) {
	param := bytes.NewBuffer(req)
	
	resp, err := http.Post(certificateUrl, "application/jose+json", param)
	if err != nil {
		return "", err
	}
	
	respBody := resp.Body
	defer resp.Body.Close()
	
	respBodyByte, err := io.ReadAll(respBody)
	if err != nil {
		return "", err
	}
	
	return string(respBodyByte), nil
}

func RevokeCertificate() {

}
