package step

import (
	"bytes"
	"errors"
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
	
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", errors.New(string(respBodyByte))
	}
	
	return string(respBodyByte), nil
}

func RevokeCertificate() {

}
