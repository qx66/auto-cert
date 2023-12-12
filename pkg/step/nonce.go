package step

// 2 获取随机数
// 在密码学中Nonce是一个只被使用一次的任意或非重复的随机数值

import (
	"errors"
	"net/http"
)

func GetNonce(newNonceUrl string) (string, error) {
	resp, err := http.Head(newNonceUrl)
	if err != nil {
		return "", err
	}
	
	contentLength := resp.ContentLength
	if contentLength > 0 {
		return "", errors.New("contentLength greater than 0")
	}
	
	replayNonce := resp.Header.Get("Replay-Nonce")
	return replayNonce, nil
}
