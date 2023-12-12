package biz

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/pkg/step"
	"go.uber.org/zap"
)

// 获取订单认证信息

type GetOrderAuthorizationsReq struct {
	UserUuid string `json:"userUuid,omitempty" form:"userUuid" validate:"required"`
}

type DnsChallenge struct {
	DomainName string `json:"domainName"`
	FQDN       string `json:"fqdn"`
	Type       string `json:"type,omitempty"`
	Value      string `json:"value"`
	Token      string `json:"token"`
	Status     string `json:"status"`
	Result     bool   `json:"result"`
}

func (orderUseCase *OrderUseCase) GetOrderAuthorizations(c *gin.Context) {
	orderUuid := c.Param("uuid")
	var req GetOrderAuthorizationsReq
	err := common.BindUriQuery(c, &req)
	if err != nil {
		return
	}
	
	// 1. 获取订单
	order, err := orderUseCase.orderRepo.GetOrder(c.Request.Context(), req.UserUuid, orderUuid)
	if err != nil {
		orderUseCase.logger.Error(
			"获取订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 2. 反序列化订单 Authorizations
	var authorizations []string
	err = json.Unmarshal(order.Authorizations, &authorizations)
	if err != nil {
		orderUseCase.logger.Error(
			"反序列化订单authorizations信息失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 3. 获取账户
	account, err := orderUseCase.accountRepo.GetAccount(c.Request.Context(), req.UserUuid)
	if err != nil {
		orderUseCase.logger.Error(
			"获取用户信息失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	privateKey, err := parsePKCS1PrivateKey([]byte(account.PrivateKey))
	
	if err != nil {
		orderUseCase.logger.Error(
			"解析用户私钥失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 4. 获取 directory
	directory, err := step.Directory(directoryUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 5. 获取 nonce
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		orderUseCase.logger.Error(
			"获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 6. 获取订单 Authorizations 信息
	var replyAuthorizations []step.Authorization
	var replyDnsChallenges []DnsChallenge
	replayNonce := &nonce
	
	for _, authorization := range authorizations {
		// 6.1. 获取 Signature
		getOrderAuthorizationContent, err := step.GetSignature(authorization, *replayNonce, "", account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Signature失败",
				zap.String("authorization", authorization),
				zap.Error(err),
			)
			c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
			return
		}
		
		getOrderAuthorizationBody := bytes.NewBuffer([]byte(getOrderAuthorizationContent.FullSerialize()))
		// 6.2. 获取 Authorization
		authoriz, nonce, err := step.GetOrderAuthorization(authorization, getOrderAuthorizationBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"获取authorization失败",
				zap.String("authorization", authorization),
				zap.Error(err),
			)
			c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
			return
		}
		
		replyAuthorizations = append(replyAuthorizations, authoriz)
		replayNonce = &nonce
		
		if authoriz.Status != "pending" {
			break
		}
		
		for _, challenge := range authoriz.Challenges {
			if challenge.Type == "dns-01" {
				
				authKey, err := step.GetKeyAuthorization(challenge.Token, privateKey)
				if err != nil {
					orderUseCase.logger.Error(
						"生成auth challenge key失败",
						zap.String("authorization", authorization),
						zap.Error(err),
					)
					c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
					return
				}
				
				fqdn, record := step.GetRecord(authoriz.Identifier.Value, authKey)
				
				// VerifyTxtRecord
				var verifyResult bool = false
				err = step.VerifyTxtRecord(fqdn, record, orderUseCase.dns)
				if err != nil {
					verifyResult = false
				} else {
					verifyResult = true
				}
				
				replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
					DomainName: authoriz.Identifier.Value,
					FQDN:       fqdn,
					Type:       "TXT",
					Value:      record,
					Token:      challenge.Token,
					Status:     challenge.Status,
					Result:     verifyResult,
				})
			}
		}
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "authorizations": replyAuthorizations, "dnsChallenges": replyDnsChallenges})
	return
}
