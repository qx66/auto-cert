package biz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/pkg/step"
	"go.uber.org/zap"
)

// Challenge

func (orderUseCase *OrderUseCase) GetOrderAuthorizationsChallenge(c *gin.Context) {
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
	
	if order.Certificate != "" {
		c.JSON(200, gin.H{"errCode": 0, "errMsg": "已通过challenge"})
		return
	}
	
	// 2. 反序列化 authorizations
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
	
	// 6. authorizations (验证) - preCheck(预检查)
	var replyAuthorizations []step.Authorization
	var replyDnsChallenges []DnsChallenge
	replayNonce := &nonce
	var preCheckAuthorizationChallenge bool = true
	
	for _, authorization := range authorizations {
		// 6.1. authorizations GetSignature
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
		
		// 6.2. GetOrderAuthorization
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
		
		//
		if authoriz.Status != "pending" {
			preCheckAuthorizationChallenge = false
			break
		}
		
		// 6.3. GetOrderAuthorization Challenges
		for _, challenge := range authoriz.Challenges {
			if challenge.Type == "dns-01" {
				
				if challenge.Status != "pending" {
					preCheckAuthorizationChallenge = false
					break
				}
				
				fqdn := fmt.Sprintf("_acme-challenge.%s", authoriz.Identifier.Value)
				// 6.3.1 Get Order Authorization DNS auth
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
				
				// 预检查 VerifyTxtRecord
				err = step.VerifyTxtRecord(fqdn, record, orderUseCase.dns)
				if err != nil {
					orderUseCase.logger.Error(
						"Order Authorization Challenge 验证DNS失败",
						zap.Error(err),
					)
					
					preCheckAuthorizationChallenge = false
					
					replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
						DomainName: authoriz.Identifier.Value,
						FQDN:       fqdn,
						Type:       "TXT",
						Token:      challenge.Token,
						Value:      record,
						Status:     challenge.Status,
						Result:     false,
					})
				} else {
					replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
						DomainName: authoriz.Identifier.Value,
						FQDN:       fqdn,
						Type:       "TXT",
						Token:      challenge.Token,
						Value:      record,
						Status:     challenge.Status,
						Result:     true,
					})
				}
			}
		}
	}
	
	// 6.2 预检查未通过
	if !preCheckAuthorizationChallenge {
		c.JSON(200, gin.H{
			"errCode":                        0,
			"errMsg":                         "fail",
			"authorizations":                 replyAuthorizations,
			"dnsChallenges":                  replyDnsChallenges,
			"preCheckAuthorizationChallenge": preCheckAuthorizationChallenge,
		})
		return
	}
	
	// 7. 实际执行 authorization Challenge
	for _, authorization := range authorizations {
		// 7.1. authorizations GetSignature
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
		
		// 7.2. GetOrderAuthorization
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
		
		// 7.3. GetOrderAuthorization Challenges
		for _, challenge := range authoriz.Challenges {
			
			if challenge.Type == "dns-01" {
				fqdn := fmt.Sprintf("_acme-challenge.%s", authoriz.Identifier.Value)
				// 7.3.1 Get Order Authorization DNS auth
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
				
				replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
					DomainName: authoriz.Identifier.Value,
					FQDN:       fqdn,
					Type:       "TXT",
					Token:      challenge.Token,
					Value:      record,
					Status:     challenge.Status,
					Result:     true,
				})
				
				// VerifyTxtRecord
				err = step.VerifyTxtRecord(fqdn, record, orderUseCase.dns)
				if err != nil {
					orderUseCase.logger.Error(
						"Order Authorization Challenge 验证DNS失败",
						zap.Error(err),
					)
					break
				}
				
				// 7.3.2 GetSignature
				getOrderAuthorizationChallengeContent, err := step.GetSignature(challenge.Url, *replayNonce, "{}", account.Url, privateKey)
				
				if err != nil {
					orderUseCase.logger.Error(
						"获取Signature失败",
						zap.String("authorization", authorization),
						zap.Error(err),
					)
					c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
					return
				}
				
				getOrderAuthorizationChallengeBody := bytes.NewBuffer([]byte(getOrderAuthorizationChallengeContent.FullSerialize()))
				
				// 7.3.3 GetOrderAuthorizationChallenge
				challenge, nonce, err := step.GetOrderAuthorizationChallenge(challenge.Url, getOrderAuthorizationChallengeBody.Bytes())
				if err != nil {
					orderUseCase.logger.Error(
						"获取authorization challenge失败",
						zap.String("authorization", authorization),
						zap.Error(err),
					)
					c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error", "challenge": challenge})
					return
				}
				replayNonce = &nonce
			}
		}
	}
	
	c.JSON(200, gin.H{
		"errCode":                        0,
		"errMsg":                         "ok",
		"authorizations":                 replyAuthorizations,
		"dnsChallenges":                  replyDnsChallenges,
		"preCheckAuthorizationChallenge": preCheckAuthorizationChallenge,
	})
	return
}
