package biz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/qx66/auto-cert/pkg/step"
	"github.com/startopsz/rule/pkg/ssl"
	"go.uber.org/zap"
)

// Task 获取状态为 Pending 状态的订单

func (orderUseCase *OrderUseCase) GetPendingStatusOrder(ctx context.Context) {
	//orderUseCase.logger.Info("开始获取 Pending 状态的订单，并执行检查逻辑")
	// 1. 列出 pending 状态订单
	orders, err := orderUseCase.orderRepo.ListOrderByStatus(ctx, "pending")
	if err != nil {
		orderUseCase.logger.Error(
			"列出Pending状态订单失败",
			zap.Error(err),
		)
	}
	
	// 2. 循环订单
	for _, order := range orders {
		orderUseCase.logger.Info(
			"开始检查Pending状态订单",
			zap.String("orderUuid", order.Uuid),
			zap.String("status", order.Status),
		)
		
		// 2.1. 获取订单关联的账户
		account, err := orderUseCase.accountRepo.GetAccount(ctx, order.AccountUuid)
		if err != nil {
			orderUseCase.logger.Error(
				"获取用户信息失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		privateKey, err := parsePKCS1PrivateKey([]byte(account.PrivateKey))
		if err != nil {
			orderUseCase.logger.Error(
				"解析用户私钥失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.2. 获取 directory
		directory, err := step.Directory(directoryUrl)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Directory失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.3. 获取 nonce
		nonce, err := step.GetNonce(directory.NewNonce)
		if err != nil {
			orderUseCase.logger.Error(
				"获取 ACME Nonce失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.4. 获取订单信息
		getOrderContent, err := step.GetSignature(order.OrderUrl, nonce, "", account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Signature失败",
				zap.Error(err),
			)
			break
		}
		
		getOrderBody := bytes.NewBuffer([]byte(getOrderContent.FullSerialize()))
		
		orderResp, nonce, err := step.GetOrder(order.OrderUrl, getOrderBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"获取Order失败",
				zap.Error(err),
			)
			break
		}
		
		if orderResp.Status != "pending" {
			err = orderUseCase.orderRepo.UpdateOrderStatus(ctx, order.Uuid, orderResp.Status)
			if err != nil {
				orderUseCase.logger.Error(
					"更新订单状态失败",
					zap.Error(err),
					zap.String("orderUuid", order.Uuid),
				)
			}
			break
		}
		
		// 2.4. 反序列化 authorizations
		var authorizations []string
		err = json.Unmarshal(order.Authorizations, &authorizations)
		if err != nil {
			orderUseCase.logger.Error(
				"反序列化订单authorizations信息失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.5. nonce
		replayNonce := &nonce
		
		// 2.6. 循环 authorizations
		for _, authorization := range authorizations {
			
			// 2.6.1. authorizations GetSignature
			getOrderAuthorizationContent, err := step.GetSignature(authorization, *replayNonce, "", account.Url, privateKey)
			if err != nil {
				orderUseCase.logger.Error(
					"获取Signature失败",
					zap.String("authorization", authorization),
					zap.String("orderUuid", order.Uuid),
					zap.Error(err),
				)
				break
			}
			
			getOrderAuthorizationBody := bytes.NewBuffer([]byte(getOrderAuthorizationContent.FullSerialize()))
			
			// 2.6.2. GetOrderAuthorization
			authoriz, nonce, err := step.GetOrderAuthorization(authorization, getOrderAuthorizationBody.Bytes())
			if err != nil {
				orderUseCase.logger.Error(
					"获取authorization失败",
					zap.String("authorization", authorization),
					zap.String("orderUuid", order.Uuid),
					zap.Error(err),
				)
				break
			}
			
			replayNonce = &nonce
			if authoriz.Status != "pending" {
				orderUseCase.logger.Info(
					"订单authorization状态不匹配",
					zap.String("authorization", authorization),
					zap.String("status", authoriz.Status),
					zap.String("orderUuid", order.Uuid),
				)
				break
			}
			
			// 2.6.3. GetOrderAuthorization Challenges
			for _, challenge := range authoriz.Challenges {
				
				if challenge.Type == "dns-01" {
					fqdn := fmt.Sprintf("_acme-challenge.%s", authoriz.Identifier.Value)
					// 2.6.3.1 Get Order Authorization DNS auth
					authKey, err := step.GetKeyAuthorization(challenge.Token, privateKey)
					if err != nil {
						orderUseCase.logger.Error(
							"生成auth challenge key失败",
							zap.String("authorization", authorization),
							zap.String("orderUuid", order.Uuid),
							zap.Error(err),
						)
						break
					}
					
					fqdn, record := step.GetRecord(authoriz.Identifier.Value, authKey)
					
					// 2.6.3.2 VerifyTxtRecord
					err = step.VerifyTxtRecord(fqdn, record, orderUseCase.dns)
					if err != nil {
						orderUseCase.logger.Error(
							"Order Authorization Challenge 验证DNS失败",
							zap.String("orderUuid", order.Uuid),
							zap.String("fqdn", fqdn),
							zap.String("value", record),
							zap.Strings("dns", orderUseCase.dns),
							zap.Error(err),
						)
						break
					}
					
					orderUseCase.logger.Info(
						"Order Authorization Challenge 本地验证DNS成功",
						zap.String("orderUuid", order.Uuid),
						zap.String("fqdn", fqdn),
						zap.String("value", record),
					)
					// 2.6.3.3 GetSignature
					getOrderAuthorizationChallengeContent, err := step.GetSignature(challenge.Url, *replayNonce, "{}", account.Url, privateKey)
					
					if err != nil {
						orderUseCase.logger.Error(
							"获取Signature失败",
							zap.String("authorization", authorization),
							zap.String("orderUuid", order.Uuid),
							zap.Error(err),
						)
						break
					}
					
					getOrderAuthorizationChallengeBody := bytes.NewBuffer([]byte(getOrderAuthorizationChallengeContent.FullSerialize()))
					
					// 2.6.3.4 GetOrderAuthorizationChallenge
					challenge, nonce, err := step.GetOrderAuthorizationChallenge(challenge.Url, getOrderAuthorizationChallengeBody.Bytes())
					if err != nil {
						orderUseCase.logger.Error(
							"获取authorization challenge失败",
							zap.String("authorization", authorization),
							zap.String("orderUuid", order.Uuid),
							zap.Error(err),
						)
						break
					}
					fmt.Println("challenge: ", challenge)
					replayNonce = &nonce
				}
			}
		}
	}
}

// 获取 Ready 状态的订单

func (orderUseCase *OrderUseCase) GetReadyStatusOrder(ctx context.Context) {
	// 1. 列出 ready 状态的订单
	orders, err := orderUseCase.orderRepo.ListOrderByStatus(ctx, "ready")
	if err != nil {
		orderUseCase.logger.Error(
			"列出 ready 状态订单失败",
			zap.Error(err),
		)
	}
	
	// 2. 循环订单
	for _, order := range orders {
		
		orderUseCase.logger.Info(
			"开始检查 ready 状态订单",
			zap.String("orderUuid", order.Uuid),
			zap.String("status", order.Status),
		)
		
		// 2.1. 获取订单关联的账户
		account, err := orderUseCase.accountRepo.GetAccount(ctx, order.AccountUuid)
		if err != nil {
			orderUseCase.logger.Error(
				"获取用户信息失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		privateKey, err := parsePKCS1PrivateKey([]byte(account.PrivateKey))
		if err != nil {
			orderUseCase.logger.Error(
				"解析用户私钥失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.2. 获取 directory
		directory, err := step.Directory(directoryUrl)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Directory失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.3. 获取 nonce
		nonce, err := step.GetNonce(directory.NewNonce)
		if err != nil {
			orderUseCase.logger.Error(
				"获取nonce失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.4. 获取订单信息
		getOrderContent, err := step.GetSignature(order.OrderUrl, nonce, "", account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Signature失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		getOrderBody := bytes.NewBuffer([]byte(getOrderContent.FullSerialize()))
		
		orderResp, nonce, err := step.GetOrder(order.OrderUrl, getOrderBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"获取Order失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		if orderResp.Status != "ready" {
			err = orderUseCase.orderRepo.UpdateOrderStatus(ctx, order.Uuid, orderResp.Status)
			if err != nil {
				orderUseCase.logger.Error(
					"更新订单状态失败",
					zap.String("orderUuid", order.Uuid),
					zap.Error(err),
				)
			}
			break
		}
		
		// 2.5. 获取 Finalize Payload
		finalizeOrderPayload, err := step.GenerateFinalizeOrderPayload(order.Csr)
		if err != nil {
			orderUseCase.logger.Error(
				"生成Payload失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.6. 获取 Signature
		finalizeOrderContent, err := step.GetSignature(order.Finalize, nonce, finalizeOrderPayload, account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"GetSignature失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		finalizeOrderBody := bytes.NewBuffer([]byte(finalizeOrderContent.FullSerialize()))
		
		// 2.7. Finalize Order
		finalizeOrder, err := step.FinalizeOrder(order.Finalize, finalizeOrderBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"FinalizeOrder失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		orderUseCase.logger.Info(
			"FinalizeOrder成功",
			zap.String("orderUuid", order.Uuid),
			zap.String("finalize", finalizeOrder.Finalize),
			zap.String("status", finalizeOrder.Status),
		
		)
		
		// 2.8
		err = orderUseCase.orderRepo.UpdateOrderStatus(ctx, order.Uuid, finalizeOrder.Status)
		if err != nil {
			orderUseCase.logger.Error(
				"更新数据库状态失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
		}
	}
}

// 获取 valid 状态订单

func (orderUseCase *OrderUseCase) GetNotCertificateOrder(ctx context.Context) {
	// 1. 列出 ready 状态的订单
	orders, err := orderUseCase.orderRepo.ListNotCertificateOrder(ctx)
	if err != nil {
		orderUseCase.logger.Error(
			"列出 ready 状态订单失败",
			zap.Error(err),
		)
	}
	
	// 2. 循环订单
	for _, order := range orders {
		
		// 2.1. 获取账户
		account, err := orderUseCase.accountRepo.GetAccount(ctx, order.AccountUuid)
		if err != nil {
			orderUseCase.logger.Error(
				"获取用户信息失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		privateKey, err := parsePKCS1PrivateKey([]byte(account.PrivateKey))
		
		if err != nil {
			orderUseCase.logger.Error(
				"解析用户私钥失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.2. 获取 directory
		directory, err := step.Directory(directoryUrl)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Directory失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.3. 获取 nonce
		nonce, err := step.GetNonce(directory.NewNonce)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Nonce失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.4. 获取 Signature
		getOrderContent, err := step.GetSignature(order.OrderUrl, nonce, "", account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Signature失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		getOrderBody := bytes.NewBuffer([]byte(getOrderContent.FullSerialize()))
		
		// 2.5. 获取订单
		orderResp, nonce, err := step.GetOrder(order.OrderUrl, getOrderBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"获取Order失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 2.6. 获取 Signature
		downloadCertificateContent, err := step.GetSignature(orderResp.Certificate, nonce, "", account.Url, privateKey)
		if err != nil {
			orderUseCase.logger.Error(
				"获取Signature失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		downloadCertificateBody := bytes.NewBuffer([]byte(downloadCertificateContent.FullSerialize()))
		
		// 8. 获取订单证书
		certificate, err := step.DownloadCertificate(orderResp.Certificate, downloadCertificateBody.Bytes())
		if err != nil {
			orderUseCase.logger.Error(
				"获取证书失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		// 9. 更新订单证书数据库信息
		cert, err := ssl.ParseSSLCertificate([]byte(certificate))
		if err != nil {
			orderUseCase.logger.Error(
				"解析证书失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		err = orderUseCase.orderRepo.UpdateOrderCertificate(ctx, order.Uuid, certificate,
			cert.NotBefore.String(), cert.NotAfter.String())
		
		if err != nil {
			orderUseCase.logger.Error(
				"更新订单证书失败",
				zap.String("orderUuid", order.Uuid),
				zap.Error(err),
			)
			break
		}
		
		orderUseCase.logger.Info(
			"更新订单证书成功",
			zap.String("orderUuid", order.Uuid),
		)
	}
}
