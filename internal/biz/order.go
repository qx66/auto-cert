package biz

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/internal/conf"
	"github.com/qx66/auto-cert/pkg/step"
	"go.uber.org/zap"
	"time"
)

type Order struct {
	Uuid           string `json:"uuid"`
	AccountUuid    string `json:"accountUuid"`
	OrderUrl       string `json:"orderUrl"`
	Status         string `json:"status"`
	Expires        string `json:"expires"`
	NotBefore      string `json:"notBefore"`
	NotAfter       string `json:"notAfter"`
	Identifiers    []byte `json:"identifiers"`
	Authorizations []byte `json:"authorizations"`
	Finalize       string `json:"finalize"`
	PrivateKey     string `json:"privateKey"`  // 证书私钥
	Csr            string `json:"csr"`         // 证书私钥生成的CSR
	Certificate    string `json:"certificate"` // 证书内容
	CreateTime     int64  `json:"createTime"`
}

func (order *Order) TableName() string {
	return "order"
}

type OrderRepo interface {
	CreateOrder(ctx context.Context, order Order) error
	GetOrder(ctx context.Context, userUuid, orderUuid string) (Order, error)
	ListOrder(ctx context.Context, userUuid string) ([]Order, error)
	ListPendingOrder(ctx context.Context) ([]Order, error)
	ExistOrder(ctx context.Context, orderUrl string) (bool, error)
	UpdateOrderCertificate(ctx context.Context, orderUuid, certificate string) error
	UpdateOrderStatus(ctx context.Context, orderUuid, status string) error
}

type OrderUseCase struct {
	orderRepo   OrderRepo
	accountRepo AccountRepo
	dns         []string
	logger      *zap.Logger
}

func NewOrderUseCase(orderRepo OrderRepo, accountRepo AccountRepo, dns *conf.Dns, logger *zap.Logger) *OrderUseCase {
	return &OrderUseCase{
		orderRepo:   orderRepo,
		accountRepo: accountRepo,
		dns:         dns.Dns,
		logger:      logger,
	}
}

// 创建订单

type CreateOrderReq struct {
	UserUuid string   `json:"userUuid,omitempty" validate:"required"`
	Domains  []string `json:"domains,omitempty" validate:"required"`
}

func (orderUseCase *OrderUseCase) CreateOrder(c *gin.Context) {
	var req CreateOrderReq
	err := common.JsonUnmarshal(c, &req)
	if err != nil {
		return
	}
	
	// 1. 获取账户
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
	
	// 2. 获取 directory
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 3. 获取 nonce
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		orderUseCase.logger.Error(
			"获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 4.
	var identifiers []step.Identifier
	for _, domain := range req.Domains {
		identifiers = append(identifiers, step.Identifier{
			Type:  "dns",
			Value: domain,
		})
	}
	
	orderPayload, err := step.GenerateNewOrderPayload(identifiers)
	if err != nil {
		orderUseCase.logger.Error(
			"生成payload信息失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	//
	orderSignedContent, err := step.GetSignature(directory.NewOrder, nonce, orderPayload, account.Url, privateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"生成Signature信息失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	orderSignedBody := bytes.NewBuffer([]byte(orderSignedContent.FullSerialize()))
	
	//
	orderResponse, orderUrl, _, err := step.NewOrder(directory.NewOrder, orderSignedBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"创建订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	//
	existOrder, err := orderUseCase.orderRepo.ExistOrder(c.Request.Context(), orderUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	if existOrder {
		c.JSON(200, gin.H{"errCode": 0, "errMsg": "order already exists"})
		return
	}
	
	identifiersByte, err := json.Marshal(orderResponse.Identifiers)
	authorizationsByte, err := json.Marshal(orderResponse.Authorizations)
	
	//
	var domains []string
	for _, identifier := range identifiers {
		domains = append(domains, identifier.Value)
	}
	
	csrPrivateKey, err := generateRsaPrivateKey()
	if err != nil {
		orderUseCase.logger.Error(
			"创建用户，生成RSA PrivateKey失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	csrPrivateKeyPem, err := marshalPKCS1PrivateKey(csrPrivateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"创建用户，序列化RSA PrivateKey失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	csr, err := step.GenerateCSR(csrPrivateKey, domains[0], domains, false)
	if err != nil {
		orderUseCase.logger.Error(
			"生成证书CSR失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	csrString := base64.RawURLEncoding.EncodeToString(csr)
	
	//
	orderUuid := uuid.NewString()
	order := Order{
		Uuid:           orderUuid,
		AccountUuid:    req.UserUuid,
		OrderUrl:       orderUrl,
		Status:         orderResponse.Status,
		Expires:        orderResponse.Expires,
		NotBefore:      orderResponse.NotBefore,
		NotAfter:       orderResponse.NotAfter,
		Identifiers:    identifiersByte,
		Authorizations: authorizationsByte,
		Finalize:       orderResponse.Finalize,
		PrivateKey:     csrPrivateKeyPem.String(),
		Csr:            csrString,
		Certificate:    "",
		CreateTime:     time.Now().Unix(),
	}
	
	err = orderUseCase.orderRepo.CreateOrder(c.Request.Context(), order)
	if err != nil {
		orderUseCase.logger.Error(
			"记录订单信息到数据库失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "order": orderResponse, "orderUrl": orderUrl, "orderUuid": orderUuid})
	return
}

// 获取订单

type GetOrderReq struct {
	UserUuid string `json:"userUuid,omitempty" form:"userUuid" validate:"required"`
}

func (orderUseCase *OrderUseCase) GetOrder(c *gin.Context) {
	orderUuid := c.Param("uuid")
	var req GetOrderReq
	
	err := common.BindUriQuery(c, &req)
	if err != nil {
		return
	}
	
	order, err := orderUseCase.orderRepo.GetOrder(c.Request.Context(), req.UserUuid, orderUuid)
	if err != nil {
		orderUseCase.logger.Error(
			"获取订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	//
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
	
	//
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	//
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		orderUseCase.logger.Error(
			"获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	//
	getOrderContent, err := step.GetSignature(order.OrderUrl, nonce, "", account.Url, privateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Signature失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	getOrderBody := bytes.NewBuffer([]byte(getOrderContent.FullSerialize()))
	
	orderResp, _, err := step.GetOrder(order.OrderUrl, getOrderBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"获取Order失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "order": orderResp})
	return
}

// 列出订单 - 仅数据库列出

type ListOrderReq struct {
	UserUuid string `json:"userUuid,omitempty" form:"userUuid" validate:"required"`
}

func (orderUseCase *OrderUseCase) ListOrder(c *gin.Context) {
	var req ListOrderReq
	err := common.BindUriQuery(c, &req)
	if err != nil {
		return
	}
	
	orders, err := orderUseCase.orderRepo.ListOrder(c.Request.Context(), req.UserUuid)
	if err != nil {
		orderUseCase.logger.Error(
			"获取订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "orders": orders})
	return
}

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
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
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
		
		if authoriz.Status == "invalid" {
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
					Token:      challenge.Token,
					Value:      record,
					Result:     verifyResult,
				})
			}
		}
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "authorizations": replyAuthorizations, "dnsChallenges": replyDnsChallenges})
	return
}

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
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
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
	
	// 6. authorizations
	var replyAuthorizations []step.Authorization
	var replyDnsChallenges []DnsChallenge
	replayNonce := &nonce
	
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
		
		if authoriz.Status == "invalid" {
			break
		}
		
		// 6.3. GetOrderAuthorization Challenges
		for _, challenge := range authoriz.Challenges {
			if challenge.Type == "dns-01" {
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
				
				// VerifyTxtRecord
				err = step.VerifyTxtRecord(fqdn, record, orderUseCase.dns)
				if err != nil {
					orderUseCase.logger.Error(
						"Order Authorization Challenge 验证DNS失败",
						zap.Error(err),
					)
					
					replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
						DomainName: authoriz.Identifier.Value,
						FQDN:       fqdn,
						Type:       "TXT",
						Token:      challenge.Token,
						Value:      record,
						Result:     false,
					})
					break
				}
				
				replyDnsChallenges = append(replyDnsChallenges, DnsChallenge{
					DomainName: authoriz.Identifier.Value,
					FQDN:       fqdn,
					Type:       "TXT",
					Token:      challenge.Token,
					Value:      record,
					Result:     true,
				})
				
				// 6.3.2 GetSignature
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
				
				// 6.3.3 GetOrderAuthorizationChallenge
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
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "authorizations": replyAuthorizations, "dnsChallenges": replyDnsChallenges})
	return
}

// Finalize

type FinalizeOrderReq struct {
	UserUuid string `json:"userUuid,omitempty" form:"userUuid" validate:"required"`
}

func (orderUseCase *OrderUseCase) FinalizeOrder(c *gin.Context) {
	orderUuid := c.Param("uuid")
	var req FinalizeOrderReq
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
	
	// 2. 获取账户
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
	
	// 3. 获取 directory
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 4. 获取 nonce
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		orderUseCase.logger.Error(
			"获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 5. 获取 Finalize Payload
	finalizeOrderPayload, err := step.GenerateFinalizeOrderPayload(order.Csr)
	if err != nil {
		orderUseCase.logger.Error(
			"生成Payload失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 6. 获取 Signature
	finalizeOrderContent, err := step.GetSignature(order.Finalize, nonce, finalizeOrderPayload, account.Url, privateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"GetSignature失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	finalizeOrderBody := bytes.NewBuffer([]byte(finalizeOrderContent.FullSerialize()))
	
	// 7. Finalize Order
	finalizeOrder, err := step.FinalizeOrder(order.Finalize, finalizeOrderBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"FinalizeOrder失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "order": finalizeOrder})
	return
}

// 获取订单证书

type GetOrderCertificateReq struct {
	UserUuid string `json:"userUuid,omitempty" form:"userUuid" validate:"required"`
}

func (orderUseCase *OrderUseCase) GetOrderCertificate(c *gin.Context) {
	orderUuid := c.Param("uuid")
	var req GetOrderCertificateReq
	
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
	
	// 1.1. 直接返回订单证书
	if order.Certificate != "" {
		c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "order": order})
		return
	}
	
	// 2. 获取账户
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
	
	// 3. 获取 directory
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 4. 获取 nonce
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		orderUseCase.logger.Error(
			"获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 5. 获取 Signature
	getOrderContent, err := step.GetSignature(order.OrderUrl, nonce, "", account.Url, privateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Signature失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	getOrderBody := bytes.NewBuffer([]byte(getOrderContent.FullSerialize()))
	
	// 6. 获取订单
	orderResp, nonce, err := step.GetOrder(order.OrderUrl, getOrderBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"获取Order失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	if orderResp.Status != "valid" {
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	if orderResp.Certificate == "" {
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 7. 获取 Signature
	downloadCertificateContent, err := step.GetSignature(orderResp.Certificate, nonce, "", account.Url, privateKey)
	if err != nil {
		orderUseCase.logger.Error(
			"获取Signature失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	downloadCertificateBody := bytes.NewBuffer([]byte(downloadCertificateContent.FullSerialize()))
	
	// 8. 获取订单证书
	certificate, err := step.DownloadCertificate(orderResp.Certificate, downloadCertificateBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"获取证书失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 9. 更新订单证书数据库信息
	err = orderUseCase.orderRepo.UpdateOrderCertificate(c.Request.Context(), orderUuid, certificate)
	if err != nil {
		orderUseCase.logger.Error(
			"更新订单证书失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "certificate": certificate})
	return
}

// Cronjob 更新订单状态

func (orderUseCase *OrderUseCase) GetPendingStatusOrder(ctx context.Context) {
	
}
