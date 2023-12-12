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
	ListOrderByStatus(ctx context.Context, status string) ([]Order, error)
	
	ListNotCertificateOrder(ctx context.Context) ([]Order, error)
	
	ExistOrder(ctx context.Context, orderUrl string) (bool, error)
	UpdateOrderCertificate(ctx context.Context, orderUuid, certificate, notBefore, notAfter string) error
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
	directory, err := step.Directory(directoryUrl)
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
	
	// 4. Payload
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
	
	// 5. GetSignature
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
	
	fmt.Println("orderPayload: ", orderPayload)
	// 6. NewOrder
	orderResponse, orderUrl, _, err := step.NewOrder(directory.NewOrder, orderSignedBody.Bytes())
	if err != nil {
		orderUseCase.logger.Error(
			"创建订单失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 7. 查看订单是否存在
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
	
	var domains []string
	for _, identifier := range identifiers {
		domains = append(domains, identifier.Value)
	}
	
	// 8. 生成订单rsa私钥
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
	
	// 8.1. 生成CSR
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
	
	// 9. 记录数据库
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
	if order.Certificate != "" {
		c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "order": order})
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
	directory, err := step.Directory(directoryUrl)
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
