package biz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/pkg/step"
	"go.uber.org/zap"
	"time"
)

type AccountRepo interface {
	CreateAccount(ctx context.Context, account Account) error
	GetAccount(ctx context.Context, uuid string) (Account, error)
	DelAccount(ctx context.Context, uuid string) error
	ExistAccount(ctx context.Context, uuid string) (bool, error)
}

type Account struct {
	Uuid                 string `json:"uuid,omitempty"`
	Contact              string `json:"contact"`
	TermsOfServiceAgreed bool   `json:"termsOfServiceAgreed"`
	PrivateKey           string `json:"privateKey"`
	Status               string `json:"status"`
	Url                  string `json:"url"`
	CreateTime           int64  `json:"createTime"`
}

func (account *Account) TableName() string {
	return "Account"
}

type AccountUseCase struct {
	accountRepo AccountRepo
	logger      *zap.Logger
}

func NewAccountUseCase(accountRepo AccountRepo, logger *zap.Logger) *AccountUseCase {
	return &AccountUseCase{
		accountRepo: accountRepo,
		logger:      logger,
	}
}

type CreateAccountReq struct {
	UserUuid string   `json:"userUuid,omitempty" validate:"required"`
	Contact  []string `json:"contact" validate:"required"`
}

// 创建用户

func (accountUseCase *AccountUseCase) CreateAccount(c *gin.Context) {
	//
	req := CreateAccountReq{}
	err := common.JsonUnmarshal(c, &req)
	if err != nil {
		return
	}
	
	// 1. 查看用户是否存在
	e, err := accountUseCase.accountRepo.ExistAccount(c.Request.Context(), req.UserUuid)
	if err != nil {
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	if e {
		c.JSON(200, gin.H{"errCode": 0, "errMsg": "该用户已存在"})
		return
	}
	
	// 2. 获取 Directory
	directory, err := step.Directory(step.LetEncryptDirectoryProdUrl)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，访问Directory失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 3. 获取 Nonce
	nonce, err := step.GetNonce(directory.NewNonce)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，获取 ACME Nonce失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 4. 生成 Payload
	var contact []string
	for _, c := range req.Contact {
		contact = append(contact, fmt.Sprintf("mailto:%s", c))
	}
	
	payload, err := step.GenerateAccountPayload(contact, true, false)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，生成 Payload 失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 5. 生成用户rsa私钥
	privateKey, err := generateRsaPrivateKey()
	if err != nil {
		accountUseCase.logger.Error(
			"生成RSA PrivateKey失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	buf, err := marshalPKCS1PrivateKey(privateKey)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，序列化RSA PrivateKey失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 6. 生成请求Signature
	newAccountReqContent, err := step.GetSignature(directory.NewAccount, nonce, payload, "", privateKey)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，生成 Signature 失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	newAccountReqBody := bytes.NewBuffer([]byte(newAccountReqContent.FullSerialize()))
	
	// 7. 新建账户请求
	newAccountResp, location, _, err := step.NewAccount(directory.NewAccount, newAccountReqBody.Bytes())
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，新建用户失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	contactByte, err := json.Marshal(newAccountResp.Contact)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，序列化Contact失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	// 8. 更新数据库记录
	account := Account{
		Uuid:                 req.UserUuid,
		Contact:              string(contactByte),
		TermsOfServiceAgreed: true,
		PrivateKey:           buf.String(),
		Status:               newAccountResp.Status,
		Url:                  location,
		CreateTime:           time.Now().Unix(),
	}
	
	err = accountUseCase.accountRepo.CreateAccount(c.Request.Context(), account)
	if err != nil {
		accountUseCase.logger.Error(
			"创建用户，添加用户到数据库失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok"})
	return
	
}

// 获取用户

func (accountUseCase *AccountUseCase) GetAccount(c *gin.Context) {
	userUuid := c.Param("uuid")
	
	account, err := accountUseCase.accountRepo.GetAccount(c.Request.Context(), userUuid)
	if err != nil {
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok", "account": account})
	return
}

// 删除用户

func (accountUseCase *AccountUseCase) DelAccount(c *gin.Context) {
	userUuid := c.Param("uuid")
	
	// 调用 acme 协议删除用户
	
	err := accountUseCase.accountRepo.DelAccount(c.Request.Context(), userUuid)
	if err != nil {
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	c.JSON(200, gin.H{"errCode": 0, "errMsg": "ok"})
	return
}

// 生成 rsa 私钥
func generateRsaPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// 序列化 rsa 私钥
func marshalPKCS1PrivateKey(key *rsa.PrivateKey) (bytes.Buffer, error) {
	var buf bytes.Buffer
	
	privateKeyDer := x509.MarshalPKCS1PrivateKey(key)
	privateKeyBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	err := pem.Encode(&buf, privateKeyBlock)
	if err != nil {
		return buf, err
	}
	
	return buf, nil
}

// 解析 rsa 私钥

func parsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(der)
	
	if b == nil {
		return nil, errors.New("block is nil")
	}
	
	return x509.ParsePKCS1PrivateKey(b.Bytes)
}
