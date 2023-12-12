package biz

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/pkg/step"
	"github.com/startopsz/rule/pkg/ssl"
	"go.uber.org/zap"
)

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
	directory, err := step.Directory(directoryUrl)
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
	cert, err := ssl.ParseSSLCertificate([]byte(certificate))
	if err != nil {
		orderUseCase.logger.Error(
			"解析证书失败",
			zap.Error(err),
		)
		c.JSON(500, gin.H{"errCode": 500, "errMsg": "Internal Server Error"})
		return
	}
	
	err = orderUseCase.orderRepo.UpdateOrderCertificate(c.Request.Context(), orderUuid, certificate,
		cert.NotBefore.String(), cert.NotAfter.String())
	
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
