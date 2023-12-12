package biz

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz/common"
	"github.com/qx66/auto-cert/pkg/step"
	"go.uber.org/zap"
)

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
