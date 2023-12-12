package common

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	userV1 "github.com/startopsz/api/user/v1"
	"github.com/startopsz/rule/pkg/response/errCode"
	"google.golang.org/grpc/metadata"
	"reflect"
)

// 统一对请求请求参数为 application/json 类型的数据进行 Unmarshal

var validate *validator.Validate

func JsonUnmarshal[r any](c *gin.Context, req r) error {
	rawDataByte, err := c.GetRawData()
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(400, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
		c.Abort()
		return err
	}
	
	err = json.Unmarshal(rawDataByte, req)
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(400, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
		c.Abort()
		return err
	}
	
	validate = validator.New()
	err = validate.Struct(req)
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(400, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
		c.Abort()
		return err
	}
	
	return nil
}

// 将 gin URI 中的参数绑定到 r any 中

func BindUriQuery[r any](c *gin.Context, req r) error {
	err := c.BindQuery(req)
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(400, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
		c.Abort()
		return err
	}
	
	validate = validator.New()
	err = validate.Struct(req)
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(400, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
		c.Abort()
		return err
	}
	return nil
}

// 处理 GRPC 响应 Error 的请求

func ResponseGrpcError(c *gin.Context, err error) {
	if err != nil {
		c.Set("error", err.Error())
		c.JSON(500, gin.H{"errCode": errCode.GRpcCallErrorCode, "errMsg": errCode.GRpcCallErrorMsg})
		c.Abort()
		return
	}
}

// 继承 gin.Context 返回 grpc Context

func GetGrpcCtx(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	md := metadata.Pairs()
	return metadata.NewOutgoingContext(ctx, md)
}

// 获取用户信息

func GetUserInfo(c *gin.Context) (*userV1.GetUserByTokenReply, error) {
	userValue, exist := c.Get("user")
	if exist {
		uu := reflect.ValueOf(userValue).Interface().(*userV1.GetUserByTokenReply)
		return uu, nil
	}
	
	c.Set("error", "获取用户信息失败，用户信息不存在")
	c.JSON(401, gin.H{"errCode": errCode.ParameterFormatErrCode, "errMsg": errCode.ParameterFormatErrMsg})
	c.Abort()
	return nil, errors.New("用户信息不存在")
}
