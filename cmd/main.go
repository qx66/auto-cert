package main

import (
	"bytes"
	"context"
	"flag"
	"github.com/gin-gonic/gin"
	"github.com/qx66/auto-cert/internal/biz"
	"github.com/qx66/auto-cert/internal/conf"
	"github.com/qx66/auto-cert/internal/tasks"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

const (
	directUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type app struct {
	accountUseCase *biz.AccountUseCase
	orderUseCase   *biz.OrderUseCase
	task           *tasks.Task
}

func newApp(accountUseCase *biz.AccountUseCase, orderUseCase *biz.OrderUseCase, task *tasks.Task) *app {
	return &app{
		accountUseCase: accountUseCase,
		orderUseCase:   orderUseCase,
		task:           task,
	}
}

var configPath string

func init() {
	flag.StringVar(&configPath, "configPath", "", "-configPath")
}

func main() {
	flag.Parse()
	
	//
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()
	
	//
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	//
	if configPath == "" {
		logger.Error("configPath 参数为空")
		return
	}
	
	//
	f, err := os.Open(configPath)
	defer f.Close()
	if err != nil {
		logger.Error(
			"加载配置文件失败",
			zap.String("configPath", configPath),
			zap.Error(err),
		)
		return
	}
	
	//
	var buf bytes.Buffer
	_, err = io.Copy(&buf, f)
	if err != nil {
		logger.Error(
			"加载配置文件copy内容失败",
			zap.Error(err),
		)
		return
	}
	
	//
	var bootstrap conf.Bootstrap
	err = yaml.Unmarshal(buf.Bytes(), &bootstrap)
	if err != nil {
		logger.Error(
			"序列化配置失败",
			zap.Error(err),
		)
		return
	}
	
	//
	app, clean, err := initApp(bootstrap.Data, bootstrap.Dns, logger)
	defer clean()
	
	if err != nil {
		logger.Error(
			"初始化程序失败",
			zap.Error(err),
		)
		panic(err)
	}
	
	route := gin.New()
	route.POST("/account", app.accountUseCase.CreateAccount)
	route.GET("/account/:uuid", app.accountUseCase.GetAccount)
	route.DELETE("/account/:uuid", app.accountUseCase.DelAccount)
	
	route.POST("/order", app.orderUseCase.CreateOrder)
	route.GET("/order/:uuid", app.orderUseCase.GetOrder)
	route.GET("/orders", app.orderUseCase.ListOrder)
	
	route.GET("/order/:uuid/authorizations", app.orderUseCase.GetOrderAuthorizations)
	route.GET("/order/:uuid/challenge", app.orderUseCase.GetOrderAuthorizationsChallenge)
	route.GET("/order/:uuid/finalize", app.orderUseCase.FinalizeOrder)
	
	route.GET("/order/:uuid/certificate", app.orderUseCase.GetOrderCertificate)
	
	app.task.CronJob(ctx)
	
	err = route.Run(":18080")
	if err != nil {
		logger.Error(
			"启动程序失败",
			zap.Error(err),
		)
	}
}
