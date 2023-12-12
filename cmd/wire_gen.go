// Code generated by Wire. DO NOT EDIT.

//go:generate go run github.com/google/wire/cmd/wire
//go:build !wireinject
// +build !wireinject

package main

import (
	"github.com/qx66/auto-cert/internal/biz"
	"github.com/qx66/auto-cert/internal/conf"
	"github.com/qx66/auto-cert/internal/data"
	"github.com/qx66/auto-cert/internal/tasks"
	"go.uber.org/zap"
)

// Injectors from wire.go:

func initApp(confData *conf.Data, dns *conf.Dns, logger *zap.Logger) (*app, func(), error) {
	dataData, cleanup, err := data.NewData(confData, logger)
	if err != nil {
		return nil, nil, err
	}
	accountRepo := data.NewAccountDataSource(dataData)
	accountUseCase := biz.NewAccountUseCase(accountRepo, logger)
	orderRepo := data.NewOrderDataSource(dataData)
	orderUseCase := biz.NewOrderUseCase(orderRepo, accountRepo, dns, logger)
	task := tasks.NewTask(orderUseCase, logger)
	mainApp := newApp(accountUseCase, orderUseCase, task)
	return mainApp, func() {
		cleanup()
	}, nil
}