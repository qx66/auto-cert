//go:build wireinject
// +build wireinject

package main

import (
	"github.com/google/wire"
	"github.com/qx66/auto-cert/internal/biz"
	"github.com/qx66/auto-cert/internal/conf"
	"github.com/qx66/auto-cert/internal/data"
	"github.com/qx66/auto-cert/internal/tasks"
	"go.uber.org/zap"
)

func initApp(*conf.Data, *conf.Dns, *zap.Logger) (*app, func(), error) {
	panic(wire.Build(
		data.ProviderSet,
		biz.ProviderSet,
		tasks.ProviderSet,
		newApp))
}
