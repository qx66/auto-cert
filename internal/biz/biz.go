package biz

import (
	"github.com/google/wire"
	"github.com/qx66/auto-cert/pkg/step"
)

const (
	directoryUrl = step.LetEncryptDirectoryProdUrl
)

var ProviderSet = wire.NewSet(NewAccountUseCase, NewOrderUseCase)
