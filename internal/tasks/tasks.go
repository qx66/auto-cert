package tasks

import (
	"context"
	"github.com/google/wire"
	"github.com/qx66/auto-cert/internal/biz"
	"github.com/robfig/cron"
	"go.uber.org/zap"
)

type Task struct {
	orderUseCase *biz.OrderUseCase
	logger       *zap.Logger
}

var ProviderSet = wire.NewSet(NewTask)

func NewTask(orderUseCase *biz.OrderUseCase, logger *zap.Logger) *Task {
	return &Task{
		orderUseCase: orderUseCase,
		logger:       logger,
	}
}

func (task *Task) CronJob(ctx context.Context) {
	c := cron.New()
	
	err := c.AddFunc("1 * * * * *", func() {
		task.orderUseCase.GetPendingStatusOrder(ctx)
	})
	if err != nil {
		task.logger.Error(
			"添加定时任务失败",
			zap.Error(err),
		)
	}
	
	c.Start()
}
