package data

import (
	"github.com/qx66/auto-cert/internal/conf"
	"go.uber.org/zap"
	
	"github.com/google/wire"
	"gorm.io/driver/mysql"
	"gorm.io/plugin/opentelemetry/tracing"
	
	"gorm.io/gorm"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewAccountDataSource, NewOrderDataSource)

// Data .
type Data struct {
	db *gorm.DB
}

// NewData .
func NewData(c *conf.Data, logger *zap.Logger) (*Data, func(), error) {
	
	db, err := gorm.Open(mysql.Open(c.Database.Source), &gorm.Config{})
	if err != nil {
		logger.Error(
			"连接MySQL数据失败",
			zap.Error(err),
		)
		panic(err)
		//return nil, nil, err
	}
	
	if err := db.Use(tracing.NewPlugin()); err != nil {
		logger.Error(
			"使用MySQL trace插件失败",
			zap.Error(err),
		)
		panic(err)
	}
	
	sqlDB, err := db.DB()
	if err != nil {
		logger.Error(
			"返回数据库连接信息失败",
			zap.Error(err),
		)
		return nil, nil, err
	}
	
	err = sqlDB.Ping()
	if err != nil {
		
		logger.Error(
			"测试数据库数据源失败",
			zap.Error(err),
		)
		return nil, nil, err
	}
	
	sqlDB.SetMaxIdleConns(int(c.Database.MaxIdleConns))
	sqlDB.SetMaxOpenConns(int(c.Database.MaxOpenConns))
	
	d := &Data{
		db: db.Debug(),
	}
	
	cleanup := func() {
		err = sqlDB.Close()
		if err != nil {
			logger.Error(
				"关闭MySQL数据源失败",
				zap.Error(err),
			)
		} else {
			logger.Info(
				"关闭MySQL数据源",
			)
		}
		
	}
	
	return d, cleanup, nil
}
