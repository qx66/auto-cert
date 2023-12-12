package data

import (
	"context"
	"github.com/qx66/auto-cert/internal/biz"
	"gorm.io/gorm"
)

type AccountDataSource struct {
	data *Data
}

func NewAccountDataSource(data *Data) biz.AccountRepo {
	return &AccountDataSource{
		data: data,
	}
}

func (accountDataSource *AccountDataSource) CreateAccount(ctx context.Context, account biz.Account) error {
	tx := accountDataSource.data.db.WithContext(ctx).Create(&account)
	return tx.Error
}

func (accountDataSource *AccountDataSource) GetAccount(ctx context.Context, uuid string) (biz.Account, error) {
	var account biz.Account
	tx := accountDataSource.data.db.WithContext(ctx).
		Where("uuid = ?", uuid).
		First(&account)
	return account, tx.Error
}

func (accountDataSource *AccountDataSource) ExistAccount(ctx context.Context, uuid string) (bool, error) {
	var account biz.Account
	tx := accountDataSource.data.db.WithContext(ctx).
		Where("uuid = ?", uuid).
		First(&account)
	
	if tx.Error == gorm.ErrRecordNotFound {
		return false, nil
	}
	
	return true, tx.Error
}

func (accountDataSource *AccountDataSource) DelAccount(ctx context.Context, uuid string) error {
	tx := accountDataSource.data.db.WithContext(ctx).
		Where("uuid = ?", uuid).
		Delete(&biz.Account{})
	return tx.Error
}
