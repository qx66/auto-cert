package data

import (
	"context"
	"github.com/qx66/auto-cert/internal/biz"
)

type OrderDataSource struct {
	data *Data
}

func NewOrderDataSource(data *Data) biz.OrderRepo {
	return &OrderDataSource{
		data: data,
	}
}

func (orderDataSource *OrderDataSource) CreateOrder(ctx context.Context, order biz.Order) error {
	tx := orderDataSource.data.db.WithContext(ctx).Create(&order)
	return tx.Error
}

func (orderDataSource *OrderDataSource) GetOrder(ctx context.Context, userUuid, orderUuid string) (biz.Order, error) {
	var order biz.Order
	tx := orderDataSource.data.db.WithContext(ctx).
		Where("account_uuid = ? and uuid = ?", userUuid, orderUuid).
		First(&order)
	return order, tx.Error
}

func (orderDataSource *OrderDataSource) ListOrder(ctx context.Context, userUuid string) ([]biz.Order, error) {
	var orders []biz.Order
	tx := orderDataSource.data.db.WithContext(ctx).
		Where("account_uuid = ?", userUuid).
		Find(&orders)
	return orders, tx.Error
}

func (orderDataSource *OrderDataSource) ExistOrder(ctx context.Context, orderUrl string) (bool, error) {
	var orders []biz.Order
	tx := orderDataSource.data.db.WithContext(ctx).
		Where("order_url = ?", orderUrl).
		Find(&orders)
	
	if tx.Error != nil {
		return false, tx.Error
	}
	
	if len(orders) == 0 {
		return false, nil
	}
	
	return true, nil
}

func (orderDataSource *OrderDataSource) ListOrderByStatus(ctx context.Context, status string) ([]biz.Order, error) {
	var orders []biz.Order
	tx := orderDataSource.data.db.WithContext(ctx).
		Where("status = ?", status).
		Find(&orders)
	return orders, tx.Error
}

func (orderDataSource *OrderDataSource) ListNotCertificateOrder(ctx context.Context) ([]biz.Order, error) {
	var orders []biz.Order
	tx := orderDataSource.data.db.WithContext(ctx).
		Where("status = ? and certificate = ?", "valid", "").
		Find(&orders)
	return orders, tx.Error
}

func (orderDataSource *OrderDataSource) UpdateOrderCertificate(ctx context.Context, orderUuid, certificate, notBefore, notAfter string) error {
	tx := orderDataSource.data.db.WithContext(ctx).
		Model(&biz.Order{}).
		Where("uuid = ?", orderUuid).
		Updates(map[string]interface{}{
			"certificate": certificate,
			"not_before":  notBefore,
			"not_after":   notAfter,
			"status":      "valid",
		})
	return tx.Error
}

func (orderDataSource *OrderDataSource) UpdateOrderStatus(ctx context.Context, orderUuid, status string) error {
	tx := orderDataSource.data.db.WithContext(ctx).
		Model(&biz.Order{}).
		Where("uuid = ?", orderUuid).
		Update("status", status)
	return tx.Error
}
