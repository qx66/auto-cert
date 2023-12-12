create database autocert default charset = "utf8mb4";
create user autocert IDENTIFIED BY 'KxJ82S0ja0Xjk';
grant all on autocert.* to 'autocert'@'%';
flush privileges;


drop table if exists `account`;
create table if not exists `account`
(
    uuid                    varchar(50) primary key,
    contact                 JSON comment '邮箱',
    terms_of_service_agreed bool,
    private_key             text,
    status                  varchar(20) comment '状态: valid,deactivated,revoked',
    url                     text,
    create_time             bigint
) comment '用户key';


drop table if exists `order`;
create table if not exists `order`
(
    uuid           varchar(50) primary key comment '订单uuid',
    account_uuid   varchar(50) comment '账户uuid',
    order_url      text comment '订单url, location',
    status         varchar(20) comment 'pending/ready/processing/valid/invalid',
    expires        varchar(100) comment '订单失效时间, 由服务商或CA决定',
    not_before     varchar(100),
    not_after      varchar(100),
    identifiers    JSON comment 'object',
    authorizations JSON,
    finalize       text,
    private_key    text comment '私钥',
    csr            text comment 'base64 csr',
    certificate    text comment '证书',
    create_time    bigint
) comment '订单';



