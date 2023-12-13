# auto-cert

auto-cert 是一个基于ACME协议，参考 lego acme client 编写的异步 acme 客户端.

## 流程

   1. 使用者需要先创建ACME账户
   2. 使用者通过账户创建订单
   3. 使用者通过账号获取订单Authorizations
   4. 使用者手动/自动触发Challenge
   5. 使用者手动/自动触发Finalize
   6. 使用者手动/自动触发获取Certificate

auto-cert暂时不提供DNSProvider

## 建议

1. 在申请 www.example.com 证书时，建议调用创建订单请求时, domains 参数填写: www.example.com, example.com

2. 在申请通配符证书 *.example.com 时,建议调用创建订单请求时, domains 参数填写: *.example.com, example.com 
   原因: 默认 *.example.com 证书不包含 example.com 证书
    
## 限制

1. 所有签发请求均受每周 5 个重复证书的限制。 
   (too many certificates (5) already issued for this exact set of domains in the)

    ```
    撤销先前发布的证书将不会重置重复证书限制。 
   
   然而，仍然存在着这种情况。 如果您发现您已经超过了上限并且您仍然需要另一个证书来获取相同的主机名，您总是可以要求一个不同的主机名“确切集”的证书。 
   
   例如，如果您超出了 [example.com] 的重复证书限制，那么为 [example.com, login.example.com] 请求证书将会成功。 
   
   同样，如果您超出了 [example.com, login.example.com]的重复证书限制，那么为 [example.com] 申请一个单独的证书，为 [login.example.com] 申请另一个证书将会成功。
   ```

2. 所有颁发请求都受到每个帐户、每个主机名、每小时 5 次失败的验证失败限制。
   (当您超过失败验证限制时，您会从您的ACME客户端收到以下错误消息 too many failed authorizations recently)

## API参考

[PostmanExportJson](docs%2Fauto-cert.postman_collection.json)

## Status

CreateOrder -> status: pending

ChallengeOrder -> status: ready

FinalizeOrder -> valid (需要 Ready 状态才能执行 Finalize)


    pending --------------+
       |                  |
       | All authz        |
       | "valid"          |
       V                  |
      ready ---------------+
       |                  |
       | Receive          |
       | finalize         |
       | request          |
       V                  |
      processing ------------+
      |                  |
      | Certificate      | Error or
      | issued           | Authorization failure
      V                  V
      valid             invalid

## Usage

listen: "0.0.0.0:18080"

启动程序

```shell
./bin/auto-cert-mac -configPath=configs/config.yaml
```

## 定时任务

每隔3分钟运行定时检查任务

## refer

[ACME_RFC](https://datatracker.ietf.org/doc/html/rfc8555)
[lego](https://github.com/go-acme/lego)
