package errCode

const (
	NormalCode = 0
	NormalMsg  = "ok"
	
	RegisterUserExistsCode = 14031
	RegisterUserExistsMsg = "该用户已经存在"
	
	NotFoundCode = 14040
	NotFoundMsg  = "资源未发现"

	UserPermissionDenyCode = 14030
	UserPermissionDenyMsg  = "用户权限拒绝"

	UserUnAuthorizeCode = 14031
	UserUnAuthorizeMsg = "用户未认证"
	
	ParameterNotFoundCode = 14041
	ParameterNotFoundMsg  = "参数缺失"
	
	ParameterFormatErrCode = 14042
	ParameterFormatErrMsg  = "参数格式异常"
	
	
	
	// 注册中心连接失败
	RegisterConnectErrorCode = 15051
	RegisterConnectErrorMsg = "注册中心连接失败"
	// GRpc 调用 Endpoint 为空
	GRpcEndpointNotFoundCode = 15052
	GRpcEndpointNotFoundMsg = "Endpoint Is Null"
	
	// GRpc 调用返回 error
	GRpcCallErrorCode = 15053
	GRpcCallErrorMsg = "Endpoint return error"
	
	DatabaseOpErrorCode = 17001
	DatabaseOpErrorMsg  = "内部系统异常，请核对code。"

	BizOpErrorCode = 17002
	BizOpErrorMsg  = "业务代码异常"

	LimitRequestCode = 18001
	LimitRequestMsg  = "请求频率限制"

	CircuitBreakerCode = 18002
	CircuitBreakerMsg  = "熔断限制"
	
	
	
)
