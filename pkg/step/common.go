package step

const (
	//let Encrypt 正式环境 API
	LetEncryptDirectoryProdUrl = "https://acme-v02.api.letsencrypt.org/directory"
	
	//let Encrypt 测试环境 API
	//LetEncryptDirectoryProdUrl = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Identifier struct {
	Type  string `json:"type"`  // required
	Value string `json:"value"` // required
}
