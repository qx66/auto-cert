package step

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBase64urlDecode(t *testing.T) {
	s := "eyJjb250YWN0IjpbIm1haWx0bzpxeEBzdGFydG9wcy5jb20uY24iXSwidGVybXNPZlNlcnZpY2VBZ3JlZWQiOnRydWV9"
	b, err := base64urlDecode(s)
	assert.Nil(t, err, "s1 base64urlDecode 失败")
	fmt.Println("Payload TestBase64urlDecode: ", string(b))
}
