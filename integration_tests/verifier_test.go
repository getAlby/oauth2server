package integrationtests

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestVerification(t *testing.T) {
	cc := "GB1gmG3eK_CthaJN93vKXCM47SKAnLgV0ngXSzMmPpM"
	//verifier should be hex string
	ver := "a639667f9f9c7406e499bbb9c59273b61fd06afe52cd13af73153ca7"
	s256 := sha256.Sum256([]byte(ver))
	c := hex.EncodeToString(s256[:])
	// trim padding
	a := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
	b := strings.TrimRight(cc, "=")
	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)
}
