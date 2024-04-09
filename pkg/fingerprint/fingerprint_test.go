package fingerprint

import (
	"appsploit/pkg/fingerprint/framework"
	"testing"
)

func TestFramework(t *testing.T) {
	for _, fingerprint := range framework.List {
		t.Log(fingerprint)
	}
}
