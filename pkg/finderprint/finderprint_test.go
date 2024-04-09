package finderprint

import (
	"appsploit/pkg/finderprint/framework"
	"testing"
)

func TestFramework(t *testing.T) {
	for _, finderprint := range framework.List {
		t.Log(finderprint)
	}
}
