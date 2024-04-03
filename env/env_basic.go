package env

import (
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/ctrsploit/sploit-spec/pkg/result/item"
	"time"
)

func WebServer() (result printer.Interface) {
	result = item.Short{
		Name:        "webserver",
		Description: "webserver info",
		Result:      fmt.Sprintf("%d", time.Now().Minute()),
	}
	return result
}

func Framework() (result printer.Interface) {
	result = item.Short{
		Name:        "framework",
		Description: "framework info",
		Result:      fmt.Sprintf("%d", time.Now().Second()),
	}
	return result
}
