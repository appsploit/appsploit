package env

import (
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
	"github.com/ctrsploit/sploit-spec/pkg/result/item"
	"time"
)

func OS() (result printer.Interface) {
	result = item.Short{
		Name:        "os",
		Description: "OS info",
		Result:      fmt.Sprintf("%d", time.Now().Minute()),
	}
	return result
}

func Component() (result printer.Interface) {
	result = item.Short{
		Name:        "component",
		Description: "component list",
		Result:      fmt.Sprintf("%d", time.Now().Minute()),
	}
	return result
}
