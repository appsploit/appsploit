package env

import (
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/printer"
)

type Result map[string]printer.Interface

func Auto() {
	result := Result{
		"WebServer": WebServer(),
		"Framework": Framework(),
		"OS":        OS(),
		"Component": Component(),
	}
	fmt.Println(printer.Printer.Print(result))
}
