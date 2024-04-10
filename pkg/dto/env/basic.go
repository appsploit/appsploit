package env

import (
	"fmt"
	"github.com/ctrsploit/sploit-spec/pkg/colorful"
)

type Basic struct {
	WebServer WebServer `json:"webserver"`
	Framework Framework `json:"framework"`
}

type WebServer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (w WebServer) Text() string {
	return fmt.Sprintf("webserver: %s, version: %s", w.Name, w.Version)
}

func (w WebServer) Colorful() string {
	output := colorful.Colorful{}
	return fmt.Sprintf("%s: %s, %s: %s",
		output.Name("webserver"),
		output.Result(w.Name),
		output.Name("version"),
		output.Result(w.Version),
	)
}

func (w WebServer) IsEmpty() bool {
	return (w.Name == "" && w.Version == "") || w.Name == "unknown"
}

type Framework struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (w Framework) Text() string {
	return fmt.Sprintf("framework: %s, version: %s", w.Name, w.Version)
}

func (w Framework) Colorful() string {
	output := colorful.Colorful{}
	return fmt.Sprintf("%s: %s, %s: %s",
		output.Name("framework"),
		output.Result(w.Name),
		output.Name("version"),
		output.Result(w.Version),
	)
}

func (w Framework) IsEmpty() bool {
	return (w.Name == "" && w.Version == "") || w.Name == "unknown"
}
