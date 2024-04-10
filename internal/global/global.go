package global

import (
	"os"
	"path/filepath"
)

var (
	ExePath, _     = os.Executable()
	ProjectDir     = filepath.Dir(ExePath)
	HttpUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
	HttpProxy      = ""
	HttpTimeout    = 15
	HttpCertVerify = false
)
