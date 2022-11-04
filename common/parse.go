package common

import (
	"flag"
	"os"
)

func Parse(cmdOptions *CmdOptions) {
	if cmdOptions.Url == "http://127.0.0.1" && cmdOptions.FileName == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}
}
