package main

import (
	"ThinkPHPExploit/common"
	"ThinkPHPExploit/vulScan"
)

func main() {
	var cmdOptions common.CmdOptions
	common.Flag(&cmdOptions)
	common.Parse(&cmdOptions)
	vulScan.StartScan(cmdOptions)
}
