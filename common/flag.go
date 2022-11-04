package common

import (
	"flag"
	"fmt"
)

const banner = `
████████╗██████╗ ███████╗   ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
╚══██╔══╝██╔══██╗██╔════╝   ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
   ██║   ██████╔╝███████╗    ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║
   ██║   ██╔═══╝ ╚════██║    ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
   ██║   ██║     ███████║██╗██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═╝   ╚═╝     ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                    Author:MrHatSec
`

func printBanner() {
	fmt.Println(banner)
	fmt.Println("thinkphp5.x所有版本的漏洞检测、利用、写shell\n如遇到exp或写shell失败,请手工尝试!\n")
	fmt.Println("\t开发人员不承担任何责任,也不对任何滥用或者损坏负责")
	fmt.Println("")
}

func Flag(info *CmdOptions) {
	printBanner()
	flag.StringVar(&info.Url, "u", "http://127.0.0.1", "Url")
	flag.StringVar(&info.FileName, "f", "", "FileName")
	flag.IntVar(&info.Thread, "t", 10, "线程,默认10")

	flag.Parse()
}
