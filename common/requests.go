package common

import (
	"ThinkPHPExploit/common/requests"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// 捕获异常
func errorE(url string) {
	err := recover()
	if err != nil {
		log.Printf("[-] %v 扫描异常,请检查!", url)
	}
}

func randomUA() string {
	ua := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36 Edg/89.0.774.57",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1.70.3861.400 QQBrowser/10.7.4313.400",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.87 Safari/537.36 SE 2.X MetaSr 1.0",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36 QBCore/4.0.1320.400 QQBrowser/9.0.2524.400 Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2875.116 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63010200)",
	}
	n := rand.Intn(7)
	return ua[n]
}

func GetReq(url string) string {
	defer errorE(url)
	transport := requests.DefaultTransport()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(5 * time.Second),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, _ := http.NewRequest("GET", url, nil)
	request.Header = http.Header{
		"User-Agent":   {randomUA()},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}
	resp, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body)

}

func PostReq(url string, body string) string {
	defer errorE(url)
	transport := requests.DefaultTransport()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(5 * time.Second),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, _ := http.NewRequest("POST", url, strings.NewReader(body))
	request.Header = http.Header{
		"User-Agent":   {randomUA()},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}
	resp, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	content, _ := ioutil.ReadAll(resp.Body)

	return string(content)

}

// Get - 自定义header头
func ZGetReq(url string, headers map[string]string) string {
	defer errorE(url)
	transport := requests.DefaultTransport()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(5 * time.Second),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, _ := http.NewRequest("GET", url, nil)
	request.Header = http.Header{
		"User-Agent": {randomUA()},
	}

	if headers != nil {
		for header, content := range headers {
			request.Header.Add(header, content)
		}
	}

	resp, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	return string(body)

}

// Post - 自定义header头
func ZPostReq(url string, body string, headers map[string]string) string {
	defer errorE(url)
	transport := requests.DefaultTransport()
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(15 * time.Second),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, _ := http.NewRequest("POST", url, strings.NewReader(body))
	request.Header = http.Header{
		"User-Agent":   {randomUA()},
		"Content-Type": {"application/x-www-form-urlencoded"},
	}
	if headers != nil {
		for header, content := range headers {
			request.Header.Add(header, content)
		}
	}
	resp, err := client.Do(request)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	content, _ := ioutil.ReadAll(resp.Body)

	return string(content)

}
