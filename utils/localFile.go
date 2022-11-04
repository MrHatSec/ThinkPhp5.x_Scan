package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ReadFile(fileName string) (urls []string) {

	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("读取文件失败")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.Replace(scanner.Text(), " ", "", -1)
		if strings.Contains(url, "http") {
			urls = append(urls, url)
		} else {
			urls = append(urls, "https://"+url)
		}
	}
	return
}
