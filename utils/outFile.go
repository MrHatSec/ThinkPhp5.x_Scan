package utils

import (
	"fmt"
	"os"
)

func OutFile(fileName string, content string) {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Create File Error")
	}
	defer file.Close()
	file.WriteString(content + "\n")
}
