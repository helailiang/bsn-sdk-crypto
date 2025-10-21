package curl

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

const (
	ApplicationJSON = "application/json"
)

// 发送GET请求
// url:请求地址
// response:请求返回的内容
func Get(url string) (response string, err error) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var buffer [512]byte
	result := bytes.NewBuffer(nil)
	for {
		n, err := resp.Body.Read(buffer[0:])
		result.Write(buffer[0:n])
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
	}
	response = result.String()
	return
}

// 发送POST请求
// url:请求地址，data:POST请求提交的数据,contentType:请求体格式，如：application/json
// content:请求放回的内容
func Post(url string, data interface{}, contentType string) (content string, err error) {
	jsonStr, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	log.Printf("Post==>URL:%s", url)
	log.Printf("    ==>req data:%s", jsonStr)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}
	defer req.Body.Close()
	req.Header.Add("content-type", contentType)

	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	result, _ := ioutil.ReadAll(resp.Body)
	content = string(result)
	log.Printf("    ==>res data:%s", content)
	return
}

func Delete(url string, contentType string) error {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("content-type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
