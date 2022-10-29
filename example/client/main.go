package main

import (
	"fmt"
	"strings"

	"github.com/go-zoox/socks5"
)

func main() {
	client := socks5.Client{
		Host: "127.0.0.1",
		Port: 1080,
	}

	request := strings.Join([]string{
		"GET /ip HTTP/1.1",
		"Host: httpbin.org",
		"Accept: */*",
		"Connection: close",
		"\n",
	}, "\n")

	// conn, _ := net.Dial("tcp", "127.0.0.1:1080")
	// conn.Write(bytes)

	fmt.Println("request:")
	fmt.Println(request)

	response, err := client.Connect("34.203.186.29", 80, []byte(request))

	if err != nil {
		panic(err)
	}

	fmt.Println("response:")
	fmt.Println(string(response))
}

// GET / HTTP/1.1
// Host: 127.0.0.1:1080
// User-Agent: curl/7.84.0
// Accept: */*

// 2022/10/29 16:37:45 ERROR auth error: reading header: EOF
// GET / HTTP/1.1
// Host: httpbin.zcorky.com
// Accept: */*
