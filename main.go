package goweb_ssrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
)

func main() {
	checkList := []string{
		"http://0266.075.0310.07/",
		"http://www.192.168.3.6.xip.io",
		"http://www.baidu.com@192.168.1.3",
		"http://0xc0.0xa8.774",
		"http://182.4048903",
	}
	for _, reqURL := range checkList {
		uri, err := url.Parse(reqURL)
		if err != nil {
			fmt.Println(err)
			continue
		}
		ips, err := net.LookupIP(uri.Hostname())
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, ip := range ips {
			fmt.Printf("%s -> %s is localip?: %v\n", uri.Hostname(), ip.String(), IsLocalIP(ip))
		}
	}
	// 自定义CheckRedirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 跳转超过10次，也拒绝继续跳转
			if len(via) >= 10 {
				return fmt.Errorf("redirect too much")
			}
			statusCode := req.Response.StatusCode
			if statusCode == 307 || statusCode == 308 {
				// 拒绝跳转访问
				return fmt.Errorf("unsupport redirect method")
			}
			// 判断ip
			ips, err := net.LookupIP(req.URL.Host)
			if err != nil {
				return err
			}
			for _, ip := range ips {
				if IsLocalIP(ip) {
					return fmt.Errorf("have local ip")
				}
				fmt.Printf("%s -> %s is localip?: %v\n", req.URL, ip.String(), IsLocalIP(ip))
			}
			return nil
		},
	}
	// 以taobao域名为例发出请求
	readAndClose(client.Get("http://taobao.com"))
	// 方案一：修改transport的DialContext
	// copy from http.
	dialer := &net.Dialer{}
	// copy from http.DefaultTransport
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		// 解析host和 端口
		if err != nil {
			return nil, err
		}
		// dns解析域名
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		// 对所有的ip进行串行发起请求
		for _, ip := range ips {
			fmt.Printf("%v -> %v is localip?: %v\n", addr, ip.String(), IsLocalIP(ip))
			if IsLocalIP(ip) {
				continue
			}
			// 拼接地址
			addr := net.JoinHostPort(ip.String(), port)
			con, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				return con, nil
			}
			fmt.Println(err)
		}

		return nil, fmt.Errorf("connect failed")
	}
	client1 := &http.Client{
		Transport: transport,
	}
	readAndClose(client1.Get("http://taobao.com"))
	// 方案二， 修改transport的Control
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		fmt.Printf("%v is localip?: %v\n", address, IsLocalIP(net.ParseIP(host)))
		return nil
	}
	// clone 一次避免链接复用
	transport = transport.Clone()
	transport.DialContext = dialer.DialContext
	client2 := &http.Client{
		Transport: transport,
	}
	readAndClose(client2.Get("http://taobao.com"))
}
