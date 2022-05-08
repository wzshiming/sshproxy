package sshproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("ok"))
}))

func TestBind(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")

	s.Start(context.Background())
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	listener, err := dial.Listen(context.Background(), "tcp", ":10000")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, nil)
	time.Sleep(time.Second / 10)
	resp, err := http.Get("http://127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestServer(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")

	s.Start(context.Background())
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	cli := testServer.Client()
	cli.Transport = &http.Transport{
		DialContext: dial.DialContext,
	}

	resp, err := cli.Get(testServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
