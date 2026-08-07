package sshproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/wzshiming/sshd/directstreamlocal"
	_ "github.com/wzshiming/sshd/directtcp"
	_ "github.com/wzshiming/sshd/streamlocalforward"
	_ "github.com/wzshiming/sshd/tcpforward"

	"golang.org/x/crypto/ssh"
)

var testServer = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("ok"))
}))

func TestBind(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL())
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	listener, err := dial.Listen(context.Background(), "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go http.Serve(listener, nil)

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var resp *http.Response
	for i := 0; ; i++ {
		resp, err = http.Get("http://127.0.0.1:" + port)
		if err == nil {
			break
		}
		if i >= 50 {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	resp.Body.Close()
}

func TestServer(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
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

func TestDialerConnections(t *testing.T) {
	s, err := NewSimpleServer("ssh://u:p@:0")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL() + "?connections=2")
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	cli1, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	cli2, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cli1 == cli2 {
		t.Fatal("expected different ssh clients when pool is filling")
	}

	cli3, err := dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if cli3 != cli1 && cli3 != cli2 {
		t.Fatal("expected ssh client to be reused from pool")
	}
}

func genHostKey(t *testing.T) (privData, pubData string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privData = base64.URLEncoding.EncodeToString(pem.EncodeToMemory(pemBlock))
	pubData = base64.URLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(sshPub))
	return privData, pubData
}

func TestHostKeyVerify(t *testing.T) {
	privData, pubData := genHostKey(t)

	s, err := NewSimpleServer("ssh://u:p@:0?hostkey_data=" + privData)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dial, err := NewDialer(s.ProxyURL() + "?hostkey_data=" + pubData)
	if err != nil {
		t.Fatal(err)
	}
	defer dial.Close()

	_, err = dial.SSHClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	_, otherPubData := genHostKey(t)
	badDial, err := NewDialer(s.ProxyURL() + "?hostkey_data=" + otherPubData)
	if err != nil {
		t.Fatal(err)
	}
	defer badDial.Close()

	_, err = badDial.SSHClient(context.Background())
	if err == nil {
		t.Fatal("expected host key mismatch error")
	}
}
