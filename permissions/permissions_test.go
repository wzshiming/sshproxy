package permissions

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMatch(t *testing.T) {
	for _, test := range []struct {
		pattern string
		args    string
		want    bool
	}{
		// Exact entries keep working, whatever characters they hold.
		{"example.com:443", "example.com:443", true},
		{"example.com:443", "example.com:80", false},
		{"example.com:443", "other.com:443", false},
		{"shell", "shell", true},
		{"", "", true},
		{"/run/[app].sock", "/run/[app].sock", true},

		// Patterns over the whole argument.
		{"*", "example.com:443", true},
		{"*", "", true},
		{"*.example.com:443", "api.example.com:443", true},
		{"*.example.com:443", "example.com:443", false},
		{"*.example.com:443", "api.example.com:80", false},
		{"*.example.com:443", "api.example.org:443", false},
		{"/run/*.sock", "/run/app.sock", true},
		{"/run/*.sock", "/run/nested/app.sock", false},
		{"/run/*.sock", "/etc/app.sock", false},
		{"db-?:5432", "db-1:5432", true},
		{"db-?:5432", "db-10:5432", false},
		{"[", "[", true},
		{"[", "x", false},

		// Ports.
		{"example.com:*", "example.com:22", true},
		{"example.com:*", "other.com:22", false},
		{"example.com:8000-8999", "example.com:8000", true},
		{"example.com:8000-8999", "example.com:8999", true},
		{"example.com:8000-8999", "example.com:7999", false},
		{"example.com:8000-8999", "example.com:9000", false},
		{"example.com:8000-8999", "example.com:http", false},
		{"example.com:8999-8000", "example.com:8500", false},
		{"example.com:-80", "example.com:80", false},
		{"*.example.com:8000-8999", "api.example.com:8080", true},

		// CIDR prefixes.
		{"10.0.0.0/8:*", "10.1.2.3:22", true},
		{"10.0.0.0/8:*", "11.1.2.3:22", false},
		{"10.0.0.0/8:*", "example.com:22", false},
		{"10.0.0.0/8:443", "10.1.2.3:443", true},
		{"10.0.0.0/8:443", "10.1.2.3:80", false},
		{"192.168.1.0/24:1-1024", "192.168.1.9:22", true},
		{"192.168.1.0/24:1-1024", "192.168.2.9:22", false},
		{"0.0.0.0/0:*", "8.8.8.8:53", true},
		{"0.0.0.0/0:*", "::1:53", false},
		{"10.0.0.0/8:*", "::ffff:10.1.2.3:22", true},
		{"10.0.0.0/33:*", "10.1.2.3:22", false},

		// IPv6, which forwarding requests carry without brackets.
		{"[::1]:80", "::1:80", true},
		{"::1:80", "::1:80", true},
		{"[::1]:80", "[::1]:80", true},
		{"[::1]:80", "::2:80", false},
		{"[fd00::/8]:443", "fd12::1:443", true},
		{"[fd00::/8]:443", "fe80::1:443", false},
		{"[fd00::/8]:*", "[fd12::1]:8080", true},
		{"[::/0]:*", "10.1.2.3:22", false},

		// Arguments that are no address only match as a whole.
		{"10.0.0.0/8:*", "shell", false},
		{"example.com:*", "", false},
	} {
		if got := match(test.pattern, test.args); got != test.want {
			t.Errorf("match(%q, %q) = %v, want %v", test.pattern, test.args, got, test.want)
		}
	}
}

func TestPermissionAllow(t *testing.T) {
	for _, test := range []struct {
		name       string
		permission Permission
		args       string
		want       bool
	}{
		{"default deny", Permission{}, "example.com:443", false},
		{"default allow", Permission{Default: true}, "example.com:443", true},
		{"allows matching pattern", Permission{Allows: []string{"10.0.0.0/8:*", "*.example.com:443"}}, "api.example.com:443", true},
		{"allows nothing else", Permission{Default: true, Allows: []string{"10.0.0.0/8:*"}}, "example.com:443", false},
		{"empty allows deny all", Permission{Default: true, Allows: []string{}}, "example.com:443", false},
		{"blocks matching pattern", Permission{Blocks: []string{"127.0.0.0/8:*", "[::1]:*"}}, "127.0.0.1:6379", false},
		{"blocks matching IPv6", Permission{Blocks: []string{"127.0.0.0/8:*", "[::1]:*"}}, "::1:6379", false},
		{"blocks nothing else", Permission{Blocks: []string{"127.0.0.0/8:*"}}, "example.com:443", true},
		{"allows win over blocks", Permission{Allows: []string{"*:443"}, Blocks: []string{"*:443"}}, "example.com:443", true},
	} {
		if got := test.permission.Allow("direct-tcpip", test.args); got != test.want {
			t.Errorf("%s: Allow(%q) = %v, want %v", test.name, test.args, got, test.want)
		}
	}
}

func TestPermissionsAllowUnknownRequest(t *testing.T) {
	permissions := Permissions{"direct-tcpip": {Default: true}}
	if !permissions.Allow("direct-tcpip", "example.com:443") {
		t.Error("configured request was denied")
	}
	if permissions.Allow("tcpip-forward", "0.0.0.0:80") {
		t.Error("request without a permission was allowed")
	}
}

func TestPermissionsFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "permissions.json")
	permissions := NewPermissionsFromFile(file, time.Second)
	if permissions.Allow("direct-tcpip", "10.1.2.3:22") {
		t.Fatal("allowed without a permissions file")
	}
	if err := os.WriteFile(file, []byte(`{"direct-tcpip":{"allows":["10.0.0.0/8:*"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !permissions.Allow("direct-tcpip", "10.1.2.3:22") {
		t.Fatal("denied an address the file allows")
	}
	if permissions.Allow("direct-tcpip", "11.1.2.3:22") {
		t.Fatal("allowed an address the file does not allow")
	}

	// The file is read again once the period has passed.
	if err := os.WriteFile(file, []byte(`{"direct-tcpip":{"allows":["11.0.0.0/8:*"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !permissions.Allow("direct-tcpip", "10.1.2.3:22") {
		t.Fatal("file was read again within the period")
	}
	time.Sleep(1100 * time.Millisecond)
	if permissions.Allow("direct-tcpip", "10.1.2.3:22") || !permissions.Allow("direct-tcpip", "11.1.2.3:22") {
		t.Fatal("file was not read again after the period")
	}

	if err := os.WriteFile(file, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if permissions.Allow("direct-tcpip", "11.1.2.3:22") {
		t.Fatal("allowed with an unparsable permissions file")
	}
}

func TestPermissionsFromFileConcurrent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(file, []byte(`{"direct-tcpip":{"default":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	permissions := NewPermissionsFromFile(file, time.Second)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if !permissions.Allow("direct-tcpip", "example.com:443") {
					t.Error("denied a request the file allows")
					return
				}
			}
		}()
	}
	wg.Wait()
}
