package cli

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientProxyRouting(t *testing.T) {
	// Go caches proxy environment variables on first use. Each case needs a
	// fresh process so other HTTP tests cannot determine its routing.
	mode := os.Getenv("DEADAIR_PROXY_TEST_CASE")
	if mode == "" {
		for _, mode := range []string{"http", "https", "http-bypass", "https-bypass", "http-lowercase", "https-lowercase"} {
			t.Run(mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHTTPClientProxyRouting$")
				for _, entry := range os.Environ() {
					name, _, _ := strings.Cut(entry, "=")
					switch strings.ToUpper(name) {
					case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "REQUEST_METHOD", "DEADAIR_PROXY_TEST_CASE":
						continue
					}
					cmd.Env = append(cmd.Env, entry)
				}
				cmd.Env = append(cmd.Env, "DEADAIR_PROXY_TEST_CASE="+mode)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("proxy test: %v\n%s", err, output)
				}
			})
		}
		return
	}

	secure := strings.HasPrefix(mode, "https")
	bypass := strings.HasSuffix(mode, "-bypass")
	var backendRequests, proxyRequests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendRequests.Add(1)
		if r.URL.Path != "/metadata" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected backend request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, "backend response")
	})
	var upstream *httptest.Server
	if secure {
		upstream = httptest.NewTLSServer(handler)
	} else {
		upstream = httptest.NewServer(handler)
	}
	defer upstream.Close()
	scheme := "http"
	if secure {
		scheme = "https"
	}
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	target := "siem.example.com:" + port
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests.Add(1)
		if bypass {
			t.Error("NO_PROXY request reached the proxy")
		}
		if r.Host != target {
			t.Errorf("proxy target=%q, want %q", r.Host, target)
		}
		if secure {
			if r.Method != http.MethodConnect {
				t.Errorf("HTTPS proxy method=%s, want CONNECT", r.Method)
				http.Error(w, "expected CONNECT", http.StatusBadRequest)
				return
			}
			forwardTestTunnel(t, w, upstream.Listener.Addr().String())
			return
		}
		if !r.URL.IsAbs() {
			t.Error("HTTP proxy request did not contain an absolute URL")
		}
		handler.ServeHTTP(w, r)
	}))
	defer proxy.Close()
	variable := strings.ToUpper(scheme) + "_PROXY"
	if strings.HasSuffix(mode, "-lowercase") {
		variable = strings.ToLower(variable)
	}
	t.Setenv(variable, proxy.URL)
	if bypass {
		t.Setenv("NO_PROXY", "siem.example.com")
	}

	opts := connOpts{timeout: 3 * time.Second}
	if secure {
		opts.caCert = filepath.Join(t.TempDir(), "ca.pem")
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
		if err := os.WriteFile(opts.caCert, cert, 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := opts.httpClient(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Fatal("transport has no proxy selector")
	}
	// Resolve the test hostname locally and reject every other destination.
	// Proxy selection itself is left untouched.
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case target:
			if !bypass {
				return nil, fmt.Errorf("request bypassed the configured proxy")
			}
			address = upstream.Listener.Addr().String()
		case proxy.Listener.Addr().String():
		default:
			return nil, fmt.Errorf("unexpected test destination %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	request, err := http.NewRequest(http.MethodGet, scheme+"://"+target+"/metadata", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "backend response" {
		t.Fatalf("response status=%d body=%q error=%v", response.StatusCode, body, err)
	}
	wantProxy := int32(1)
	if bypass {
		wantProxy = 0
	}
	if proxyRequests.Load() != wantProxy || backendRequests.Load() != 1 {
		t.Fatalf("proxy/backend requests=%d/%d, want %d/1", proxyRequests.Load(), backendRequests.Load(), wantProxy)
	}
	if secure && (transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == nil) {
		t.Fatal("custom CA request disabled TLS verification")
	}
}

func forwardTestTunnel(t *testing.T, w http.ResponseWriter, address string) {
	t.Helper()
	upstream, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Error(err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	client, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	defer client.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		t.Error(err)
		return
	}
	if err := buffer.Flush(); err != nil {
		t.Error(err)
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, buffer)
		_ = upstream.Close()
		close(done)
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-done
}
