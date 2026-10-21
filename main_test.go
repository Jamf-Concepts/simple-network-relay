// Copyright (c) 2026 JAMF Software, LLC
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

const (
	testRelayPort = 8443
	testAuthToken = "secret"
	rootCAFile    = "cert/simple_network_relay_root_ca.crt"
)

type streamWrapper struct {
	*http3.RequestStream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s streamWrapper) LocalAddr() net.Addr {
	return s.localAddr
}

func (s streamWrapper) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func TestProxyData(t *testing.T) {
	var keyLogWriter bytes.Buffer
	s, err := newHTTP3Server(testRelayPort, &keyLogWriter, testAuthToken, true)
	require.NoError(t, err)

	go func() {
		err := s.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	defer func(s *http3.Server) {
		err := s.Close()
		if err != nil {
			panic(err)
		}
	}(s)

	t.Run("Proxy TCP request", func(t *testing.T) {
		targetServer, port := mockServer(t, "response from target server")
		defer targetServer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		respConnect := sendConnect(t, stream.RequestStream, fmt.Sprintf("127.0.0.1:%s", port))
		defer respConnect.Body.Close()

		respGet := sendGet(t, stream, targetServer.Certificate())
		defer respGet.Body.Close()

		body, _ := io.ReadAll(respGet.Body)
		require.Equal(t, "response from target server", string(body))
		require.Contains(t, keyLogWriter.String(), "SERVER_TRAFFIC_SECRET_0")
	})

	t.Run("Client resets stream - close server connection", func(t *testing.T) {
		serverConns, port := mockTCPServer(t)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		respConnect := sendConnect(t, stream.RequestStream, fmt.Sprintf("127.0.0.1:%s", port))
		defer respConnect.Body.Close()

		serverConn := <-serverConns
		defer serverConn.Close()

		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))

		// Server connection must be closed by the relay, not left waiting for the server
		require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(2*time.Second)))
		_, err := serverConn.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF)
	})

	t.Run("Server closes connection - close tunnel", func(t *testing.T) {
		serverConns, port := mockTCPServer(t)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		respConnect := sendConnect(t, stream.RequestStream, fmt.Sprintf("127.0.0.1:%s", port))
		defer respConnect.Body.Close()

		serverConn := <-serverConns
		require.NoError(t, serverConn.Close())

		// Client must see the end of the tunnel even though it did not close its side
		_, err := io.ReadAll(respConnect.Body)
		require.NoError(t, err)
	})

	t.Run("Invalid authority - respond with StatusServiceUnavailable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodConnect,
			Header: http.Header{"auth": []string{testAuthToken}},
			Host:   "::1",
		}

		err = stream.SendRequestHeader(req)
		require.NoError(t, err)

		resp, err := stream.ReadResponse()
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("Non-CONNECT request - respond with StatusServiceUnavailable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: "/test"},
			Header: http.Header{"auth": []string{testAuthToken}},
			Host:   "127.0.0.1:80",
		}

		err = stream.SendRequestHeader(req)
		require.NoError(t, err)

		resp, err := stream.ReadResponse()
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("Invalid auth header - respond with StatusBadGateway", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodConnect,
			Header: http.Header{"auth": []string{"wrong_secret"}},
			Host:   "127.0.0.1:80",
		}

		err = stream.SendRequestHeader(req)
		require.NoError(t, err)

		resp, err := stream.ReadResponse()
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("Dial failure - respond with StatusServiceUnavailable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodConnect,
			Header: http.Header{"auth": []string{testAuthToken}},
			Host:   "127.0.0.1:8888",
		}

		err = stream.SendRequestHeader(req)
		require.NoError(t, err)

		resp, err := stream.ReadResponse()
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("DNS lookup failure - respond with StatusServiceUnavailable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodConnect,
			Header: http.Header{"auth": []string{testAuthToken}},
			Host:   "unknown-host:80",
		}

		err = stream.SendRequestHeader(req)
		require.NoError(t, err)

		resp, err := stream.ReadResponse()
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

func TestDialTCPDeniedDestination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, authority := range []string{
		"127.0.0.1:80", "[::1]:80", "10.0.0.1:80", "169.254.169.254:80", "[::ffff:192.168.1.1]:80",
		"0.1.2.3:80", "100.64.0.1:80", "198.18.0.1:80", "240.0.0.1:80", "[64:ff9b::a00:1]:80", "[2002:a00:1::1]:80",
		"[2001::1]:80", "[fec0::1]:80",
	} {
		_, err := dialTCP(ctx, authority, false)
		require.ErrorIs(t, err, errDestinationNotAllowed, authority)
	}
}

func TestOpenKeyLog(t *testing.T) {
	dir := t.TempDir()

	t.Run("New file - create with mode 0600", func(t *testing.T) {
		path := dir + "/new"
		f, err := openKeyLog(path)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

		// Existing private file is reused
		f, err = openKeyLog(path)
		require.NoError(t, err)
		require.NoError(t, f.Close())
	})

	t.Run("File accessible by others - refuse", func(t *testing.T) {
		path := dir + "/public"
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.NoError(t, os.Chmod(path, 0o644))
		_, err := openKeyLog(path)
		require.Error(t, err)
	})

	t.Run("Symlink - refuse", func(t *testing.T) {
		path := dir + "/link"
		require.NoError(t, os.Symlink(dir+"/target", path))
		_, err := openKeyLog(path)
		require.Error(t, err)
		require.NoFileExists(t, dir+"/target")
	})
}

func dialRelay(t *testing.T, ctx context.Context) *streamWrapper {
	t.Helper()
	tlsConf := &tls.Config{
		NextProtos: []string{"h3"},
		RootCAs:    loadCACert(t, rootCAFile),
		MinVersion: tls.VersionTLS13,
	}

	qc, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", testRelayPort), tlsConf, &quic.Config{})
	require.NoError(t, err)

	tr := &http3.Transport{}
	conn := tr.NewClientConn(qc)

	select {
	case <-ctx.Done():
		t.Error(context.Cause(ctx))
	case <-conn.Context().Done():
		t.Error(context.Cause(conn.Context()))
	case <-conn.ReceivedSettings():
	}

	stream, err := conn.OpenRequestStream(ctx)
	require.NoError(t, err)

	return &streamWrapper{
		RequestStream: stream,
		localAddr:     qc.LocalAddr(),
		remoteAddr:    qc.RemoteAddr(),
	}
}

func sendConnect(t *testing.T, str *http3.RequestStream, host string) *http.Response {
	t.Helper()
	req := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{"auth": []string{testAuthToken}},
		Host:   host,
	}

	err := str.SendRequestHeader(req)
	require.NoError(t, err)

	resp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp
}

func sendGet(t *testing.T, stream *streamWrapper, serverCert *x509.Certificate) *http.Response {
	t.Helper()
	trustedCerts := x509.NewCertPool()
	trustedCerts.AddCert(serverCert)

	tlsConn := tls.Client(stream, &tls.Config{ServerName: "127.0.0.1", RootCAs: trustedCerts, MinVersion: tls.VersionTLS13})
	err := tlsConn.Handshake()
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)

	err = req.Write(tlsConn)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp
}

func loadCACert(t *testing.T, certFile string) *x509.CertPool {
	t.Helper()
	cert, err := os.ReadFile(certFile)
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(cert) {
		require.Fail(t, "append PEM certificate")
	}
	return caCertPool
}

func mockTCPServer(t *testing.T) (<-chan net.Conn, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	conns := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			conns <- c
		}
	}()

	_, port, _ := net.SplitHostPort(l.Addr().String())
	return conns, port
}

func mockServer(t *testing.T, response string) (*httptest.Server, string) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/test" {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(response)); err != nil {
				t.Fatalf("Mock server failed to write response: %v", err)
			}
		} else {
			http.Error(w, "Not Found", http.StatusNotFound)
		}
	}))

	srv.Config.SetKeepAlivesEnabled(false)
	parsedURL, _ := url.Parse(srv.URL)
	return srv, parsedURL.Port()
}
