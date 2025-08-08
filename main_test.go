// Copyright (c) 2025 JAMF Software, LLC
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
	s, err := newHTTP3Server(testRelayPort, &keyLogWriter)
	require.NoError(t, err)

	go func() {
		err = s.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	defer func(s *http3.Server) {
		err = s.Close()
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

	t.Run("Non-CONNECT request - respond with StatusServiceUnavailable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		stream := dialRelay(t, ctx)
		defer stream.Close()

		req := &http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Path: "/test"},
			Header: http.Header{"auth": []string{"secret"}},
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
			Header: http.Header{"auth": []string{"secret"}},
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
			Header: http.Header{"auth": []string{"secret"}},
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
		Header: http.Header{"auth": []string{"secret"}},
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
