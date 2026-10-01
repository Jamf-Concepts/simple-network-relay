// Copyright (c) 2026 JAMF Software, LLC
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"
)

type proxyStatus struct {
	code  int
	error string
}

var (
	statusOK = proxyStatus{
		code: http.StatusOK,
	}
	statusGoDirect = proxyStatus{
		code:  http.StatusServiceUnavailable,
		error: "SimpleNetworkRelay; error=destination_unavailable",
	}
	statusBlock = proxyStatus{
		code:  http.StatusBadGateway,
		error: "SimpleNetworkRelay; error=connection_refused",
	}
)

const authTokenFile = "cert/auth_token.txt" //nolint:gosec

func main() {
	authToken, err := os.ReadFile(authTokenFile)
	if err != nil {
		log.Fatalf("Failed to read auth token: %v", err)
	}

	// TLS key logging is opt-in, enabled by setting SSLKEYLOGFILE
	var keyLog io.Writer
	if path := os.Getenv("SSLKEYLOGFILE"); path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec
		if err != nil {
			log.Fatalf("Failed to open TLS key log file: %v", err)
		}
		defer f.Close()
		keyLog = f
		log.Printf("Writing TLS keys to %s\n", path) //nolint:gosec
	}

	s, err := newHTTP3Server(443, keyLog, strings.TrimSpace(string(authToken)))
	if err != nil {
		log.Fatalf("Failed to create HTTP/3 server: %v", err)
	}

	log.Printf("Listening for HTTP/3 connections on %s\n", s.Addr)
	if err = s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newHTTP3Server(port int, keyLog io.Writer, authToken string) (*http3.Server, error) {
	if authToken == "" {
		return nil, errors.New("auth token must not be empty")
	}

	kp, err := tls.LoadX509KeyPair("cert/simple_network_relay.crt", "cert/simple_network_relay.key")
	if err != nil {
		return nil, fmt.Errorf("loading key pair failed: %w", err)
	}

	return &http3.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: &relay{authToken: []byte(authToken)},
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{kp},
			KeyLogWriter: keyLog,
		},
		QUICConfig:  &quic.Config{Allow0RTT: false},
		IdleTimeout: 30 * time.Second,
	}, nil
}

type relay struct {
	authToken []byte
}

func (rl *relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Close = true

	// Handle only CONNECT TCP requests
	if r.Method != http.MethodConnect || r.Proto == "connect-udp" {
		writeHeader(w, statusGoDirect)
		return
	}

	// Authenticate the request
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("auth")), rl.authToken) != 1 {
		writeHeader(w, statusBlock)
		return
	}

	log.Printf("CONNECT request from %q to %q", r.RemoteAddr, r.Host) //nolint:gosec

	// Resolve DNS and open connection to the target server
	c, err := dialTCP(r.Context(), r.Host)
	if err != nil {
		log.Printf("Failed to connect to %q: %s", r.Host, err) //nolint:gosec
		writeHeader(w, statusGoDirect)
		return
	}

	// Proxy data
	writeHeader(w, statusOK)
	if err = proxyData(w, r, c); err != nil {
		log.Printf("Tunnel closed: %s", err)
	}
}

func writeHeader(w http.ResponseWriter, s proxyStatus) {
	if s.error != "" {
		w.Header().Add("proxy-status", s.error)
	}
	w.WriteHeader(s.code)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func dialTCP(ctx context.Context, authority string) (*net.TCPConn, error) {
	// CONNECT requires the authority in host:port form
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return nil, fmt.Errorf("invalid authority '%s': %w", authority, err)
	} else if host == "" || port == "" {
		return nil, fmt.Errorf("invalid authority '%s': missing host or port", authority)
	}

	// Resolve using public DNS resolver
	ip, err := resolveDNS(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host '%s': %w", host, err)
	}

	dial := net.Dialer{Timeout: 5 * time.Second}
	c, err := dial.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func resolveDNS(ctx context.Context, host string) (net.IP, error) {
	// Check if the host is an IP address
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	// Resolve target server IP address
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resolvedIPs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	} else if len(resolvedIPs) == 0 {
		return nil, fmt.Errorf("no IPs found for host '%s'", host)
	}
	return resolvedIPs[0].IP, nil
}

func proxyData(w http.ResponseWriter, r *http.Request, c *net.TCPConn) error {
	defer c.Close()

	// Close the server connection when the client resets the stream or the QUIC connection closes
	stop := context.AfterFunc(r.Context(), func() { _ = c.Close() })
	defer stop()

	eg := errgroup.Group{}
	fw := &flushingWriter{ResponseWriter: w}

	// Tunnel data from client to server
	eg.Go(func() error {
		if _, err := io.Copy(c, r.Body); err != nil {
			_ = c.Close()
			return err
		}
		// Client finished sending, propagate the half-close to the server
		return c.CloseWrite()
	})

	// Tunnel data from server to client
	eg.Go(func() error {
		_, err := io.Copy(fw, c)
		// Server finished sending, stop reading from the client so the tunnel can close
		_ = r.Body.Close()
		return err
	})

	return eg.Wait()
}

type flushingWriter struct {
	http.ResponseWriter
}

func (fw *flushingWriter) Write(b []byte) (int, error) {
	n, err := fw.ResponseWriter.Write(b)
	if f, ok := fw.ResponseWriter.(http.Flusher); ok && err == nil {
		f.Flush()
	}
	return n, err
}
