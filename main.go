// Copyright (c) 2025 JAMF Software, LLC
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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

func main() {
	// #nosec G303
	keylogFile, _ := os.Create("/tmp/keys")
	defer keylogFile.Close()

	s, err := newHTTP3Server(443, keylogFile)
	if err != nil {
		log.Fatalf("Failed to create HTTP/3 server: %v", err)
	}

	log.Printf("Listening for HTTP/3 connections on %s\n", s.Addr)
	if err = s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newHTTP3Server(port int, keyLog io.Writer) (*http3.Server, error) {
	kp, err := tls.LoadX509KeyPair("cert/simple_network_relay.crt", "cert/simple_network_relay.key")
	if err != nil {
		return nil, fmt.Errorf("loading key pair failed: %w", err)
	}

	return &http3.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{kp},
			KeyLogWriter: keyLog,
		},
		QUICConfig:  &quic.Config{Allow0RTT: false},
		IdleTimeout: 30 * time.Second,
	}, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Close = true

	// Handle only CONNECT TCP requests
	if r.Method != http.MethodConnect || r.Proto == "connect-udp" {
		writeHeader(w, statusGoDirect)
		return
	}

	// Authenticate the request
	if r.Header.Get("auth") != "secret" {
		writeHeader(w, statusBlock)
		return
	}

	log.Printf("CONNECT request from '%s' to '%s'", r.RemoteAddr, r.Host)

	// Resolve DNS and open connection to the target server
	c, err := dialTCP(r.Context(), r.Host)
	if err != nil {
		log.Printf("Failed to connect to '%s': %s", r.Host, err)
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

func dialTCP(ctx context.Context, authority string) (net.Conn, error) {
	host, port := splitHostPort(authority)

	// Resolve using public DNS resolver
	ip, err := resolveDNS(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve host '%s': %w", host, err)
	}

	dial := net.Dialer{Timeout: 5 * time.Second}
	return dial.Dial("tcp", net.JoinHostPort(ip.String(), port))
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

func splitHostPort(authority string) (string, string) {
	h, p, err := net.SplitHostPort(authority)
	if err != nil {
		return authority, "443"
	}
	return h, p
}

func proxyData(w http.ResponseWriter, r *http.Request, c net.Conn) error {
	defer c.Close()
	eg := errgroup.Group{}
	fw := &flushingWriter{ResponseWriter: w}

	// Tunnel data from client to server
	eg.Go(func() error {
		_, err := io.Copy(c, r.Body)
		return err
	})

	// Tunnel data from server to client
	eg.Go(func() error {
		_, err := io.Copy(fw, c)
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
