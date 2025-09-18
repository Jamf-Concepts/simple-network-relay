# Simple Network Relay

Simple Network Relay provides a lightweight implementation of a Network Relay server intended for learning and
experiments. It is written in [Golang](https://go.dev) and uses the [quic-go](https://github.com/quic-go/quic-go)
library.

Network relays are a special type of proxy that can be used for remote access and privacy solutions supported on Apple
devices. These relays are built into the network stack of the operating systems and don’t require any custom app code.
Relays are available on devices with iOS 17, iPadOS 17, macOS 14 or tvOS 17, or later.

![Diagram of Network relay tunneling TLS traffic over HTTP/3.](/image/relay.png)


> [!TIP]
> Additional information on relays can be found in the
> [Network relays on Apple devices](https://support.apple.com/en-gb/guide/deployment/dep91a6e427d/web) and
> [Relay payload](https://developer.apple.com/documentation/devicemanagement/relay) documentation.

## Build and run

### Build dependencies

* [Go 1.24.0 or later](https://go.dev/doc/install)
* [GNU Make](https://www.gnu.org/software/make/)
* [OpenSSL](https://openssl-library.org/source/)

### Build and run the relay server

To build and run the relay server on your local machine, run the following command in the project root directory:

```bash
  make
```

The relay certificate uses local hostname, so the client device must be on the same network as the relay server.

### Configure relay on client device

To enable the relay on the client:

1) Install generated CA certificate
    * Install certificate `cert/simple_network_relay_root_ca.crt` to the client device[^1]
        * Set the CA certificate to trusted depending on the platform:
            * macOS: in
              `Keychain Access > Open Keychain Access > login > Simple Network Relay Root CA >  When using this certificate: Always Trust`
            * iOS/iPadOS: in `Settings > General > About > Certificate Trust Settings`

2) Install configuration profile with Relay payload
    * Install profile `relay.mobileconfig` to the client device for system to start routing traffic to the relay [^1]
    * To toggle relay ON/OFF, use `Settings > VPN & Relays > Network Relay > (De)Activate Configuration`

[^1]: You can use AirDrop or [Apple Configurator](https://apps.apple.com/us/app/apple-configurator/id1037126344)

### Troubleshooting

#### Analyze traffic

The HTTP/3 traffic can be inspected with [Wireshark](https://www.wireshark.org/). Configure the Pre-Master-Secret log
location in `Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename` to `/tmp/keys`. Note, that tunneled
traffic is end-to-end encrypted, so you will only see the QUIC layer and not the actual content.

#### Debugging connection issues

1) If you see `CRYPTO_ERROR` messages in the relay logs, it indicates that the client device does not trust the CA
   certificate. Make sure you have installed the CA certificate and set it as trusted on the client device.
    ```
    Closing connection with error: CRYPTO_ERROR 0x12a (remote) (frame type: 0x6): TLS alert error
    ```

2) Verify generated relay certificate matches your local hostname. If not, set `HOST` manually in
   `script/generate_certificates`, run `make clean && make` and re-install the certificates.
    ```
    $ scutil --get LocalHostName
    MacBook-Pro

    $ openssl x509 -noout -text -in cert/simple_network_relay.crt | grep DNS
    DNS:MacBook-Pro.local, IP Address:127.0.0.1
    ```

3) Verify `HTTP3RelayURL` in `relay.mobileconfig` file contains hostname in correct format. If not, set the hostname
   manually in the `relay.mobileconfig` file. The expected format is `https://<hostname>:443`.
    ```
    $ scutil --get LocalHostName
    MacBook-Pro

    $ grep 'HTTP3RelayURL' relay.mobileconfig -A 1
    <key>HTTP3RelayURL</key>
    <string>https://MacBook-Pro.local:443</string>
    ```

4) Verify that the relay server is running and listening on port UDP 443. If not, make sure the user has sufficient
   permissions and the port is not occupied by another process, or try rebooting the system. If you need to use a
   different port, change it in the relay source and in `relay.mobileconfig` file.
    ```
    $ sudo lsof -nP +c 20 -iUDP:443
    COMMAND              PID USER FD TYPE             DEVICE SIZE/OFF NODE NAME
    simple-network-relay  42 user 5u IPv6 0x154e6b4514d0dcf4      0t0  UDP *:443
    ```

5) Verify the relay server responds to HTTP/3 requests on localhost. If not, check the relay server logs for errors.
    ```
    # brew install cloudflare/homebrew-cloudflare/curl
    $ curl --http3 -kv https://localhost:443
    ...
    < HTTP/3 503
    < proxy-status: NetworkRelay; error=destination_unavailable
    ```

6) Verify that client device can resolve DNS name of the relay server. If not, disconnect and restart both client and
   server devices.
    ```
    $ dns-sd -G v46 MacBook-Pro.local
    Timestamp     A/R  Flags     IF  Hostname            Address                                      TTL
    16:37:01.464  Add  40000003  12  MacBook-Pro.local.  FE80:0000:0000:0000:1087:EABF:4B3F:479A%en0  4500
    16:37:01.464  Add  40000002  12  MacBook-Pro.local.  10.124.26.188                                4500
    ```

### Who do I talk to?

If you have any questions reach out to tomas.dragoun@jamf.com
