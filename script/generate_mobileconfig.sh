#!/bin/bash
# Copyright (c) 2026 JAMF Software, LLC
set -e
umask 077 # readable only by the owner

AUTH_TOKEN_FILE=cert/auth_token.txt

generate_auth_token() {
  [ -f ${AUTH_TOKEN_FILE} ] && return
  openssl rand -hex 32 > ${AUTH_TOKEN_FILE}
}

generate_mobile_config() {
  AUTH_TOKEN=$(cat ${AUTH_TOKEN_FILE})
  HOST=$(scutil --get LocalHostName || hostname)
  [[ $HOST != *.local ]] && HOST="${HOST}.local"
  cat > "relay.mobileconfig" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>PayloadContent</key>
        <array>
            <dict>
                <key>PayloadDisplayName</key>
                <string>Network Relay</string>
                <key>PayloadType</key>
                <string>com.apple.relay.managed</string>
                <key>Relays</key>
                <array>
                    <dict>
                        <key>HTTP3RelayURL</key>
                        <string>https://${HOST}:443</string>
                        <key>AdditionalHTTPHeaderFields</key>
                        <dict>
                            <key>auth</key>
                            <string>${AUTH_TOKEN}</string>
                        </dict>
                    </dict>
                </array>
                <key>PayloadUUID</key>
                <string>payloadUUID2</string>
                <key>PayloadIdentifier</key>
                <string>payloadIdentifier</string>
                <key>PayloadVersion</key>
                <integer>1</integer>
            </dict>
        </array>
        <key>PayloadDescription</key>
        <string>Simple Network Relay</string>
        <key>PayloadDisplayName</key>
        <string>SimpleNetworkRelay</string>
        <key>PayloadIdentifier</key>
        <string>payloadIdentifier</string>
        <key>PayloadOrganization</key>
        <string>SimpleNetworkRelay</string>
        <key>PayloadType</key>
        <string>Configuration</string>
        <key>PayloadUUID</key>
        <string>payloadUUID1</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
    </dict>
</plist>
EOF
}

[ -d cert ] || mkdir cert
generate_auth_token
generate_mobile_config
