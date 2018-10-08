# Genosis-Access-Proxy
Genosis is an access proxy. It offers non-https ssl termination, 2FA login, permissions based on username, and yaml configuration. Best used in a Zero Trust environment.

### Prerequisites:
        golang
        redis-server

### Build:
        go build genosis.go
        go build bpm.go
        go build 2fa.go

### Build Self Signed Cert:
        openssl genrsa -out server.key 2048
        openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650

### Usage:
    ./genosis <config file path>
    ./bpm
    ./2fa set <email>
    
### File Structure:
        permissions-
            email:server1, server2
          
        config-
            bind_addr: ":4443"

            frontends:
              servername:
                tls_key: server.key
                tls_crt: server.crt
                backends:
                  -
                    addr: "10.10.1.3:80"
