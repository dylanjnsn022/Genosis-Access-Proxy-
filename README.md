# Genosis-Access-Proxy

### Prerequisites:
        golang
        redis-server

### Build:
        go build genosis.go
        go build bpm.go
        go build 2fa.go

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
