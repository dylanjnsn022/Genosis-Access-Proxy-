# Genosis-Access-Proxy

### Build:
        go build genosis.go
        go build bpm.go

### Usage:
    ./genosis <config file path>
    ./bpm
    
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
