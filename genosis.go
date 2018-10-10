package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/go-redis/redis"
	"github.com/go-yaml/yaml"
	vhost "github.com/inconshreveable/go-vhost"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"github.com/thanhpk/randstr"
)

const (
	muxTimeout            = 10 * time.Second
	defaultConnectTimeout = 10000 // milliseconds
)

type loadTLSConfigFn func(crtPath, keyPath string) (*tls.Config, error)

type Options struct {
	configPath string
}

type Backend struct {
	Addr           string `"yaml:addr"`
	ConnectTimeout int    `yaml:connect_timeout"`
}

type Frontend struct {
	Backends []Backend `yaml:"backends"`
	Strategy string    `yaml:"strategy"`
	TLSCrt   string    `yaml:"tls_crt"`
	mux      *vhost.TLSMuxer
	TLSKey   string `yaml:"tls_key"`
	Default  bool   `yaml:"default"`

	strategy  BackendStrategy `yaml:"-"`
	tlsConfig *tls.Config     `yaml:"-"`
}

type Configuration struct {
	BindAddr        string               `yaml:"bind_addr"`
	Frontends       map[string]*Frontend `yaml:"frontends"`
	defaultFrontend *Frontend
}

type Server struct {
	*log.Logger
	*Configuration
	wait sync.WaitGroup

	// these are for easier testing
	mux   *vhost.TLSMuxer
	ready chan int
}

func finish_verify(name string, ip_addr string) string {

	s := strings.Split(ip_addr, ":")
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       1,  // use default DB
	})
	val, err := client.Get(s[0]).Result()
	if err != nil {
		checksum := "0"
		return checksum
	}
	clientall := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       2,  // use default DB
	})
	all, err := clientall.Get("all").Result()
	if err != nil {
		fmt.Println("%%No all permission is set in the permissions file")
	}
	ss_all := strings.Split(all, ",")
	for i := 0; i < len(ss_all); i++ {
		if name == strings.Replace(ss_all[i], " ", "", -1) {
			fmt.Println("----------------Permissions found for all:" + name)
			checksum := "1"
			return checksum
		}
	}
	client2 := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       2,  // use default DB
	})
	val2, err := client2.Get(val).Result()
	if err != nil {
		fmt.Println("%%ERROR User permissions are not defined")
	}
	ss := strings.Split(val2, ",")
	for i := 0; i < len(ss); i++ {
		if name == strings.Replace(ss[i], " ", "", -1) {
			err := client.Set(s[0], val, time.Minute).Err()
			if err != nil {
				fmt.Println("%%error with redis set")
			}
			fmt.Println("----------------Permissions found for " + val + ":" + name)
			checksum := "1"
			return checksum
		}
	}

	checksum := "0"
	return checksum
}

func (s *Server) Run() error {
	// bind a port to handle TLS connections
	l, err := net.Listen("tcp", s.Configuration.BindAddr)
	if err != nil {
		return err
	}
	s.Printf("Serving connections on %v", l.Addr())

	// start muxing on it
	s.mux, err = vhost.NewTLSMuxer(l, muxTimeout)
	if err != nil {
		return err
	}

	// wait for all frontends to finish
	s.wait.Add(len(s.Frontends))

	// setup muxing for each frontend
	for name, front := range s.Frontends {
		fl, err := s.mux.Listen(name)
		if err != nil {
			return err
		}
		go s.runFrontend(name, front, fl)
	}

	// custom error handler so we can log errors
	go func() {
		for {
			conn, err := s.mux.NextError()

			if conn == nil {
				s.Printf("Failed to mux next connection, error: %v", err)
				if _, ok := err.(vhost.Closed); ok {
					return
				} else {
					continue
				}
			} else {
				if _, ok := err.(vhost.NotFound); ok && s.defaultFrontend != nil {
					go s.proxyConnection(conn, s.defaultFrontend)
				} else {
					s.Printf("Failed to mux connection from %v, error: %v", conn.RemoteAddr(), err)
					// XXX: respond with valid TLS close messages
					conn.Close()
				}
			}
		}
	}()

	// we're ready, signal it for testing
	if s.ready != nil {
		close(s.ready)
	}

	s.wait.Wait()

	return nil
}

func (s *Server) runFrontend(name string, front *Frontend, l net.Listener) {
	// mark finished when done so Run() can return
	defer s.wait.Done()

	// always round-robin strategy for now
	front.strategy = &RoundRobinStrategy{backends: front.Backends}

	s.Printf("Handling connections to %v", name)
	for {
		// accept next connection to this frontend
		conn, err := l.Accept()
		if err != nil {
			s.Printf("Failed to accept new connection for '%v': %v", conn.RemoteAddr())
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return
		}
		verify := finish_verify(name, conn.RemoteAddr().String())
		if verify == "1" {
			s.Printf("Accepted new connection for %v from %v", name, conn.RemoteAddr())
			// proxy the connection to an backend
			go s.proxyConnection(conn, front)
		} else {
			fmt.Println("----------------No permissions")
		}
	}
}

func (s *Server) proxyConnection(c net.Conn, front *Frontend) (err error) {
	// unwrap if tls cert/key was specified
	if front.tlsConfig != nil {
		c = tls.Server(c, front.tlsConfig)
	}

	// pick the backend
	backend := front.strategy.NextBackend()

	// dial the backend
	upConn, err := net.DialTimeout("tcp", backend.Addr, time.Duration(backend.ConnectTimeout)*time.Millisecond)
	if err != nil {
		s.Printf("Failed to dial backend connection %v: %v", backend.Addr, err)
		c.Close()
		return
	}
	s.Printf("Initiated new connection to backend: %v %v", upConn.LocalAddr(), upConn.RemoteAddr())

	// join the connections
	s.joinConnections(c, upConn)
	return
}

func (s *Server) joinConnections(c1 net.Conn, c2 net.Conn) {
	var wg sync.WaitGroup
	halfJoin := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		defer dst.Close()
		defer src.Close()
		n, err := io.Copy(dst, src)
		s.Printf("Copy from %v to %v failed after %d bytes with error %v", src.RemoteAddr(), dst.RemoteAddr(), n, err)
	}

	s.Printf("Joining connections: %v %v", c1.RemoteAddr(), c2.RemoteAddr())
	wg.Add(2)
	go halfJoin(c1, c2)
	go halfJoin(c2, c1)
	wg.Wait()
}

type BackendStrategy interface {
	NextBackend() Backend
}

type RoundRobinStrategy struct {
	backends []Backend
	idx      int
}

func (s *RoundRobinStrategy) NextBackend() Backend {
	n := len(s.backends)

	if n == 1 {
		return s.backends[0]
	} else {
		s.idx = (s.idx + 1) % n
		return s.backends[s.idx]
	}
}

func parseArgs() (*Options, error) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <config file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s is a simple TLS reverse proxy that can multiplex TLS connections\n"+
			"by inspecting the SNI extension on each incoming connection. This\n"+
			"allows you to accept connections to many different backend TLS\n"+
			"applications on a single port.\n\n"+
			"%s takes a single argument: the path to a YAML configuration file.\n\n", os.Args[0], os.Args[0])
	}
	flag.Parse()

	if len(flag.Args()) != 1 {
		return nil, fmt.Errorf("You must specify a single argument, the path to the configuration file.")
	}

	return &Options{
		configPath: flag.Arg(0),
	}, nil

}

func parseConfig(configBuf []byte, loadTLS loadTLSConfigFn) (config *Configuration, err error) {
	// deserialize/parse the config
	config = new(Configuration)
	if err = yaml.Unmarshal(configBuf, &config); err != nil {
		err = fmt.Errorf("Error parsing configuration file: %v", err)
		return
	}

	// configuration validation / normalization
	if config.BindAddr == "" {
		err = fmt.Errorf("You must specify a bind_addr")
		return
	}

	if len(config.Frontends) == 0 {
		err = fmt.Errorf("You must specify at least one frontend")
		return
	}

	for name, front := range config.Frontends {
		if len(front.Backends) == 0 {
			err = fmt.Errorf("You must specify at least one backend for frontend '%v'", name)
			return
		}

		if front.Default {
			if config.defaultFrontend != nil {
				err = fmt.Errorf("Only one frontend may be the default")
				return
			}
			config.defaultFrontend = front
		}

		for _, back := range front.Backends {
			if back.ConnectTimeout == 0 {
				back.ConnectTimeout = defaultConnectTimeout
			}

			if back.Addr == "" {
				err = fmt.Errorf("You must specify an addr for each backend on frontend '%v'", name)
				return
			}
		}

		if front.TLSCrt != "" || front.TLSKey != "" {
			if front.tlsConfig, err = loadTLS(front.TLSCrt, front.TLSKey); err != nil {
				err = fmt.Errorf("Failed to load TLS configuration for frontend '%v': %v", name, err)
				return
			}
		}
	}

	return
}

func loadTLSConfig(crtPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func login(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		// logic part of log in
		uname := strings.Join(r.Form["username"], " ")
		pswd := strings.Join(r.Form["password"], " ")
		twofa := strings.Join(r.Form["2fa"], " ")
		client := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})
		val, err := client.Get(uname).Result()
		if err != nil {
			fmt.Println("----------------Login FAILED(Username): " + uname)
			denied := "https://" + r.Host + "/denied.html"
			http.Redirect(w, r, denied, http.StatusSeeOther)
		} else {
			if val == GetMD5Hash(pswd) {
				if twofa == get2fa(uname) {
				client1 := redis.NewClient(&redis.Options{
					Addr:     "localhost:6379",
					Password: "", // no password set
					DB:       1,  // use default DB
				})
				fmt.Println("----------------Login event: " + uname)
				ip_addr := string(r.RemoteAddr)
				s := strings.Split(ip_addr, ":")
				err := client1.Set(s[0], uname, time.Minute).Err()
				if err != nil {
					fmt.Println("%%error with redis set - Login")
				}
				t, _ := template.ParseFiles("redirect.gtpl")
				t.Execute(w, nil)
			  } else {
					fmt.Println("----------------Login FAILED(2FA): " + uname)
					denied := "https://" + r.Host + "/denied.html"
					http.Redirect(w, r, denied, http.StatusSeeOther)
				}
			} else {
				fmt.Println("----------------Login FAILED(Password): " + uname)
				denied := "https://" + r.Host + "/denied.html"
				http.Redirect(w, r, denied, http.StatusSeeOther)
			}
		}

}

func register(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	uname := strings.Join(r.Form["uname"], " ")
	pswd := GetMD5Hash(strings.Join(r.Form["psswd"], " "))
	pswd1 := GetMD5Hash(strings.Join(r.Form["psswd1"], " "))
	if pswd == pswd1 {
		client := redis.NewClient(&redis.Options{
			Addr:     "localhost:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})
		fmt.Println("----------------User Registered: " + uname)
		err := client.Set(uname, pswd, 0).Err()
		if err != nil {
			fmt.Println("Error Registering" + uname)
		}
		set2fa(uname)
		t, _ := template.ParseFiles("redirect_home.gtpl")
		t.Execute(w, nil)
	} else {
		fmt.Println("----------------User Registration FAILED(Passwords did not match): " + uname)
		t, _ := template.ParseFiles("register_fail.gtpl")
		t.Execute(w, nil)
	}
}

func redirect_http(w http.ResponseWriter, req *http.Request){
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
			target += "?" + req.URL.RawQuery
	}
	log.Printf("redirect to: %s", target)
	http.Redirect(w, req, target,
					http.StatusTemporaryRedirect)
}

func serve() {
	go http.ListenAndServe(":80", http.HandlerFunc(redirect_http))
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/", fs)
	http.HandleFunc("/login/", login)
	http.HandleFunc("/register/", register)
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil) // setting listening port
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func ap_proxy_run() {
	opts, err := parseArgs()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}


	configBuf, err := ioutil.ReadFile(opts.configPath)
	if err != nil {
		fmt.Printf("Failed to read configuration file %s: %v\n", opts.configPath, err)
		os.Exit(1)
	}


	config, err := parseConfig(configBuf, loadTLSConfig)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}


	s := &Server{
		Configuration: config,
		Logger:        log.New(os.Stdout, "+ ", log.LstdFlags|log.Lshortfile),
	}

	err = s.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start genosis: %v\n", err)
		os.Exit(1)
	}
}

func builder() {
	cmd := "./bpm"
	if err := exec.Command(cmd).Run(); err != nil {
		fmt.Println("%%Error Building Permissions")
	}
}

func check(e error) {
	if e != nil {
		fmt.Println("%%Error")
	}
}


func prefix0(otp string) string {
	if len(otp) == 6 {
		return otp
	}
	for i := (6 - len(otp)); i > 0; i-- {
		otp = "0" + otp
	}
	return otp
}

func getHOTPToken(secret string, interval int64) string {


	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	check(err)
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))


	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)


	o := (h[19] & 15)

	var header uint32

	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)

	check(err)

	h12 := (int(header) & 0x7fffffff) % 1000000


	otp := strconv.Itoa(int(h12))

	return prefix0(otp)
}

func getTOTPToken(secret string) string {
	interval := time.Now().Unix() / 30
	return getHOTPToken(secret, interval)
}

func get2fa(email string) string{
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       3,  // use default DB
	})
data, err := client.Get(email).Result()
if err != nil {
fmt.Println("%%ERROR getting 2fa for " + email)
}
	return getTOTPToken(data)
}

func set2fa(name string) {
token := randstr.String(16)
data := []byte(token)
str := base32.StdEncoding.EncodeToString(data)
s := str[0:16]
client := redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "", // no password set
	DB:       3,  // use default DB
})
err := client.Set(name, s, 0).Err()
if err != nil {
	panic(err)
}
fmt.Println(name + ": " + s)
}

func main() {
	builder()
	go ap_proxy_run()
	serve()
}
