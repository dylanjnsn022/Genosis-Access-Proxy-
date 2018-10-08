package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
	"github.com/go-redis/redis"
	"github.com/thanhpk/randstr"
	"os"
)

//Panic if error is not nil
func check(e error) {
	if e != nil {
		panic(e)
	}
}

//Append extra 0s if the length of otp is less than 6
//If otp is "1234", it will return it as "001234"
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

	//Converts secret to base32 Encoding. Base32 encoding desires a 32-character
	//subset of the twenty-six letters A–Z and ten digits 0–9
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	check(err)
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	//Signing the value using HMAC-SHA1 Algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	o := (h[19] & 15)

	var header uint32
	//Get 32 bit chunk from hash starting at the o
	r := bytes.NewReader(h[o : o+4])
	err = binary.Read(r, binary.BigEndian, &header)

	check(err)
	//Ignore most significant bits as per RFC 4226.
	//Takes division from one million to generate a remainder less than < 7 digits
	h12 := (int(header) & 0x7fffffff) % 1000000

	//Converts number as a string
	otp := strconv.Itoa(int(h12))

	return prefix0(otp)
}

func getTOTPToken(secret string) string {
	//The TOTP token is just a HOTP token seeded with every 30 seconds.
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
panic(err)
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
arg := os.Args[1]
if arg == "get" {
	fmt.Println(get2fa(os.Args[2]))
} else if arg == "set" {
	set2fa(os.Args[2])
} else {
	fmt.Println("set email")
	fmt.Println("get email")
}
}
