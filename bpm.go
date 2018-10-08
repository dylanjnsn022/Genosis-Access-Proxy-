package main

import (
	"bufio"
	"fmt"
	"github.com/go-redis/redis"
	"log"
	"os"
	"strings"
)

func main() {
	file, err := os.Open("permissions")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       2,  // use default DB
	})
  client.FlushDB()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), ":")
		err := client.Set(s[0], s[1], 0).Err()
		if err != nil {
			panic(err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Build *Permissions* Complete")
}
