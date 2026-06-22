package main

import "fmt"

func main() {
	// Simulate leaked credentials in source
	apiKey := "sk-test_abcdefghijklmnopqrstuvwxyz123456"
	token := "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	awsKey := "AKIAIOSFODNN7EXAMPLE"

	fmt.Println(apiKey, token, awsKey)
}
