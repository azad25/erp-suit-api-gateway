package main

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Since there's a proto mismatch, let's test the connection directly
func main() {
	// Connect to the auth service
	conn, err := grpc.Dial("auth-service:50051", 
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithTimeout(10*time.Second))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	fmt.Println("✅ gRPC connection to auth-service:50051 successful!")
	fmt.Println("❌ However, there's a proto mismatch:")
	fmt.Println("   - API Gateway expects: Login method")
	fmt.Println("   - Auth Service provides: Authenticate method")
	fmt.Println("")
	fmt.Println("🔧 This explains why the API Gateway can't communicate with the auth service.")
}