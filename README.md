# SSHClient

SSHClient is a Go package that provides an easy-to-use interface for executing commands on a remote server via SSH and transferring files using SFTP.

## Features
- Execute remote commands via SSH
- Upload and download files via SFTP
- Support for both password and SSH key authentication
- Configurable timeout settings
- Secure host key verification

## Installation
```sh
go get github.com/vts0/sshclient
```

## Usage
### Creating an SSH Client
```go
package main

import (
	"fmt"
	"log"
	"github.com/vts0/sshclient"
)

func main() {
	client, err := sshclient.NewClient("example.com", "username",
		sshclient.WithAuthType(sshclient.KeyAuth),
		sshclient.WithKeyPath("/path/to/private/key"),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	output, err := client.Execute("ls -l")
	if err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}
	fmt.Println(output)
}
```

### Key-Based Authentication
```go
client, err := sshclient.NewClient("example.com", "username",
	sshclient.WithAuthType(sshclient.KeyAuth),
	sshclient.WithKeyPath("/home/user/.ssh/id_rsa"),
	sshclient.WithPassphrase("your_passphrase"),
)
if err != nil {
	log.Fatalf("Failed to connect: %v", err)
}
defer client.Close()
```

### Executing Commands
```go
output, err := client.Execute("ls -l")
if err != nil {
    log.Printf("Error executing command: %v", err)
}
fmt.Println("Command output:", output)
```

## File Transfer with SFTP
### Uploading a File
```go
err := client.UploadFile(context.Background(), "local.txt", "/remote/path.txt")
if err != nil {
    log.Printf("Upload failed: %v", err)
}
```

### Downloading a File
```go
err := client.DownloadFile(context.Background(), "/remote/file.txt", "local.txt")
if err != nil {
    log.Printf("Download failed: %v", err)
}
```

## License
This project is licensed under the MIT License.

