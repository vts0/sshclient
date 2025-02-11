package sshclient

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Client represents a client for executing commands on a remote server via SSH.
type Client struct {
	ssh  *ssh.Client
	sftp *sftp.Client
}

// AuthMethod defines the type of authentication.
type AuthMethod string

const (
	PasswordAuth AuthMethod = "password"
	KeyAuth      AuthMethod = "key"
)

// ClientOptions contains parameters for creating a new client.
type ClientOptions struct {
	Port       int
	AuthType   AuthMethod
	Password   string
	KeyPath    string
	Passphrase string
	UseSFTP    bool
	Timeout    time.Duration
}

// WithPort sets the port number for the SSH connection.
func WithPort(port int) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.Port = port
	}
}

// WithAuthType sets the authentication method for the SSH connection.
func WithAuthType(authType AuthMethod) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.AuthType = authType
	}
}

// WithPassword sets the password for password-based authentication.
func WithPassword(password string) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.Password = password
	}
}

// WithKeyPath sets the path to the private key for key-based authentication.
func WithKeyPath(keyPath string) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.KeyPath = keyPath
	}
}

// WithPassphrase sets the passphrase for encrypted private keys.
func WithPassphrase(passphrase string) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.Passphrase = passphrase
	}
}

// WithUseSFTP enables or disables SFTP support.
func WithUseSFTP(useSFTP bool) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.UseSFTP = useSFTP
	}
}

// WithTimeout sets the timeout duration for the SSH connection.
func WithTimeout(timeout time.Duration) func(*ClientOptions) {
	return func(opts *ClientOptions) {
		opts.Timeout = timeout
	}
}

// NewClient creates a new instance of Client with given host, user, and options.
func NewClient(host, user string, opts ...func(*ClientOptions)) (*Client, error) {
	defaultOpts := &ClientOptions{
		Port:    22,
		Timeout: 10 * time.Second,
	}

	for _, opt := range opts {
		opt(defaultOpts)
	}

	var authMethods []ssh.AuthMethod
	if defaultOpts.AuthType == PasswordAuth {
		if defaultOpts.Password == "" {
			return nil, fmt.Errorf("password is required for password authentication")
		}
		authMethods = append(authMethods, ssh.Password(defaultOpts.Password))
	} else if defaultOpts.AuthType == KeyAuth {
		if defaultOpts.KeyPath == "" {
			return nil, fmt.Errorf("private key path is required for key authentication")
		}
		signer, err := loadPrivateKey(defaultOpts.KeyPath, defaultOpts.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		Timeout:         defaultOpts.Timeout,
		HostKeyCallback: getHostKeyCallback(),
	}

	address := fmt.Sprintf("%s:%d", host, defaultOpts.Port)
	sshClient, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	client := &Client{ssh: sshClient}

	if defaultOpts.UseSFTP {
		sftpClient, err := sftp.NewClient(sshClient)
		if err != nil {
			sshClient.Close()
			return nil, fmt.Errorf("failed to create SFTP client: %w", err)
		}
		client.sftp = sftpClient
	}

	return client, nil
}

// Close closes the SSH and SFTP connections.
func (c *Client) Close() {
	if c.sftp != nil {
		c.sftp.Close()
	}
	if c.ssh != nil {
		c.ssh.Close()
	}
}

// Execute executes a command on the remote server via SSH.
func (c *Client) Execute(command string) (string, error) {
	session, err := c.ssh.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %w", err)
	}

	return string(output), nil
}

// UploadFile uploads a file to the remote server via SFTP.
func (c *Client) UploadFile(ctx context.Context, localPath, remotePath string) error {
	if c.sftp == nil {
		return fmt.Errorf("SFTP client is not initialized")
	}

	srcFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := c.sftp.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer dstFile.Close()

	_, err = srcFile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("failed to seek local file: %w", err)
	}

	_, err = dstFile.ReadFrom(srcFile)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	return nil
}

// DownloadFile downloads a file from the remote server via SFTP.
func (c *Client) DownloadFile(ctx context.Context, remotePath, localPath string) error {
	if c.sftp == nil {
		return fmt.Errorf("SFTP client is not initialized")
	}

	srcFile, err := c.sftp.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer dstFile.Close()

	_, err = srcFile.WriteTo(dstFile)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	return nil
}

// UploadDirectory uploads an entire local directory to the remote server via SFTP.
func (c *Client) UploadDirectory(ctx context.Context, localDir, remoteDir string) error {
	if c.sftp == nil {
		return fmt.Errorf("SFTP client is not initialized")
	}

	info, err := os.Stat(localDir)
	if err != nil {
		return fmt.Errorf("failed to access local directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("local path is not a directory: %s", localDir)
	}

	err = filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		relPath, err := filepath.Rel(localDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}
		relPath = filepath.ToSlash(relPath)
		remotePath := path.Join(remoteDir, relPath)

		if info.IsDir() {
			if err := c.sftp.MkdirAll(remotePath); err != nil {
				return fmt.Errorf("failed to create remote directory %s: %w", remotePath, err)
			}
		} else {
			remoteDirPath := path.Dir(remotePath)
			if err := c.sftp.MkdirAll(remoteDirPath); err != nil {
				return fmt.Errorf("failed to create remote directory %s: %w", remoteDirPath, err)
			}
			if err := c.UploadFile(ctx, path, remotePath); err != nil {
				return fmt.Errorf("failed to upload file %s: %w", path, err)
			}
		}

		return nil
	})

	return err
}

// DownloadDirectory downloads an entire remote directory from the server via SFTP.
func (c *Client) DownloadDirectory(ctx context.Context, remoteDir, localDir string) error {
	if c.sftp == nil {
		return fmt.Errorf("SFTP client is not initialized")
	}

	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	var walk func(string) error
	walk = func(currentRemoteDir string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entries, err := c.sftp.ReadDir(currentRemoteDir)
		if err != nil {
			return fmt.Errorf("failed to read remote directory %s: %w", currentRemoteDir, err)
		}

		for _, entry := range entries {
			remoteEntryPath := path.Join(currentRemoteDir, entry.Name())
			relPath, err := getRelPath(remoteDir, remoteEntryPath)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %w", remoteEntryPath, err)
			}
			localEntryPath := filepath.Join(localDir, filepath.FromSlash(relPath))

			if entry.IsDir() {
				if err := os.MkdirAll(localEntryPath, 0755); err != nil {
					return fmt.Errorf("failed to create local directory %s: %w", localEntryPath, err)
				}
				if err := walk(remoteEntryPath); err != nil {
					return err
				}
			} else {
				if err := c.DownloadFile(ctx, remoteEntryPath, localEntryPath); err != nil {
					return fmt.Errorf("failed to download file %s: %w", remoteEntryPath, err)
				}
			}
		}
		return nil
	}

	return walk(remoteDir)
}

// getRelPath computes the relative path of target relative to base in Unix-style format.
func getRelPath(base, target string) (string, error) {
	base = path.Clean(base)
	target = path.Clean(target)

	if base == "." {
		return target, nil
	}

	if !strings.HasPrefix(target, base+"/") {
		return "", fmt.Errorf("target %s is not within base %s", target, base)
	}

	return strings.TrimPrefix(target, base+"/"), nil
}

// loadPrivateKey loads and parses an SSH private key with error wrapping.
func loadPrivateKey(privateKeyPath, passphrase string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key read failed: %w", err)
	}
	defer func() {
		for i := range keyData {
			keyData[i] = 0 // Clear sensitive data from memory
		}
	}()

	var signer ssh.Signer
	if passphrase == "" {
		signer, err = ssh.ParsePrivateKey(keyData)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("private key parsing failed: %w", err)
	}
	return signer, nil
}

// getHostKeyCallback creates a host key verifier using the known_hosts file.
func getHostKeyCallback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return handleHostKeyVerification(hostname, remote, key)
	}
}

// handleHostKeyVerification implements interactive host key verification.
func handleHostKeyVerification(hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsFile, err := knownHostsFilePath()
	if err != nil {
		return promptUserForNewHost(hostname, key)
	}

	callback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return promptUserForNewHost(hostname, key)
	}

	err = callback(hostname, remote, key)
	if err == nil {
		return nil // Valid known host
	}

	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		return fmt.Errorf("host key verification error: %w", err)
	}

	// Handle unknown host
	if len(keyErr.Want) == 0 {
		return promptUserForNewHost(hostname, key)
	}

	return fmt.Errorf("host key mismatch: %w", keyErr)
}

// promptUserForNewHost prompts the user to confirm a new host key.
func promptUserForNewHost(hostname string, key ssh.PublicKey) error {
	fmt.Printf("\nWARNING: Host key verification is disabled!\n")
	fmt.Printf("The authenticity of host '%s' can't be established.\n", hostname)
	fmt.Printf("Fingerprint: %s\n", ssh.FingerprintSHA256(key))

	if !confirmHostKey() {
		return errors.New("host key verification aborted by user")
	}

	return saveHostKey(hostname, key)
}

// saveHostKey safely appends a host key to the known_hosts file.
func saveHostKey(hostname string, key ssh.PublicKey) error {
	knownHostsFile, err := knownHostsFilePath()
	if err != nil {
		return fmt.Errorf("known_hosts path resolution failed: %w", err)
	}

	// Ensure the .ssh directory exists
	if err := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); err != nil {
		return fmt.Errorf("directory creation failed: %w", err)
	}

	// Open the file in append mode
	file, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("file open failed: %w", err)
	}
	defer file.Close()

	// Write the formatted known_hosts entry
	entry := knownhosts.Line([]string{hostname}, key) + "\n"
	if _, err := file.WriteString(entry); err != nil {
		return fmt.Errorf("file write failed: %w", err)
	}
	return nil
}

// confirmHostKey prompts the user for host key confirmation.
func confirmHostKey() bool {
	const maxAttempts = 3
	attempt := 0

	for attempt < maxAttempts {
		fmt.Print("Do you want to continue connecting? (yes/no): ")
		answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		switch answer {
		case "yes", "y":
			return true
		case "no", "n":
			return false
		default:
			attempt++
			fmt.Printf("Invalid response. Attempts remaining: %d\n", maxAttempts-attempt)
		}
	}
	return false
}

// knownHostsFilePath returns the standard SSH known_hosts file location.
func knownHostsFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory lookup failed: %w", err)
	}
	return filepath.Join(homeDir, ".ssh", "known_hosts"), nil
}
