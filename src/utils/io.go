package utils

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
)

var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
}

func Parse_IP(ipStr string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		log.Println("Unable to parse string into IP address: " + ipStr)
		return nil
	}

	return ip
}

func Is_IP_Private(ip net.IP) bool {
	if ip == nil {
		return false
	}

	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

func Get_Local_Private_IP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("cannot list interfaces: %w", err)
	}

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Only IPv4
			ip = ip.To4()
			if ip == nil {
				continue
			}

			if Is_IP_Private(ip) {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no private IPv4 address found")
}

func Build_Template(template string, replacements map[string]string) string {

	// Read the template file from disk
	content, err := os.ReadFile(template)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Convert the content to a string for manipulation
	text := string(content)

	// Perform the replacements
	for key, value := range replacements {
		text = strings.ReplaceAll(text, key, value)
	}

	return text
}

func Deploy_Template(template string, replacements map[string]string, destination string) {

	// Write the modified content to a new file
	err := os.WriteFile(destination, []byte(Build_Template(template, replacements)), 0644)
	if err != nil {
		log.Fatalf("Error writing file: %v", err)
	}
}

func MoveFiles(sourceDir string, destDir string) {

	// Check if destination directory exists, if not, create it
	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		err := os.MkdirAll(destDir, 0755)
		if err != nil {
			log.Fatalf("Failed to create destination directory: %v", err)
		}
	}

	// Walk through the source directory and move files and directories
	err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Construct the destination path
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(destDir, relPath)

		// If it's a directory, create it in the destination
		if info.IsDir() {
			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				err := os.MkdirAll(destPath, 0755)
				if err != nil {
					return fmt.Errorf("failed to create directory: %w", err)
				}
			}
		} else {
			// Move file
			err := MoveFile(path, destPath)
			if err != nil {
				return fmt.Errorf("failed to move file %s: %w", path, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Failed to walk through source directory: %v", err)
	}
}

func MoveFile(srcFile, destFile string) error {
	// Open source file
	src, err := os.Open(srcFile)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	// Create destination file
	dest, err := os.Create(destFile)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dest.Close()

	// Copy content from source to destination
	_, err = io.Copy(dest, src)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Remove source file
	err = os.Remove(srcFile)
	if err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	return nil
}

func WriteToFile(destination string, data []byte) error {
	// Ensure the directory exists
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Write data to file
	err := os.WriteFile(destination, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data to file: %w", err)
	}

	return nil
}

func DeleteFileIfExists(filePath string) error {
	// Check if the file exists
	if _, err := os.Stat(filePath); err == nil {
		// File exists, attempt to delete it
		err = os.Remove(filePath)
		if err != nil {
			return err // Return error if deletion fails
		}
	} else if os.IsNotExist(err) {
		// File does not exist, return without error
		return nil
	} else {
		// Some other error occurred (e.g., permission issue), return it
		return err
	}

	return nil
}

func DeleteConfFiles(dirPath string) error {
	// Walk through all files in the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Return an error if accessing the file failed
		}

		// Check if the file has a .conf extension and is not a directory
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			// Attempt to delete the file
			if removeErr := os.Remove(path); removeErr != nil {
				return removeErr // Return error if deletion fails
			}
			log.Printf("Deleted: %s\n", path) // Optional log to confirm deletion
		}
		return nil
	})

	return err // Return nil if successful or any errors encountered
}
