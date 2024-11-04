package handlers

import (
	"fmt"
	"io/ioutil"

	"identity.plus/mtls-gw/global"
)

func List_Service_Configurations() ([]string, error) {
	// Directory containing the files
	dir := global.Config__.DataDirectory + "/identity"

	// Read all files in the directory
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %v", err)
	}

	// Array to store the resulting filenames
	var serviceFiles []string

	// Loop over the files and process them
	for _, file := range files {
		// Get the filename
		filename := file.Name()

		// Check if the file ends with ".yam
		if filename != "_" {
			// Append to the result array
			serviceFiles = append(serviceFiles, filename)
		}
	}

	return serviceFiles, nil
}
