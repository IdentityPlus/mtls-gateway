package utils

import (
	"strings"
)

func Join(slice []string, separator string) string {
	return strings.Join(slice, separator)
}
