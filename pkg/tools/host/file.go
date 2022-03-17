package host

import (
	"os"
	"strings"
)

var hostMappingPath = os.Getenv("ROVER_HOST_MAPPING")

// GetFileInHost means add the host root mapping prefix, it's dependent when the rover is deploy in a container
func GetFileInHost(absPath string) string {
	if hostMappingPath != "" && strings.HasPrefix(absPath, hostMappingPath) {
		return absPath
	}
	return hostMappingPath + absPath
}
