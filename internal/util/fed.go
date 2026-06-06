package util

import "strings"

// isRemoteUser returns true if the user is remote (i.e. not on the same server)
func IsRemoteUser(userID, serverName string) bool {

	parts := strings.Split(userID, ":")
	if len(parts) != 2 {
		return false
	}
	return parts[1] != serverName
}
