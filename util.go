package vessel

import (
	"encoding/base64"
	"strings"
)

func base64URLDecode(token string) ([]byte, error) {

	// Restore base64 32-bit aligned padding if needed
	// NOTE: Padding (=) often gets dropped by senders as an optimization
	if paddingRequired := len(token) % 4; paddingRequired != 0 {
		token += strings.Repeat("=", 4-paddingRequired)
	}

	bytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
