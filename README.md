# Vessel Go Library

The Vessel Go library makes it easy to integrate with Vessel Web3 identity tokens and attestations in Go applications.

## Install
```console
$ go get github.com/vesselxyz/vessel-go
```

## Usage

[TODO]

### Example usage
Configure a permitted server name scope for incoming sessions:
NOTE: This should match your TLS certificate hostname
```go
func main() {
	// Add my server name to the list of permitted scopes
	vessel.AddPermittedScope("my.servername.com")
  
	// Start the HTTPS server and handle requests ...
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
```

Extracting the Web3 User's ID & Attestations from an HTTPS request:
```go
func HandleWeb3UserRequest(w http.ResponseWriter, req *http.Request) {

	// Verify the validity of the web3 session cookie
	web3session, err := vessel.GetWeb3UserContext(req)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Printf("[+] Got verified web3 ID session for: \"%s\"\r\n", web3session.UserID)

	// Extract verified attestations
	verified_username := web3session.Attestations["name"]
	verified_email := web3session.Attestations["email"]
	verified_sms := web3session.Attestations["sms"]

	fmt.Fprintf(w, "<h1>Greeetings %s<h1>", web3session.UserID)
	fmt.Fprintf(w, "<h2>You have the following attestations present:<h2>\r\n")
	fmt.Fprintf(w, "<h2>Has Web3 Auth Token: true\r\n</h2>")
	fmt.Fprintf(w, "<h2>Has Web3 Username: %v (%s)\r\n</h2>", (len(verified_username) != 0), verified_username)
	fmt.Fprintf(w, "<h2>Has Web3 Verified Email: %v (%s)\r\n</h2>", (len(verified_email) != 0), verified_email)
	fmt.Fprintf(w, "<h2>Has Web3 Verified SMS: %v (%s)\r\n</h2>", (len(verified_sms) != 0), verified_sms)
}
```

## Support
Have questions while integrating Vessel into your app? Reach out to us at developers@vessel.xyz!
