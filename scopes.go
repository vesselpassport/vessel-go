package vessel

func AddPermittedScope(servername string) {

	// Add the requested scope to the list of scopes
	gPermittedScopes = append(gPermittedScopes, servername)
}
