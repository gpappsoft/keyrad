package radiussrv

// MS-CHAPv2 helpers and validation
func ValidateMSCHAPv2(challenge, response []byte, username, password string) (bool, byte, []byte, string) {
	// ...move validateMSCHAPv2 and helpers here...
	// ...use exported names...
	return false, 0, nil, ""
}

// ...other helpers: buildMSCHAP2Success, computeNTResponse, challengeHash, ntPasswordHash, challengeResponse, makeDESKey, utf16le, md4sum, generateAuthenticatorResponse...
