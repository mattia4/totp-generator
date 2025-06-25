package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"time"
)

type HashingAlgorithm int

const (
	SHA1 HashingAlgorithm = iota // RFC 6238 advice SHA-1 per TOTP
	SHA256
	SHA512
)

// generateTOTP generate a TOTP (Time-Based One-Time Password)
// secret: secret key coded in base64.
// algorithm: hashing algorithm (SHA1, SHA256, SHA512).
// digits: number of digits for the otp code (ex. 6, 8).
// timeStep: code validation interval in seconds (ex. 30 secondi).
func generateTOTP(secret string, algorithm HashingAlgorithm, digits int, timeStep int) (string, error) {
	if timeStep <= 0 {
		return "", fmt.Errorf("timestep has to be, timestep > 0")
	}

	if digits <= 0 {
		return "", fmt.Errorf("digits has to be, digits > 0")
	}

	currentTime := time.Now().UTC().Unix()
	counter := currentTime / int64(timeStep)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	var hashFunc func() hash.Hash
	switch algorithm {
	case SHA1:
		hashFunc = sha1.New
	case SHA256:
		hashFunc = sha256.New
	case SHA512:
		hashFunc = sha512.New
	default:
		return "", fmt.Errorf("hashing not supported")
	}

	mac := hmac.New(hashFunc, []byte(secret))
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := int(hash[len(hash)-1] & 0x0f)
	slice := hash[offset : offset+4]

	codeInt := int(binary.BigEndian.Uint32(slice) & 0x7fffffff)

	modDivisor := 1
	for range digits {
		modDivisor *= 10
	}

	otp := codeInt % modDivisor

	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), otp), nil
}

func main() {
	var secret string
	flag.StringVar(&secret, "secret", "", "secret key for OTP")

	var algorithmStr string
	flag.StringVar(&algorithmStr, "alg", "SHA1", " hashing algorithm (SHA1, SHA256, SHA512)")

	var digits int
	flag.IntVar(&digits, "digits", 6, "number of digits for the otp code (ex. 6, 8).")

	var timeStep int
	flag.IntVar(&timeStep, "step", 30, "time step in sec (ex. 30, 60)")

	flag.Parse()

	if secret == "" {
		fmt.Println("Error: secret (-secret) is mandatory.")
		flag.Usage()
		return
	}

	var algorithm HashingAlgorithm
	switch algorithmStr {
	case "SHA1":
		algorithm = SHA1
	case "SHA256":
		algorithm = SHA256
	case "SHA512":
		algorithm = SHA512
	default:
		fmt.Printf("Error: Algorithm '%s' not supported. (SHA1, SHA256 o SHA512).\n", algorithmStr)
		flag.Usage()
		return
	}

	totpCode, err := generateTOTP(secret, algorithm, digits, timeStep)
	if err != nil {
		fmt.Println("Error while generating OTP:", err)
		return
	}

	fmt.Printf("TOTP generated (Alg: %d, Digits: %d, Step: %d): %s\n", algorithm, digits, timeStep, totpCode)
}
