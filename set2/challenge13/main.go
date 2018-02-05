// Code to ECB CopyPasta Block privilege escalation
// 1. Construct an email address that forces the role value to start at the beginning of a block
// 2. Provide a ProfileFor value with known bytes (e.g., "X") in order to pad and close the first block (e.g., email=XX..end of block)
// 2a. With the first block padded, add the escalated role (e.g., admin) to align with the start of the new block
// 2b. Need to also PKCS7 pad the remainder of the "escalation" block. Padding is tricky here.
// 3. Byte slice the original user profile blocks minus the value for the role [:32]
// 4. Byte slice the escalated profile block with only the role in it. Should be [16:32] for the second block
// 5. Append Byte slice User blocks + Escalated block
// 6. Decrypt and you should see something like "email=pwned@bar.com&uid=10&role=admin"

// Why this works: ECB is stateless and nondeterministic so every block is encrypted with the same key, but unaware of \
// the prior or following block. Therefore, cutting along a block boundary and pasting into the ciphertext \
// is a valid operation.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/packetassailant/cryptopals/crypt"
	"github.com/packetassailant/cryptopals/rand"
)

var key = rand.String(16)

func profileFor(e string) ([]byte, error) {
	if strings.ContainsRune(e, 61) {
		result := strings.Split(e, string(61))
		e = result[0]
	}
	if strings.ContainsRune(e, 38) {
		result := strings.Split(e, string(38))
		e = result[0]
	}
	type Profile struct {
		Email string
		UID   string
		Role  string
	}
	ps := &Profile{
		Email: e,
		UID:   "10",
		Role:  "user",
	}
	return json.Marshal(ps)
}

func encodeProfile(p []byte) string {
	type Profile struct {
		Email string
		UID   string
		Role  string
	}
	var profile Profile
	err := json.Unmarshal(p, &profile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	var query [][]string
	query = append(query, []string{"email", profile.Email})
	query = append(query, []string{"uid", profile.UID})
	query = append(query, []string{"role", profile.Role})

	var params []string
	for _, v := range query {
		params = append(params, v[0]+"="+v[1])
	}
	return strings.Join(params, "&")
}

func encryptProfile(plaintext []byte) ([]byte, error) {
	return crypt.EncryptAesECB(plaintext, []byte(key))
}

func decryptProfile(ciphertext []byte) []byte {
	return crypt.DecryptAes128(ciphertext, []byte(key))
}

func buildPrivEscBlocks(userCiphertext, adminCiphertext []byte) []byte {
	userBlocks := userCiphertext[:32]
	adminBlocks := adminCiphertext[16:32]
	var escBlocks []byte
	escBlocks = append(escBlocks, userBlocks...)
	escBlocks = append(escBlocks, adminBlocks...)
	return escBlocks
}

func main() {
	escalateRole := "admin"
	userProfile, _ := profileFor("pwned@bar.com")

	padAdminProfile, _ := crypt.Pkcs7Pad([]byte(escalateRole), 16)
	padBytes := padAdminProfile[len(escalateRole):len(padAdminProfile)]

	adminByteBlock := []byte("XXXXXXXXXX" + escalateRole)
	adminByteBlock = append(adminByteBlock, padBytes...)

	adminProfile, _ := profileFor(string(adminByteBlock))

	userQuery := []byte(encodeProfile(userProfile))
	adminQuery := []byte(encodeProfile(adminProfile))

	userCiphertext, _ := encryptProfile(userQuery)
	adminCiphertext, _ := encryptProfile(adminQuery)

	userPlaintext := decryptProfile(userCiphertext)

	escCiphertext := buildPrivEscBlocks(userCiphertext, adminCiphertext)
	escPlaintext := decryptProfile(escCiphertext)

	fmt.Println("Original User: " + string(userPlaintext))
	fmt.Println("PrivEsc User: " + string(escPlaintext))
}
