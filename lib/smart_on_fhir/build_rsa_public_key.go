package smart_on_fhir

import (
	"fmt"

	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
)

func buildRSAPublicKey(modulus string, exponent string) (*rsa.PublicKey, error) {
	fmt.Println("===> Modulus:", modulus)
	decodedModulus, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil {
		return &rsa.PublicKey{}, err
	}

	bigN := big.NewInt(0)
	bigN.SetBytes(decodedModulus)
	if err != nil {
		return &rsa.PublicKey{}, err
	}

	decodedExponent, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil {
		return &rsa.PublicKey{}, err
	}

	var eBytes []byte
	if len(decodedExponent) < 8 {
		eBytes = make([]byte, 8-len(decodedExponent), 8)
		eBytes = append(eBytes, decodedExponent...)
	} else {
		eBytes = decodedExponent
	}

	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		return &rsa.PublicKey{}, err
	}
	pKey := rsa.PublicKey{N: bigN, E: int(e)}

	return &pKey, nil
}
