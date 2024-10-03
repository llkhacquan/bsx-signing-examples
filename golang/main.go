package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// Domain can be fetched from:
// mainnet: curl -s https://api.bsx.exchange/chain/configs | jq .main
// testnet: curl -s https://api.testnet.bsx.exchange/chain/configs | jq .main
type Domain struct {
	Name              string `mapstructure:"name"`               // example: "BSX Mainnet"
	Version           string `mapstructure:"version"`            // example: "1" (not that it's a string, not an integer)
	ChainID           string `mapstructure:"chain_id"`           // should be the same as chain.id, example "8453"; MUST be an INTEGER string
	VerifyingContract string `mapstructure:"verifying_contract"` // address prefixed with 0x; example 0x0000000000000000000000000000000000000002
}

type Order struct {
	// address prefixed with 0x; example 0x0000000000000000000000000000000000000001
	Sender string `json:"sender"`
	// INTEGER string representation of the size in wei (need x10^18); example: for 1.23 ETH we need to put "1230000000000000000"
	// We use string because int64 can't hold too large numbers
	Size string `json:"size"`
	// INTEGER string representation of the price in wei (need x10^18); example for 123.4 USDC we need to put "123400000000000000000"
	// We use string because int64 can't hold too large numbers
	Price        string `json:"price"`
	Nonce        uint64 `json:"nonce"`         // should be ~ current nano timestamp; so using uint64 is enough
	ProductIndex uint8  `json:"product_index"` // BTC-1; ETH-2; etc; note that 0 is not a valid product index
	Side         uint8  `json:"side"`          // 0 for buy, 1 for sell
}

// ManuallySignOrder is the manual implementation of the EIP-712 signing algorithm, without typed-data
func ManuallySignOrder(privateKey *ecdsa.PrivateKey, domain Domain, order Order) ([]byte, error) {
	domainSeparator, err := hashTypedDataDomain(domain)
	if err != nil {
		return nil, err
	}
	fmt.Printf("domainSeparator: %x\n", domainSeparator)
	typedDataHash := hashOrder(order)
	fmt.Printf("typedDataHash: %x\n", typedDataHash)

	// Calculate the final data hash that needs to be signed: keccak256("\x19\x01" + domainSeparator + typedDataHash)
	data := append([]byte("\x19\x01"), domainSeparator.Bytes()...)
	data = append(data, typedDataHash.Bytes()...)

	// Calculate Keccak-256 hash of the data to ensure it's exactly 32 bytes
	hash := crypto.Keccak256(data)

	// Sign calculates an ECDSA signature.
	//This function is susceptible to chosen plaintext attacks that can leak information about the private key that is used for signing. Callers must be aware that the given digest cannot be chosen by an adversary. Common solution is to hash any input before calculating the signature.
	//The produced signature is in the [R || S || V] format where V is 0 or 1.
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}

	// Ethereum's signature formatting: add 27 to recovery id (v) to conform with the standard
	signature[64] += 27
	return signature, nil
}

// hashTypedDataDomain compute the domain separator hash for the given TypedDataDomain.
// note that we only use `name`, `version`, `chainId`, and `verifyingContract` fields from the domain.
// `salt` is not used in the hash.
// "EIP712Domain": [
//
//	  {
//	    "name": "name",
//	    "type": "string"
//	  },
//	  {
//	    "name": "version",
//	    "type": "string"
//	  },
//	  {
//	    "name": "chainId",
//	    "type": "uint256"
//	  },
//	  {
//	    "name": "verifyingContract",
//	    "type": "address"
//	  }
//	]
func hashTypedDataDomain(domain Domain) (common.Hash, error) {
	// this string is constant and derived from the EIP712 standard
	// we should not mess with it: adding new spaces, changing the order of the fields, changing the case of the letters, etc.
	// for better performance, we can precompute the hash of this string and use it in the future
	domainTypeHash := crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))

	// Name and Version are string, we can just convert them to bytes and hash them directly
	nameHash := crypto.Keccak256Hash([]byte(domain.Name))
	versionHash := crypto.Keccak256Hash([]byte(domain.Version))

	// For big.Int, we need to use BigToHash to convert it to common.Hash
	chainID, err := strconv.Atoi(domain.ChainID)
	if err != nil {
		return [32]byte{}, err
	}
	chainIDHash := common.BigToHash(big.NewInt(int64(chainID)))

	// encode VerifyingContract (an address) as an 32 bytes array
	// An address is 20 bytes, so we need simply add 12 bytes of 0 to the left of the address
	verifyingContract := common.HexToAddress(domain.VerifyingContract)
	verifyingContractHash := common.BytesToHash(verifyingContract.Bytes())

	// Concatenate all the hashes
	// the order of the fields is important, the same as the order in the domainTypeHash
	encodedData := append(domainTypeHash.Bytes(), nameHash.Bytes()...)
	encodedData = append(encodedData, versionHash.Bytes()...)
	encodedData = append(encodedData, chainIDHash.Bytes()...)
	encodedData = append(encodedData, verifyingContractHash.Bytes()...)

	// Hash the final concatenated data
	return crypto.Keccak256Hash(encodedData), nil
}

func hashOrder(order Order) common.Hash {
	// Type hash for the Order type
	typeHash := crypto.Keccak256Hash([]byte("Order(address sender,uint128 size,uint128 price,uint64 nonce,uint8 productIndex,uint8 orderSide)"))

	// Hash the individual fields with proper padding
	senderHash := common.BytesToHash(common.HexToAddress(order.Sender).Bytes())                             // 20 bytes, already left-padded
	sizeHash := intStringTO32Bytes(order.Size)                                                              // encode size as 0-padded 32 bytes integer
	priceHash := intStringTO32Bytes(order.Price)                                                            // encode price as 0-padded 32 bytes integer
	nonceHash := padTo32Bytes(math.U256(new(big.Int).SetUint64(order.Nonce)).Bytes())                       // encode nonce as 0-padded 32 bytes integer
	productIndexHash := padTo32Bytes(math.U256(new(big.Int).SetUint64(uint64(order.ProductIndex))).Bytes()) // encode product index as 0-padded 32 bytes integer
	orderSideHash := padTo32Bytes([]byte{order.Side})                                                       // encode order side as 0-padded 32 bytes integer

	// Concatenate all the fields (ordering is important)
	encodedData := append(typeHash.Bytes(), senderHash.Bytes()...)
	encodedData = append(encodedData, sizeHash...)
	encodedData = append(encodedData, priceHash...)
	encodedData = append(encodedData, nonceHash...)
	encodedData = append(encodedData, productIndexHash...)
	encodedData = append(encodedData, orderSideHash...)

	// Final hash of the entire struct
	return crypto.Keccak256Hash(encodedData)
}

func intStringTO32Bytes(s string) []byte {
	i, _ := new(big.Int).SetString(s, 10)
	return padTo32Bytes(i.Bytes())
}

func padTo32Bytes(b []byte) []byte {
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func main0() error {
	domain := Domain{
		Name:              "BSX Testnet",
		Version:           "1",
		ChainID:           "8453",
		VerifyingContract: "0x0000000000000000000000000000000000000002",
	}
	order := Order{
		Sender:       "0x0000000000000000000000000000000000000001",
		Size:         "1230000000000000000",
		Price:        "123400000000000000000",
		Nonce:        1632816000000000000,
		ProductIndex: 1,
		Side:         0,
	}
	privateKeyRaw := "0000000000000000000000000000000000000000000000000000000000000001" // use dummy private key
	privateKey, err := crypto.HexToECDSA(privateKeyRaw)
	if err != nil {
		return err
	}
	signOrder, err := ManuallySignOrder(privateKey, domain, order)
	if err != nil {
		return err
	}
	fmt.Printf("Signature: %x\n", signOrder)
	return nil
}

func main() {
	if err := main0(); err != nil {
		log.Fatal(err)
	}

	//domainSeparator: 452197ade50f91a3e8593509e6cbf206700b274eaa41dc959a141a499d1943ef
	//typedDataHash: fbea394814ee65e1fcdcd78ecef18fb69fb58f0ba604903b2eec33cd676c446e
	//Signature: 8cc51c73e31b54427e638fdc195601b1244e4db6be3d0af9661c058f697709ec5652fdb52ba7c8d7f808e05f7c509b3db7c7acb075164f993b1fb60da85596571c
}
