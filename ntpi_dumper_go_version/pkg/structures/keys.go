// Package structures - AES key mappings for different firmware versions
package structures

import "fmt"

// AESKeyDict represents a set of AES keys and IVs for one firmware version
type AESKeyDict struct {
	Version string
	Keys    map[string]string // key_1 to key_5
	IVs     map[string]string // iv_1 to iv_5
}

// AES keys for firmware version 1.3.0
var AESDict_V1_3_0 = &AESKeyDict{
	Version: "1.3.0",
	Keys: map[string]string{
		"key_1": "08ed9260dec3807aac3ec00e765186cf4b9c677601ba844f8ec3e8c2fe1e11cb",
		"key_2": "7cec0ee7e63a703197afa8e09ce40f9b10a5fded6e5f04cb4ba7a435ed600288",
		"key_3": "76fa1a8d6663aae8b964470c384508f7f974d21af2535cd3549c7c51ed68b0e6",
		"key_4": "1c37c2a0b579512481e8529532909c7c1be72f9bb5e1a4610328a5e2b67c10f4",
		"key_5": "4ae22e3ae6ff0b65d06fa18df4f99ae59e6a90cb92ca03de65b64fc0fac958ce",
	},
	IVs: map[string]string{
		"iv_1": "0797205f6b02c0232cd2798795ba588d",
		"iv_2": "01c5aaae7c4001592ea6a2310364a9a1",
		"iv_3": "de930fcc2c37009400e21dfa9f7d1363",
		"iv_4": "ab15d90ce88a83680a4074d5bb96d94c",
		"iv_5": "eaaa17604ad7dae5773639c217978da5",
	},
}

// VersionKeyMap maps version tuples to their key dictionaries
var VersionKeyMap = map[string]*AESKeyDict{
	"1.3.0": AESDict_V1_3_0,
	// Add more versions here as needed:
	// "1.4.0": AESDict_V1_4_0,
}

// DefaultAESDict is used when version is not recognized
var DefaultAESDict = AESDict_V1_3_0

// GetAESDictForVersion returns the AES key dictionary for a specific version
func GetAESDictForVersion(major, minor, patch uint64) *AESKeyDict {
	version := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	// Try exact match
	if dict, ok := VersionKeyMap[version]; ok {
		return dict
	}

	// Try partial match (major.minor)
	partialVersion := fmt.Sprintf("%d.%d", major, minor)
	for key, dict := range VersionKeyMap {
		if len(key) >= len(partialVersion) && key[:len(partialVersion)] == partialVersion {
			return dict
		}
	}

	// Return default if no match found
	return DefaultAESDict
}

// GetKeyForRegion returns the AES key for a specific region type
func (d *AESKeyDict) GetKeyForRegion(regionType uint64) string {
	keyName := fmt.Sprintf("key_%d", regionType)
	if key, ok := d.Keys[keyName]; ok {
		return key
	}
	return ""
}

// GetIVForRegion returns the IV for a specific region type
func (d *AESKeyDict) GetIVForRegion(regionType uint64) string {
	ivName := fmt.Sprintf("iv_%d", regionType)
	if iv, ok := d.IVs[ivName]; ok {
		return iv
	}
	return ""
}
