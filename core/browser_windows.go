package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"extract-browser-data/core/decrypt"
	"extract-browser-data/utils"

	"github.com/tidwall/gjson"
)

const (
	chromeProfilePath     = "/AppData/Local/Google/Chrome/User Data/*/"
	chromeKeyPath         = "/AppData/Local/Google/Chrome/User Data/Local State"
	chromeBetaProfilePath = "/AppData/Local/Google/Chrome Beta/User Data/*/"
	chromeBetaKeyPath     = "/AppData/Local/Google/Chrome Beta/User Data/Local State"
	chromiumProfilePath   = "/AppData/Local/Chromium/User Data/*/"
	chromiumKeyPath       = "/AppData/Local/Chromium/User Data/Local State"
)

var (
	browserList = map[string]struct {
		ProfilePath string
		Name        string
		KeyPath     string
		Storage     string
		New         func(profile, key, name, storage string) (Browser, error)
	}{
		"chrome": {
			ProfilePath: os.Getenv("USERPROFILE") + chromeProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromeKeyPath,
			Name:        chromeName,
			New:         NewChromium,
		},
		"chrome-beta": {
			ProfilePath: os.Getenv("USERPROFILE") + chromeBetaProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromeBetaKeyPath,
			Name:        chromeBetaName,
			New:         NewChromium,
		},
		"chromium": {
			ProfilePath: os.Getenv("USERPROFILE") + chromiumProfilePath,
			KeyPath:     os.Getenv("USERPROFILE") + chromiumKeyPath,
			Name:        chromiumName,
			New:         NewChromium,
		},
	}
)

var (
	errBase64DecodeFailed = errors.New("decode base64 failed")
)

// InitSecretKey with win32 DPAPI
// conference from @https://gist.github.com/akamajoris/ed2f14d817d5514e7548
func (c *Chromium) InitSecretKey() error {
	if c.keyPath == "" {
		return nil
	}
	if _, err := os.Stat(c.keyPath); os.IsNotExist(err) {
		return fmt.Errorf("%s secret key path is empty", c.name)
	}
	keyFile, err := utils.ReadFile(c.keyPath)
	if err != nil {
		return err
	}
	encryptedKey := gjson.Get(keyFile, "os_crypt.encrypted_key")
	if encryptedKey.Exists() {
		pureKey, err := base64.StdEncoding.DecodeString(encryptedKey.String())
		if err != nil {
			return errBase64DecodeFailed
		}
		c.secretKey, err = decrypt.DPApi(pureKey[5:])
		return err
	}
	return nil
}
