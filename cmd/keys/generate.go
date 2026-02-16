package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sos/internal/config"
	"sos/internal/logger"
	"sos/pkg/crypto_utils"
	"sos/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type PrKenGen struct {
	outputPath string
	keyBitSize int
	saltSize   int
}

func init() {
	keysCmd.AddCommand(keyGenCmd)

	keyGenCmd.Flags().String("pub-key-path", "pub_key.pem", "Path to save pub")
	keyGenCmd.Flags().String("priv-out", "priv_out.pem", "Path to save priv")
	keyGenCmd.Flags().Int("priv-size", 2048, " priv key size")
	keyGenCmd.Flags().Int("salt-size", 16, " salt for priv key size")
}

var keyGenCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generates key",
	Long:  "Geneeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeerates key",
	Run: func(cmd *cobra.Command, args []string) {

		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		pkGenConf := PrKenGen{
			outputPath: localViper.GetString("priv-out"),
			keyBitSize: localViper.GetInt("priv-size"),
			saltSize:   localViper.GetInt("salt-size"),
		}

		pK, err := generPrivKey(pkGenConf)
		logger.HaltOnError(err)

		err = generatePubKey(localViper.GetString("pub-key-path"), pK)
		logger.HaltOnError(err)
	},
}

func generatePubKey(path string, privK *rsa.PrivateKey) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		fmt.Print(1)
		return fmt.Errorf("fail to get abspath: %v", err)
	}
	pubS, err := x509.MarshalPKIXPublicKey(&privK.PublicKey)
	if err != nil {
		fmt.Print(2)
		return fmt.Errorf("fail to get open key: %w", err)
	}

	file, err := os.Create(absPath)
	if err != nil {
		fmt.Print(3)
		return fmt.Errorf("failed to create pub file %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "PUBKEY", Bytes: pubS}); err != nil {
		fmt.Print(4)
		return fmt.Errorf("failed to encode pub  %w", err)
	}
	fmt.Print(5)
	return nil
}
func generPrivKey(pkGenConf PrKenGen) (*rsa.PrivateKey, error) {
	absPath, err := filepath.Abs(pkGenConf.outputPath)
	if err != nil {
		return nil, fmt.Errorf("fail to get path: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, pkGenConf.keyBitSize)
	if err != nil {
		return nil, fmt.Errorf("fail to gen key: %w", err)
	}

	pass, err := utils.GetPass()
	if err != nil {
		return nil, err
	}

	pKB := x509.MarshalPKCS1PrivateKey(privateKey)

	salt, err := makeSalt(pkGenConf.saltSize)
	if err != nil {
		return nil, err
	}

	key, err := crypto_utils.DerKey(crypto_utils.KeyDeConf{
		Pass: pass,
		Salt: salt,
	})
	if err != nil {
		return nil, err
	}

	crypted, err := crypto_utils.Crypter(key)
	if err != nil {
		return nil, err
	}

	nonce, err := crypto_utils.MkN(crypted)
	if err != nil {
		return nil, err
	}

	encData := crypted.Seal(nil, nonce, pKB, nil)

	encPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encData,
		Headers: map[string]string{
			"Nonce": base64.StdEncoding.EncodeToString(nonce),
			"Salt":  base64.StdEncoding.EncodeToString(salt),
			"KDF":   "Argon2",
		},
	}

	err = sPKtoPEM(absPath, encPem)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
func sPKtoPEM(absPath string, encPem *pem.Block) error {
	file, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("failed to create pk file %v", err)
	}
	defer file.Close()

	if err := pem.Encode(file, encPem); err != nil {
		return fmt.Errorf("failed to encode pk  %w", err)
	}
	return nil
}
func makeSalt(ms int) ([]byte, error) {
	salr := make([]byte, ms)
	if _, err := rand.Read(salr); err != nil {
		return nil, fmt.Errorf("fail in salt: %v", err)
	}
	return salr, nil
}
