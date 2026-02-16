package signatures

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
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

func init() {
	signaturesCmd.AddCommand(signaturesSignFileCmd)

	signaturesSignFileCmd.Flags().String("priv-out", "priv_key.pem", "PATH TO..")
	signaturesSignFileCmd.Flags().String("signer_id", "", "PATH TO..")
}
func validateSignerId(sID string) error {
	const (
		minSigner = 1
		maxSigner = 65535
	)

	if len(sID) < minSigner || len(sID) > maxSigner {
		return fmt.Errorf("signer takoy nado %d - %d", minSigner, maxSigner)
	}
	return nil
}

var signaturesSignFileCmd = &cobra.Command{
	Use:   "signfile",
	Short: "Sign file",
	Long:  "Siiiiiiiiiiiiiiiign file",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		sID := cmd.Flag("signer_id").Value.String()
		return validateSignerId(sID)
	},
	Run: func(cmd *cobra.Command, args []string) {
		localViper := cmd.Context().Value(config.ViperKey).(*viper.Viper)

		fullPKpath, err := utils.ProcessFilePath(localViper.GetString("priv-out"))
		logger.HaltOnError(err, "failed to process priv key path")

		fullFilepath, err := utils.ProcessFilePath(localViper.GetString("file-path"))
		logger.HaltOnError(err, "failed to process file path")

		digest, err := hashFile(fullFilepath)
		logger.HaltOnError(err, "hash ne ne")

		pk, err := loadPK(fullPKpath)
		logger.HaltOnError(err, "Pk ne ne")

		signaure, err := signDigest(digest, pk)
		logger.HaltOnError(err, "sign ne ne")

		signaurePackage, err := makeSignaurePackage(signaure, localViper.GetString("signer_id"))
		logger.HaltOnError(err, "signpackege ne ne")

		err = writeSignPackToFile(signaurePackage, fullFilepath)
		logger.HaltOnError(err, "write ne ne")
	},
}

func writeSignPackToFile(signaturePackage []byte, initialFilePath string) error {
	sigFilePath := filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")
	return os.WriteFile(sigFilePath, signaturePackage, 0o644)
}

func makeSignaurePackage(signaure []byte, sIn string) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(sIn))); err != nil {
		return nil, fmt.Errorf("falidet to write signer info length: %v", err)
	}

	if _, err := buf.WriteString(sIn); err != nil {
		return nil, fmt.Errorf("falidet to write signer info: %v", err)
	}

	if _, err := buf.Write(signaure); err != nil {
		return nil, fmt.Errorf("falidet to write signaure: %v", err)
	}
	return buf.Bytes(), nil
}

func signDigest(digest []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	}
	signaure, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA3_256, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign")
	}

	return signaure, nil
}

func decodePEMFile(pkPath string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file: %v", err)
	}
	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM file")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("failed to decode PEM file extra ata tut")
	}
	return block, nil
}

func getSaltAndNonce(block *pem.Block) ([]byte, []byte, error) {
	nonceb63, ok := block.Headers["Nonce"]
	if !ok {
		return nil, nil, fmt.Errorf("nonce not found in PEM headers")
	}
	saltb63, ok := block.Headers["Salt"]
	if !ok {
		return nil, nil, fmt.Errorf("salt not found in PEM headers")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceb63)
	if !ok {
		return nil, nil, fmt.Errorf("fail to decode nonce: %v", err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltb63)
	if !ok {
		return nil, nil, fmt.Errorf("fail to decode nonce: %v", err)
	}

	return salt, nonce, nil
}

func loadPK(pkPath string) (*rsa.PrivateKey, error) {
	block, err := decodePEMFile(pkPath)
	if err != nil {
		return nil, err
	}

	salt, nonce, err := getSaltAndNonce(block)
	if err != nil {
		return nil, err
	}

	pass, err := utils.GetPass()
	if err != nil {
		return nil, err
	}

	key, err := crypto_utils.DerKey(crypto_utils.KeyDeConf{
		Pass: pass,
		Salt: salt,
	})
	logger.HaltOnError(err)

	crypter, err := crypto_utils.Crypter(key)
	if err != nil {
		return nil, fmt.Errorf("failed to make crypter: %v", err)
	}

	plaintext, err := crypter.Open(nil, []byte(nonce), block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open PKfile: %v", err)
	}

	pk, err := x509.ParsePKCS1PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKfile: %v", err)
	}

	return pk, nil
}
