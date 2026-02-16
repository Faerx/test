package signatures

import (
	"crypto/sha3"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var signaturesCmd = &cobra.Command{
	Use:   "signatures",
	Short: "Create signatures",
	Long:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

func Init(rootCmd *cobra.Command) {
	rootCmd.AddCommand(signaturesCmd)

	signaturesCmd.PersistentFlags().String("file-path", "", "Path to the file that should be signed")
}

func hashFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("ne open file %s: %v", filePath, err)
	}

	defer file.Close()

	hasher := sha3.New256()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("error while hashing file %s: %v", filePath, err)
	}

	return hasher.Sum(nil), nil
}
