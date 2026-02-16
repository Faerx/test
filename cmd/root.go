package cmd

import (
	"context"
	"fmt"
	"os"
	"sos/cmd/keys"
	"sos/cmd/signatures"
	"sos/internal/config"
	"sos/internal/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var version = "dev"

func RootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "brave_signer",
		Short:        "generated key",
		Long:         "geeeeeeeeeeeeeeeeeenerated key",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, ars []string) error {
			return initializeConfig(cmd)
		},
	}

	keys.Init(rootCmd)
	signatures.Init(rootCmd)

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of L7",
		Long:  "Priiiiiiiiiiiiiiint the version number of L7",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("L7 version:", version)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:    "gendocs",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := generateDocs(rootCmd, "./docs"); err != nil {
				logger.Warn(fmt.Errorf("error generating docs: %v", err))
			}
		},
	})
	return rootCmd
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return doc.GenMarkdownTree(rootCmd, dir)
}

func initializeConfig(cmd *cobra.Command) error {
	localViper, err := config.LoadYamlConfig()
	if err != nil {
		return err
	}

	if err := config.BindFlags(cmd, localViper); err != nil {
		return err
	}

	ctx := context.WithValue(cmd.Context(), config.ViperKey, localViper)
	cmd.SetContext(ctx)
	return nil
}
