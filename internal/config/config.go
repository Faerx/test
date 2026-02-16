package config

import (
	"fmt"
	"sos/internal/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type ContexKey uint

const ViperKey ContexKey = 0

func LoadYamlConfig() (*viper.Viper, error) {
	localViper := viper.New()
	localViper.SetConfigName("config")
	localViper.SetConfigType("yaml")
	localViper.AddConfigPath(".")

	err := localViper.ReadInConfig()

	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			logger.Info("Conf not found? using default")
		} else {
			return localViper, fmt.Errorf("file estb, no choto nasrano... %v", err)
		}
	}
	return localViper, nil
}

func BindFlags(cmd *cobra.Command, v *viper.Viper) error {
	var firstErr error

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if err := v.BindPFlag(flag.Name, flag); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("error binding flag '%s': %v", flag.Name, err)
			}
			logger.Warn(err)
		}
		if !flag.Changed && v.IsSet(flag.Name) {
			if err := cmd.Flags().Set(flag.Name, v.GetString(flag.Name)); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("error satting flag '%s' from conf: %v", flag.Name, err)
				}
				logger.Warn(err)
			}
		}
	})

	return firstErr
}
