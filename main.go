package main

import (
    "errors"
    "os"
    "time"

    "github.com/bytejedi/ipsec-forward/ipsec"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

const flagDestination = "destination"

func main() {
    rootCmd := &cobra.Command{
        Use:   "ipsecfwd",
        Short: "ipsecfwd is a IPSEC packets forwarder",
        Long: `forward IPSEC packets like a reverse NAT & supports multiple users`,
        RunE: func(cmd *cobra.Command, args []string) error {
            dstIPs := viper.GetStringSlice(flagDestination)
            if len(dstIPs) == 0 {
               return errors.New("destination IPs required")
            }

            _, err := ipsec.Forward("0.0.0.0:4500", "0.0.0.0:4500", time.Second*10)
            if err != nil {
                return err
            }
            select {}
        },
    }
    rootCmd.Flags().StringSliceP(flagDestination, "d", []string{}, "Set destination IPs to forward to")
    viper.BindPFlag(flagDestination, rootCmd.Flags().Lookup(flagDestination))

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
