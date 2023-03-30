package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "cardano-signer",
	Short:         "A CLI application to manage signing messages in Cardano.",
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// if rootCmd.Execute() != nil {
	// 	os.Exit(1)
	// }
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	// rootCmd.Flags().Bool("cip8", false, "Use CIP8 (COSE)")
	// rootCmd.Flags().Bool("cip30", false, "Use CIP30 (COSE)")
	rootCmd.Flags().Bool("cip22", false, "Use CIP22 (VRF keys)")
	rootCmd.Flags().String("data", "", "message to sign/verify")
	rootCmd.Flags().String("nonce", "", "a lower-case hex string (optional)")
	rootCmd.Flags().Bool("json", false, "Output formatted as JSON")
}
