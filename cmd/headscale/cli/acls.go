package cli

import (
	"encoding/json"
	"fmt"

	"github.com/ori-edge/headscale"
	v1 "github.com/ori-edge/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

func init() {
	aclCmd.PersistentFlags().StringP("user", "u", "", "User")
	rootCmd.AddCommand(aclCmd)
	aclCmd.AddCommand(createACLcmd)
}

var aclCmd = &cobra.Command{
	Use:     "acls",
	Short:   "Manage the acls of Headscale",
	Aliases: []string{"acl"},
}

var createACLcmd = &cobra.Command{
	Use:     "create POLICY",
	Short:   "Creates a new acl policy for the given user",
	Aliases: []string{"c", "new"},
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errMissingParameter
		}

		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")

		user, err := cmd.Flags().GetString("user")
		if err != nil {
			ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)

			return
		}

		var policy headscale.ACLPolicy

		err = json.Unmarshal([]byte(args[0]), &policy)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Invalid acl policy: %s",
					status.Convert(err).Message(),
				),
				output,
			)
		}

		ctx, client, conn, cancel := getHeadscaleCLIClient()
		defer cancel()
		defer conn.Close()

		log.Trace().Interface("client", client).Msg("Obtained gRPC client")

		request := &v1.CreateACLPolicyRequest{User: user, AclPolicy: policy.ToProto()}

		log.Trace().Interface("request", request).Msg("Sending CreateACLPolicy request")
		response, err := client.CreateACLPolicy(ctx, request)
		if err != nil {
			ErrorOutput(
				err,
				fmt.Sprintf(
					"Cannot create acl: %s",
					status.Convert(err).Message(),
				),
				output,
			)

			return
		}

		SuccessOutput(response, "acl created", output)
	},
}
