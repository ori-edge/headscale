package integration

import (
	v1 "github.com/ori-edge/headscale/gen/go/headscale/v1"
	"github.com/ory/dockertest/v3"
)

type ControlServer interface {
	Shutdown() error
	SaveLog(string) error
	Execute(command []string) (string, error)
	ConnectToNetwork(network *dockertest.Network) error
	GetHealthEndpoint() string
	GetEndpoint() string
	WaitForReady() error
	CreateUser(user string) error
	CreateACLPolicy(user string, policy string) error
	CreateAuthKey(
		user string,
		reusable bool,
		ephemeral bool,
		tags []string,
	) (*v1.PreAuthKey, error)
	ListMachinesInUser(user string) ([]*v1.Machine, error)
	GetCert() []byte
	GetHostname() string
	GetIP() string
}
