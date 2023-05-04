package headscale

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	v1 "github.com/ori-edge/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"
)

var (
	errDuplicateGroup        = errors.New("duplicate group in acl policy")
	errDuplicateHost         = errors.New("duplicate host in acl policy")
	errDuplicateTagOwner     = errors.New("duplicate tag owner in acl policy")
	errDuplicateAutoApprover = errors.New("duplicate auto approver in acl policy")
	errInvalidCIDRBlock      = errors.New("invalid cidr block")
	errUnknownACLACtion      = errors.New("unknown ACL action")
)

// ACLPolicy represents a Tailscale ACL Policy.
type ACLPolicy struct {
	Groups        Groups        `json:"groups"        yaml:"groups"`
	Hosts         Hosts         `json:"hosts"         yaml:"hosts"`
	TagOwners     TagOwners     `json:"tagOwners"     yaml:"tagOwners"`
	ACLs          []ACL         `json:"acls"          yaml:"acls"`
	Tests         []ACLTest     `json:"tests"         yaml:"tests"`
	AutoApprovers AutoApprovers `json:"autoApprovers" yaml:"autoApprovers"`
	SSHs          []SSH         `json:"ssh"           yaml:"ssh"`
}

// ACL is a basic rule for the ACL Policy.
type ACL struct {
	Action       string   `json:"action" yaml:"action"`
	Protocol     string   `json:"proto"  yaml:"proto"`
	Sources      []string `json:"src"    yaml:"src"`
	Destinations []string `json:"dst"    yaml:"dst"`
}

// Groups references a series of alias in the ACL rules.
type Groups map[string][]string

// Hosts are alias for IP addresses or subnets.
type Hosts map[string]netip.Prefix

// TagOwners specify what users (users?) are allow to use certain tags.
type TagOwners map[string][]string

// ACLTest is not implemented, but should be use to check if a certain rule is allowed.
type ACLTest struct {
	Source string   `json:"src"            yaml:"src"`
	Accept []string `json:"accept"         yaml:"accept"`
	Deny   []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}

// AutoApprovers specify which users (users?), groups or tags have their advertised routes
// or exit node status automatically enabled.
type AutoApprovers struct {
	Routes   map[string][]string `json:"routes"   yaml:"routes"`
	ExitNode []string            `json:"exitNode" yaml:"exitNode"`
}

// SSH controls who can ssh into which machines.
type SSH struct {
	Action       string   `json:"action"                yaml:"action"`
	Sources      []string `json:"src"                   yaml:"src"`
	Destinations []string `json:"dst"                   yaml:"dst"`
	Users        []string `json:"users"                 yaml:"users"`
	CheckPeriod  string   `json:"checkPeriod,omitempty" yaml:"checkPeriod,omitempty"`
}

// UnmarshalJSON allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalJSON(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)
	ast, err := hujson.Parse(data)
	if err != nil {
		return err
	}
	ast.Standardize()
	data = ast.Pack()
	err = json.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		if !strings.Contains(prefixStr, "/") {
			prefixStr += "/32"
		}
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// UnmarshalYAML allows to parse the Hosts directly into netip objects.
func (hosts *Hosts) UnmarshalYAML(data []byte) error {
	newHosts := Hosts{}
	hostIPPrefixMap := make(map[string]string)

	err := yaml.Unmarshal(data, &hostIPPrefixMap)
	if err != nil {
		return err
	}
	for host, prefixStr := range hostIPPrefixMap {
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			return err
		}
		newHosts[host] = prefix
	}
	*hosts = newHosts

	return nil
}

// IsZero is perhaps a bit naive here.
func (policy ACLPolicy) IsZero() bool {
	if len(policy.Groups) == 0 && len(policy.Hosts) == 0 && len(policy.ACLs) == 0 {
		return true
	}

	return false
}

// Returns the list of autoApproving users, groups or tags for a given IPPrefix.
func (autoApprovers *AutoApprovers) GetRouteApprovers(
	prefix netip.Prefix,
) ([]string, error) {
	if prefix.Bits() == 0 {
		return autoApprovers.ExitNode, nil // 0.0.0.0/0, ::/0 or equivalent
	}

	approverAliases := []string{}

	for autoApprovedPrefix, autoApproverAliases := range autoApprovers.Routes {
		autoApprovedPrefix, err := netip.ParsePrefix(autoApprovedPrefix)
		if err != nil {
			return nil, err
		}

		if prefix.Bits() >= autoApprovedPrefix.Bits() &&
			autoApprovedPrefix.Contains(prefix.Masked().Addr()) {
			approverAliases = append(approverAliases, autoApproverAliases...)
		}
	}

	return approverAliases, nil
}

func (policy ACLPolicy) ToProto() *v1.ACLPolicy {
	protoACLs := make([]*v1.ACL, len(policy.ACLs))
	for i, rule := range policy.ACLs {
		protoACLs[i] = &v1.ACL{
			// defaults to UNKNOWN if the action is invalid
			Action: v1.ACL_Action(
				v1.ACL_Action_value[strings.ToUpper(rule.Action)],
			),
			// defaults to ANY if the protocol is not known
			Protocol: v1.Protocol_Enum(
				v1.Protocol_Enum_value[strings.ToUpper(rule.Protocol)],
			),
			Sources:      rule.Sources,
			Destinations: rule.Destinations,
		}
	}

	protoGroups := make([]*v1.ACLGroup, 0, len(policy.Groups))
	for name, users := range policy.Groups {
		protoGroups = append(protoGroups, &v1.ACLGroup{
			Name:  name,
			Users: users,
		})
	}

	protoHosts := make([]*v1.ACLHost, 0, len(policy.Hosts))
	for name, prefix := range policy.Hosts {
		protoHosts = append(protoHosts, &v1.ACLHost{
			Name:      name,
			CidrBlock: prefix.String(),
		})
	}

	protoTagOwners := make([]*v1.ACLTagOwner, 0, len(policy.TagOwners))
	for tag, users := range policy.TagOwners {
		protoTagOwners = append(protoTagOwners, &v1.ACLTagOwner{
			Tag:   tag,
			Users: users,
		})
	}

	protoRoutes := make([]*v1.ACLRoutes, 0, len(policy.AutoApprovers.Routes))
	for route, users := range policy.AutoApprovers.Routes {
		protoRoutes = append(protoRoutes, &v1.ACLRoutes{
			Route: route,
			Users: users,
		})
	}

	return &v1.ACLPolicy{
		Groups:    protoGroups,
		Hosts:     protoHosts,
		TagOwners: protoTagOwners,
		Acls:      protoACLs,
		AutoApprovers: &v1.ACLAutoApprovers{
			ExitNodes: policy.AutoApprovers.ExitNode,
			Routes:    protoRoutes,
		},
	}
}

func aclFromProto(inACL *v1.ACLPolicy) (ACLPolicy, error) {
	out := ACLPolicy{}

	out.Groups = make(map[string][]string, len(inACL.GetGroups()))
	for _, group := range inACL.GetGroups() {
		if _, exists := out.Groups[group.Name]; exists {
			return out, errDuplicateGroup
		}
		out.Groups[group.Name] = group.Users
	}

	out.Hosts = make(map[string]netip.Prefix, len(inACL.GetHosts()))
	for _, host := range inACL.GetHosts() {
		if _, exists := out.Hosts[host.Name]; exists {
			return out, errDuplicateHost
		}
		prefixStr := host.CidrBlock
		if !strings.Contains(prefixStr, "/") {
			prefixStr += "/32"
		}
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			log.Error().
				Caller().
				Str("cidrBlock", host.CidrBlock).
				Err(err)

			return out, errInvalidCIDRBlock
		}
		out.Hosts[host.Name] = prefix
	}

	for _, acl := range inACL.GetAcls() {
		if acl.GetAction() == v1.ACL_UNKNOWN {
			log.Error().
				Caller().
				Interface("aclPolicy", inACL).
				Msg("Unknown ACL action")

			return out, errUnknownACLACtion
		}
		protocol := ""
		if acl.Protocol != v1.Protocol_ANY {
			protocol = strings.ToLower(acl.Protocol.String())
		}
		out.ACLs = append(out.ACLs, ACL{
			Action:       strings.ToLower(acl.Action.String()),
			Protocol:     protocol,
			Sources:      acl.Sources,
			Destinations: acl.Destinations,
		})
	}

	out.TagOwners = make(map[string][]string, len(inACL.GetTagOwners()))
	for _, tagOwner := range inACL.GetTagOwners() {
		if _, exists := out.TagOwners[tagOwner.Tag]; exists {
			return out, errDuplicateTagOwner
		}
		out.TagOwners[tagOwner.Tag] = tagOwner.Users
	}

	out.AutoApprovers.Routes = make(
		map[string][]string,
		len(inACL.GetAutoApprovers().GetRoutes()),
	)
	for _, autoApproverRoutes := range inACL.GetAutoApprovers().GetRoutes() {
		if _, exists := out.AutoApprovers.Routes[autoApproverRoutes.Route]; exists {
			return out, errDuplicateAutoApprover
		}
		out.AutoApprovers.Routes[autoApproverRoutes.Route] = autoApproverRoutes.Users
	}

	out.AutoApprovers.ExitNode = inACL.GetAutoApprovers().GetExitNodes()

	return out, nil
}
