package trafficpolicy

import (
	"fmt"
	"slices"

	envoy_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/kube/krt"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/kgateway/extensions2/pluginutils"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/filters"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
	"github.com/kgateway-dev/kgateway/v2/pkg/utils/cmputils"
)

const (
	// extProcFilterPrefix is the prefix for the ExtProc filter name
	extProcFilterPrefix = "ext_proc/"

	// extProcGlobalDisableFilterName is the name of the filter for ExtProc that disables all ExtProc providers
	extProcGlobalDisableFilterName = "global_disable/ext_proc"

	// extProcGlobalDisableFilterMetadataNamespace is the metadata namespace for the global disable ExtProc filter
	extProcGlobalDisableFilterMetadataNamespace = "dev.kgateway.disable_ext_proc"
)

type extprocIR struct {
	perProviderConfig   []*perProviderExtProcConfig
	disableAllProviders bool
	// providerNames is used to track duplicates during policy merging,
	// and has no relevance to the policy config, so it can be excluded from Equals
	// +noKrtEquals
	providerNames sets.Set[string]
}

type perProviderExtProcConfig struct {
	provider       *TrafficPolicyGatewayExtensionIR
	perRouteConfig *envoy_ext_proc_v3.ExtProcPerRoute
	filterStage    filters.FilterStage[filters.WellKnownFilterStage]
}

var _ PolicySubIR = &extprocIR{}

func (e *extprocIR) Equals(other PolicySubIR) bool {
	otherExtProc, ok := other.(*extprocIR)
	if !ok {
		return false
	}
	if e == nil || otherExtProc == nil {
		return e == nil && otherExtProc == nil
	}
	if e.disableAllProviders != otherExtProc.disableAllProviders {
		return false
	}
	if !slices.EqualFunc(e.perProviderConfig, otherExtProc.perProviderConfig, func(a, b *perProviderExtProcConfig) bool {
		// compare filterStage
		if a.filterStage != b.filterStage {
			return false
		}
		// compare perRouteConfig
		return proto.Equal(a.perRouteConfig, b.perRouteConfig) &&
			// compare provider config
			cmputils.CompareWithNils(a.provider, b.provider, func(a, b *TrafficPolicyGatewayExtensionIR) bool {
				return a.Equals(*b)
			})
	}) {
		return false
	}

	return true
}

func (e *extprocIR) Validate() error {
	if e == nil {
		return nil
	}

	for _, p := range e.perProviderConfig {
		if p.perRouteConfig != nil {
			if err := p.perRouteConfig.ValidateAll(); err != nil {
				return err
			}
		}
		if p.provider != nil {
			if err := p.provider.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// constructExtProc constructs the external processing policy IR from the policy specification.
func constructExtProc(
	krtctx krt.HandlerContext,
	in *kgateway.TrafficPolicy,
	fetchGatewayExtension FetchGatewayExtensionFunc,
	out *trafficPolicySpecIr,
) error {
	spec := in.Spec.ExtProc
	if spec == nil {
		return nil
	}

	if spec.Disable != nil {
		out.extProc = &extprocIR{
			disableAllProviders: true,
		}
		return nil
	}

	// Convert API stage config to internal filter stage
	filterStage := convertExtProcStageConfig(spec.Stage)

	// kubebuilder validation ensures the extensionRef is not nil, since disable is nil
	gatewayExtension, err := fetchGatewayExtension(krtctx, *spec.ExtensionRef, in.GetNamespace())
	if err != nil {
		return fmt.Errorf("extproc: %w", err)
	}
	if gatewayExtension.ExtProc == nil {
		return pluginutils.ErrInvalidExtensionType(kgateway.GatewayExtensionTypeExtProc)
	}
	out.extProc = &extprocIR{
		perProviderConfig: []*perProviderExtProcConfig{
			{
				provider:       gatewayExtension,
				perRouteConfig: translateExtProcPerFilterConfig(spec),
				filterStage:    filterStage,
			},
		},
		providerNames: sets.New(providerName(gatewayExtension)),
	}
	return nil
}

// convertExtProcStageConfig converts the API ExtProcStageConfig to a FilterStage.
// Defaults to AfterStage(AuthZStage) if nil or empty.
func convertExtProcStageConfig(cfg *kgateway.ExtProcStageConfig) filters.FilterStage[filters.WellKnownFilterStage] {
	// Default to After AuthZ stage
	if cfg == nil {
		return filters.AfterStage(filters.AuthZStage)
	}

	// Convert stage
	var wellKnownStage filters.WellKnownFilterStage
	switch cfg.Stage {
	case kgateway.ExtProcFilterStageFault:
		wellKnownStage = filters.FaultStage
	case kgateway.ExtProcFilterStageCors:
		wellKnownStage = filters.CorsStage
	case kgateway.ExtProcFilterStageWaf:
		wellKnownStage = filters.WafStage
	case kgateway.ExtProcFilterStageAuthN:
		wellKnownStage = filters.AuthNStage
	case kgateway.ExtProcFilterStageAuthZ:
		wellKnownStage = filters.AuthZStage
	case kgateway.ExtProcFilterStageRateLimit:
		wellKnownStage = filters.RateLimitStage
	case kgateway.ExtProcFilterStageAccepted:
		wellKnownStage = filters.AcceptedStage
	case kgateway.ExtProcFilterStageOutAuth:
		wellKnownStage = filters.OutAuthStage
	case kgateway.ExtProcFilterStageRoute:
		wellKnownStage = filters.RouteStage
	default:
		wellKnownStage = filters.AuthZStage
	}

	// Convert predicate
	switch cfg.Predicate {
	case kgateway.ExtProcFilterPredicateBefore:
		return filters.BeforeStage(wellKnownStage)
	case kgateway.ExtProcFilterPredicateDuring:
		return filters.DuringStage(wellKnownStage)
	case kgateway.ExtProcFilterPredicateAfter:
		return filters.AfterStage(wellKnownStage)
	default:
		return filters.AfterStage(wellKnownStage)
	}
}

func translateExtProcPerFilterConfig(
	extProc *kgateway.ExtProcPolicy,
) *envoy_ext_proc_v3.ExtProcPerRoute {
	overrides := &envoy_ext_proc_v3.ExtProcOverrides{}
	if extProc.ProcessingMode != nil {
		overrides.ProcessingMode = toEnvoyProcessingMode(extProc.ProcessingMode)
	}

	return &envoy_ext_proc_v3.ExtProcPerRoute{
		Override: &envoy_ext_proc_v3.ExtProcPerRoute_Overrides{
			Overrides: overrides,
		},
	}
}

// headerSendModeFromString converts a string to envoy HeaderSendMode
func headerSendModeFromString(mode string) envoy_ext_proc_v3.ProcessingMode_HeaderSendMode {
	switch mode {
	case "SEND":
		return envoy_ext_proc_v3.ProcessingMode_SEND
	case "SKIP":
		return envoy_ext_proc_v3.ProcessingMode_SKIP
	default:
		return envoy_ext_proc_v3.ProcessingMode_DEFAULT
	}
}

// bodySendModeFromString converts a string to envoy BodySendMode
func bodySendModeFromString(mode string) envoy_ext_proc_v3.ProcessingMode_BodySendMode {
	switch mode {
	case "STREAMED":
		return envoy_ext_proc_v3.ProcessingMode_STREAMED
	case "BUFFERED":
		return envoy_ext_proc_v3.ProcessingMode_BUFFERED
	case "BUFFERED_PARTIAL":
		return envoy_ext_proc_v3.ProcessingMode_BUFFERED_PARTIAL
	case "FULL_DUPLEX_STREAMED":
		return envoy_ext_proc_v3.ProcessingMode_FULL_DUPLEX_STREAMED
	default:
		return envoy_ext_proc_v3.ProcessingMode_NONE
	}
}

// toEnvoyProcessingMode converts our ProcessingMode to envoy's ProcessingMode
func toEnvoyProcessingMode(p *kgateway.ProcessingMode) *envoy_ext_proc_v3.ProcessingMode {
	if p == nil {
		return nil
	}

	return &envoy_ext_proc_v3.ProcessingMode{
		RequestHeaderMode:   headerSendModeFromString(p.RequestHeaderMode),
		ResponseHeaderMode:  headerSendModeFromString(p.ResponseHeaderMode),
		RequestBodyMode:     bodySendModeFromString(p.RequestBodyMode),
		ResponseBodyMode:    bodySendModeFromString(p.ResponseBodyMode),
		RequestTrailerMode:  headerSendModeFromString(p.RequestTrailerMode),
		ResponseTrailerMode: headerSendModeFromString(p.ResponseTrailerMode),
	}
}

// defaultExtProcFilterStage is the default filter stage for ExtProc (After AuthZ).
var defaultExtProcFilterStage = filters.AfterStage(filters.AuthZStage)

// extProcFilterName generates a unique filter name based on provider name and filter stage.
// For the default stage (After AuthZ), the format is: ext_proc/{providerName} (backward compatible)
// For non-default stages, the format is: ext_proc/{stage}_{predicate}/{providerName}
func extProcFilterName(name string, filterStage filters.FilterStage[filters.WellKnownFilterStage]) string {
	// Use simple naming for default stage (backward compatible)
	if filterStage == defaultExtProcFilterStage {
		if name == "" {
			return extProcFilterPrefix
		}
		return extProcFilterPrefix + name
	}

	// Use stage-qualified naming for non-default stages
	stageName := filterStageName(filterStage)
	prefix := extProcFilterPrefix + stageName + "/"
	if name == "" {
		return prefix
	}
	return prefix + name
}

// filterStageName returns a string representation of the filter stage for use in filter names.
func filterStageName(stage filters.FilterStage[filters.WellKnownFilterStage]) string {
	var stagePart string
	switch stage.RelativeTo {
	case filters.FaultStage:
		stagePart = "fault"
	case filters.CorsStage:
		stagePart = "cors"
	case filters.WafStage:
		stagePart = "waf"
	case filters.AuthNStage:
		stagePart = "authn"
	case filters.AuthZStage:
		stagePart = "authz"
	case filters.RateLimitStage:
		stagePart = "ratelimit"
	case filters.AcceptedStage:
		stagePart = "accepted"
	case filters.OutAuthStage:
		stagePart = "outauth"
	case filters.RouteStage:
		stagePart = "route"
	default:
		stagePart = "authz"
	}

	var predicatePart string
	switch {
	case stage.RelativeWeight < 0:
		predicatePart = "before"
	case stage.RelativeWeight > 0:
		predicatePart = "after"
	default:
		predicatePart = "during"
	}

	return stagePart + "_" + predicatePart
}

func (p *trafficPolicyPluginGwPass) handleExtProc(filterChain string, pCtxTypedFilterConfig *ir.TypedFilterConfigMap, in *extprocIR) {
	if in == nil {
		return
	}

	// Add the global disable all filter if all providers are disabled
	if in.disableAllProviders {
		pCtxTypedFilterConfig.AddTypedConfig(extProcGlobalDisableFilterName, EnableFilterPerRoute())
		return
	}

	for _, cfg := range in.perProviderConfig {
		providerName := providerName(cfg.provider)
		p.extProcPerProvider.Add(filterChain, providerName, cfg.provider, cfg.filterStage)

		filterName := extProcFilterName(providerName, cfg.filterStage)
		pCtxTypedFilterConfig.AddTypedConfig(filterName, cfg.perRouteConfig)
	}
}

func providerName(provider *TrafficPolicyGatewayExtensionIR) string {
	if provider == nil {
		return ""
	}
	return provider.ResourceName()
}
