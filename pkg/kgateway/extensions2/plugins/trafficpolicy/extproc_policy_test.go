package trafficpolicy

import (
	"testing"

	envoycorev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/filters"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

func TestExtprocIREquals(t *testing.T) {
	createSimpleExtproc := func(requestMode envoy_ext_proc_v3.ProcessingMode_HeaderSendMode) *envoy_ext_proc_v3.ExtProcPerRoute {
		return &envoy_ext_proc_v3.ExtProcPerRoute{
			Override: &envoy_ext_proc_v3.ExtProcPerRoute_Overrides{
				Overrides: &envoy_ext_proc_v3.ExtProcOverrides{
					ProcessingMode: &envoy_ext_proc_v3.ProcessingMode{
						RequestHeaderMode: requestMode,
					},
				},
			},
		}
	}
	createProvider := func(name string) *TrafficPolicyGatewayExtensionIR {
		return &TrafficPolicyGatewayExtensionIR{
			Name: name,
			ExtProc: buildCompositeExtProcFilter(
				kgateway.ExtProcProvider{FailOpen: true},
				&envoycorev3.GrpcService{
					TargetSpecifier: &envoycorev3.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoycorev3.GrpcService_EnvoyGrpc{
							ClusterName: name,
						},
					},
				},
			),
		}
	}

	tests := []struct {
		name     string
		extproc1 *extprocIR
		extproc2 *extprocIR
		expected bool
	}{
		{
			name:     "both nil are equal",
			extproc1: nil,
			extproc2: nil,
			expected: true,
		},
		{
			name:     "nil vs non-nil are not equal",
			extproc1: nil,
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			expected: false,
		},
		{
			name:     "non-nil vs nil are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			extproc2: nil,
			expected: false,
		},
		{
			name:     "same instance is equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			expected: true,
		},
		{
			name:     "different processing modes are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SKIP)}}},
			expected: false,
		},
		{
			name:     "different providers are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{provider: createProvider("service1")}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{provider: createProvider("service2")}}},
			expected: false,
		},
		{
			name:     "same providers are equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{provider: createProvider("service1")}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{provider: createProvider("service1")}}},
			expected: true,
		},
		{
			name:     "nil perRoute fields are equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: nil}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: nil}}},
			expected: true,
		},
		{
			name:     "nil vs non-nil perRoute fields are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: nil}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND)}}},
			expected: false,
		},
		{
			name: "same filterStage are equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.BeforeStage(filters.AuthNStage),
			}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.BeforeStage(filters.AuthNStage),
			}}},
			expected: true,
		},
		{
			name: "different filterStage stages are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.BeforeStage(filters.AuthNStage),
			}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.AfterStage(filters.AuthZStage),
			}}},
			expected: false,
		},
		{
			name: "different filterStage predicates are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.BeforeStage(filters.AuthZStage),
			}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:    createProvider("service1"),
				filterStage: filters.AfterStage(filters.AuthZStage),
			}}},
			expected: false,
		},
		{
			name: "same provider different filterStage are not equal",
			extproc1: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:       createProvider("service1"),
				perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND),
				filterStage:    filters.BeforeStage(filters.AuthNStage),
			}}},
			extproc2: &extprocIR{perProviderConfig: []*perProviderExtProcConfig{{
				provider:       createProvider("service1"),
				perRouteConfig: createSimpleExtproc(envoy_ext_proc_v3.ProcessingMode_SEND),
				filterStage:    filters.AfterStage(filters.AuthZStage),
			}}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.extproc1.Equals(tt.extproc2)
			assert.Equal(t, tt.expected, result)

			// Test symmetry: a.Equals(b) should equal b.Equals(a)
			reverseResult := tt.extproc2.Equals(tt.extproc1)
			assert.Equal(t, result, reverseResult, "Equals should be symmetric")
		})
	}
}

func TestBuildEnvoyExtProc(t *testing.T) {
	tests := []struct {
		name           string
		gatewayExt     *ir.GatewayExtension
		extprocConfig  *kgateway.ExtProcPolicy
		expectedError  string
		validateResult func(*testing.T, *envoy_ext_proc_v3.ExtProcPerRoute)
	}{
		{
			name: "with all processing modes",
			gatewayExt: &ir.GatewayExtension{
				ExtProc: &kgateway.ExtProcProvider{
					GrpcService: kgateway.ExtGrpcService{
						BackendRef: gwv1.BackendRef{
							BackendObjectReference: gwv1.BackendObjectReference{
								Name: "test-service",
							},
						},
					},
				},
			},
			extprocConfig: &kgateway.ExtProcPolicy{
				ProcessingMode: &kgateway.ProcessingMode{
					RequestHeaderMode:   "SEND",
					ResponseHeaderMode:  "SKIP",
					RequestBodyMode:     "STREAMED",
					ResponseBodyMode:    "BUFFERED",
					RequestTrailerMode:  "SEND",
					ResponseTrailerMode: "SKIP",
				},
			},
			validateResult: func(t *testing.T, result *envoy_ext_proc_v3.ExtProcPerRoute) {
				processingMode := result.GetOverrides().GetProcessingMode()
				assert.NotNil(t, processingMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_SEND, processingMode.RequestHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_SKIP, processingMode.ResponseHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_STREAMED, processingMode.RequestBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_BUFFERED, processingMode.ResponseBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_SEND, processingMode.RequestTrailerMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_SKIP, processingMode.ResponseTrailerMode)
			},
		},
		{
			name: "with default processing modes",
			gatewayExt: &ir.GatewayExtension{
				ExtProc: &kgateway.ExtProcProvider{
					GrpcService: kgateway.ExtGrpcService{
						BackendRef: gwv1.BackendRef{
							BackendObjectReference: gwv1.BackendObjectReference{
								Name: "test-service",
							},
						},
					},
				},
			},
			extprocConfig: &kgateway.ExtProcPolicy{
				ProcessingMode: &kgateway.ProcessingMode{},
			},
			validateResult: func(t *testing.T, result *envoy_ext_proc_v3.ExtProcPerRoute) {
				processingMode := result.GetOverrides().GetProcessingMode()
				assert.NotNil(t, processingMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.RequestHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.ResponseHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_NONE, processingMode.RequestBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_NONE, processingMode.ResponseBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.RequestTrailerMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.ResponseTrailerMode)
			},
		},
		{
			name: "with invalid processing modes",
			gatewayExt: &ir.GatewayExtension{
				ExtProc: &kgateway.ExtProcProvider{
					GrpcService: kgateway.ExtGrpcService{
						BackendRef: gwv1.BackendRef{
							BackendObjectReference: gwv1.BackendObjectReference{
								Name: "test-service",
							},
						},
					},
				},
			},
			extprocConfig: &kgateway.ExtProcPolicy{
				ProcessingMode: &kgateway.ProcessingMode{
					RequestHeaderMode:   "INVALID",
					ResponseHeaderMode:  "INVALID",
					RequestBodyMode:     "INVALID",
					ResponseBodyMode:    "INVALID",
					RequestTrailerMode:  "INVALID",
					ResponseTrailerMode: "INVALID",
				},
			},
			validateResult: func(t *testing.T, result *envoy_ext_proc_v3.ExtProcPerRoute) {
				processingMode := result.GetOverrides().GetProcessingMode()
				assert.NotNil(t, processingMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.RequestHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.ResponseHeaderMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_NONE, processingMode.RequestBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_NONE, processingMode.ResponseBodyMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.RequestTrailerMode)
				assert.Equal(t, envoy_ext_proc_v3.ProcessingMode_DEFAULT, processingMode.ResponseTrailerMode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := translateExtProcPerFilterConfig(tt.extprocConfig)

			// require.NoError(t, err)
			require.NotNil(t, result)
			tt.validateResult(t, result)
		})
	}
}

func TestConvertExtProcStageConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *kgateway.ExtProcStageConfig
		expected filters.FilterStage[filters.WellKnownFilterStage]
	}{
		{
			name:     "nil config returns default (After AuthZ)",
			config:   nil,
			expected: filters.AfterStage(filters.AuthZStage),
		},
		{
			name:     "empty config returns default (After AuthZ)",
			config:   &kgateway.ExtProcStageConfig{},
			expected: filters.AfterStage(filters.AuthZStage),
		},
		{
			name: "Fault stage with Before predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageFault,
				Predicate: kgateway.ExtProcFilterPredicateBefore,
			},
			expected: filters.BeforeStage(filters.FaultStage),
		},
		{
			name: "AuthN stage with During predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageAuthN,
				Predicate: kgateway.ExtProcFilterPredicateDuring,
			},
			expected: filters.DuringStage(filters.AuthNStage),
		},
		{
			name: "AuthZ stage with After predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageAuthZ,
				Predicate: kgateway.ExtProcFilterPredicateAfter,
			},
			expected: filters.AfterStage(filters.AuthZStage),
		},
		{
			name: "RateLimit stage with Before predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageRateLimit,
				Predicate: kgateway.ExtProcFilterPredicateBefore,
			},
			expected: filters.BeforeStage(filters.RateLimitStage),
		},
		{
			name: "Cors stage with During predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageCors,
				Predicate: kgateway.ExtProcFilterPredicateDuring,
			},
			expected: filters.DuringStage(filters.CorsStage),
		},
		{
			name: "Waf stage with After predicate",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageWaf,
				Predicate: kgateway.ExtProcFilterPredicateAfter,
			},
			expected: filters.AfterStage(filters.WafStage),
		},
		{
			name: "Accepted stage",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageAccepted,
				Predicate: kgateway.ExtProcFilterPredicateBefore,
			},
			expected: filters.BeforeStage(filters.AcceptedStage),
		},
		{
			name: "OutAuth stage",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageOutAuth,
				Predicate: kgateway.ExtProcFilterPredicateDuring,
			},
			expected: filters.DuringStage(filters.OutAuthStage),
		},
		{
			name: "Route stage",
			config: &kgateway.ExtProcStageConfig{
				Stage:     kgateway.ExtProcFilterStageRoute,
				Predicate: kgateway.ExtProcFilterPredicateAfter,
			},
			expected: filters.AfterStage(filters.RouteStage),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertExtProcStageConfig(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFilterStageName(t *testing.T) {
	tests := []struct {
		name     string
		stage    filters.FilterStage[filters.WellKnownFilterStage]
		expected string
	}{
		{
			name:     "Fault Before",
			stage:    filters.BeforeStage(filters.FaultStage),
			expected: "fault_before",
		},
		{
			name:     "Cors During",
			stage:    filters.DuringStage(filters.CorsStage),
			expected: "cors_during",
		},
		{
			name:     "Waf After",
			stage:    filters.AfterStage(filters.WafStage),
			expected: "waf_after",
		},
		{
			name:     "AuthN Before",
			stage:    filters.BeforeStage(filters.AuthNStage),
			expected: "authn_before",
		},
		{
			name:     "AuthZ After",
			stage:    filters.AfterStage(filters.AuthZStage),
			expected: "authz_after",
		},
		{
			name:     "RateLimit During",
			stage:    filters.DuringStage(filters.RateLimitStage),
			expected: "ratelimit_during",
		},
		{
			name:     "Accepted Before",
			stage:    filters.BeforeStage(filters.AcceptedStage),
			expected: "accepted_before",
		},
		{
			name:     "OutAuth After",
			stage:    filters.AfterStage(filters.OutAuthStage),
			expected: "outauth_after",
		},
		{
			name:     "Route During",
			stage:    filters.DuringStage(filters.RouteStage),
			expected: "route_during",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterStageName(tt.stage)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtProcFilterName(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		filterStage filters.FilterStage[filters.WellKnownFilterStage]
		expected    string
	}{
		{
			name:        "default stage (After AuthZ) uses simple naming",
			provider:    "my-provider",
			filterStage: filters.AfterStage(filters.AuthZStage),
			expected:    "ext_proc/my-provider",
		},
		{
			name:        "default stage with empty provider",
			provider:    "",
			filterStage: filters.AfterStage(filters.AuthZStage),
			expected:    "ext_proc/",
		},
		{
			name:        "non-default stage uses qualified naming",
			provider:    "my-provider",
			filterStage: filters.BeforeStage(filters.AuthNStage),
			expected:    "ext_proc/authn_before/my-provider",
		},
		{
			name:        "non-default stage with empty provider",
			provider:    "",
			filterStage: filters.BeforeStage(filters.AuthNStage),
			expected:    "ext_proc/authn_before/",
		},
		{
			name:        "During AuthZ is not default",
			provider:    "my-provider",
			filterStage: filters.DuringStage(filters.AuthZStage),
			expected:    "ext_proc/authz_during/my-provider",
		},
		{
			name:        "Before AuthZ is not default",
			provider:    "my-provider",
			filterStage: filters.BeforeStage(filters.AuthZStage),
			expected:    "ext_proc/authz_before/my-provider",
		},
		{
			name:        "After RateLimit uses qualified naming",
			provider:    "ratelimit-extproc",
			filterStage: filters.AfterStage(filters.RateLimitStage),
			expected:    "ext_proc/ratelimit_after/ratelimit-extproc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extProcFilterName(tt.provider, tt.filterStage)
			assert.Equal(t, tt.expected, result)
		})
	}
}
