package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	sbOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	sJson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// OutboundBuilder creates outbound instances from raw node options.
type OutboundBuilder interface {
	Build(rawOptions json.RawMessage, dependencyBundle json.RawMessage) (adapter.Outbound, error)
}

// dependencyBundleJSON is the wire format for dependency outbound bundles.
type dependencyBundleJSON struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

// ---------------------------------------------------------------------------
// SingboxBuilder — creates real sing-box adapter.Outbound instances.
// ---------------------------------------------------------------------------

// SingboxBuilder builds real sing-box outbound instances from raw JSON options.
// It holds a fully-wired context with DNS services so that domain-based
// outbound servers can be resolved.
//
// Each Build() call with a non-nil dependencyBundle gets its own isolated
// OutboundManager so that detour tag resolution never collides across nodes.
type SingboxBuilder struct {
	registry            *sbOutbound.Registry
	outboundMgr         adapter.OutboundManager // shared manager (no-dep builds only)
	endpointMgr         adapter.EndpointManager
	ctx                 context.Context
	logFactory          log.Factory
	dnsTransportManager *dns.TransportManager
	dnsRouter           *dns.Router
}

// NewSingboxBuilder creates a SingboxBuilder with a complete sing-box service
// graph (registries + DNS). The caller must call Close() when done.
func NewSingboxBuilder() (*SingboxBuilder, error) {
	ctx := context.Background()
	ctx = include.Context(ctx) // inject protocol registries

	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("resin-outbound")

	// --- Service graph (same order as Demos/simple-proxy/main.go) -----------

	// Endpoint Manager
	endpointMgr := endpoint.NewManager(logger, service.FromContext[adapter.EndpointRegistry](ctx))
	service.MustRegister[adapter.EndpointManager](ctx, endpointMgr)

	// Inbound Manager (required dependency even though unused)
	inboundMgr := inbound.NewManager(logger, service.FromContext[adapter.InboundRegistry](ctx), endpointMgr)
	service.MustRegister[adapter.InboundManager](ctx, inboundMgr)

	// Outbound Manager (sing-box's own manager, used only for no-dependency builds)
	outboundMgr := sbOutbound.NewManager(logger, service.FromContext[adapter.OutboundRegistry](ctx), endpointMgr, "")
	service.MustRegister[adapter.OutboundManager](ctx, outboundMgr)

	// DNS Transport Manager
	dnsTransportMgr := dns.NewTransportManager(logger, service.FromContext[adapter.DNSTransportRegistry](ctx), outboundMgr, "")
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportMgr)

	// DNS Router
	dnsRouter := dns.NewRouter(ctx, logFactory, option.DNSOptions{})
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)

	// Register local DNS transport
	if err := dnsTransportMgr.Create(ctx, logger, "local", "local", &option.LocalDNSServerOptions{}); err != nil {
		return nil, fmt.Errorf("singbox builder: create local DNS transport: %w", err)
	}

	// Start DNS Transport Manager lifecycle
	if err := dnsTransportMgr.Start(adapter.StartStateInitialize); err != nil {
		return nil, fmt.Errorf("singbox builder: initialize DNS transport manager: %w", err)
	}
	if err := dnsTransportMgr.Start(adapter.StartStateStart); err != nil {
		_ = dnsTransportMgr.Close()
		return nil, fmt.Errorf("singbox builder: start DNS transport manager: %w", err)
	}

	// Start DNS Router lifecycle
	if err := dnsRouter.Initialize(nil); err != nil {
		_ = dnsTransportMgr.Close()
		return nil, fmt.Errorf("singbox builder: initialize DNS router: %w", err)
	}
	if err := dnsRouter.Start(adapter.StartStateStart); err != nil {
		_ = dnsRouter.Close()
		_ = dnsTransportMgr.Close()
		return nil, fmt.Errorf("singbox builder: start DNS router: %w", err)
	}

	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*sbOutbound.Registry)

	return &SingboxBuilder{
		registry:            registry,
		outboundMgr:         outboundMgr,
		endpointMgr:         endpointMgr,
		ctx:                 ctx,
		logFactory:          logFactory,
		dnsTransportManager: dnsTransportMgr,
		dnsRouter:           dnsRouter,
	}, nil
}

// Build parses rawOptions (a complete sing-box outbound JSON object with
// type/tag fields) into a real adapter.Outbound and runs it through the
// lifecycle stages.
//
// If dependencyBundle is non-nil, Build creates an isolated OutboundManager
// with its own service registry so that detour tag resolution is scoped to
// this single Build call. This prevents tag collisions when multiple nodes
// share the same detour tag name (e.g. "🇺🇸 美国中转").
func (b *SingboxBuilder) Build(rawOptions json.RawMessage, dependencyBundle json.RawMessage) (adapter.Outbound, error) {
	// Determine which context and registry to use for outbound creation.
	// For builds with dependencies, create an isolated context; otherwise
	// use the shared context.
	buildCtx := b.ctx
	var isoMgr adapter.OutboundManager // non-nil only when we created an isolated manager

	if len(dependencyBundle) > 0 {
		// Create an isolated service context with its own OutboundManager.
		var err error
		buildCtx, isoMgr, err = b.makeIsolatedContext()
		if err != nil {
			return nil, fmt.Errorf("create isolated context: %w", err)
		}

		// Register dependency outbounds on the isolated manager.
		var bundle dependencyBundleJSON
		if err := json.Unmarshal(dependencyBundle, &bundle); err != nil {
			return nil, fmt.Errorf("parse dependency bundle: %w", err)
		}
		for _, depRaw := range bundle.Outbounds {
			var depConfig option.Outbound
			if err := sJson.UnmarshalContext(buildCtx, depRaw, &depConfig); err != nil {
				return nil, fmt.Errorf("parse dependency outbound options: %w", err)
			}

			depLogger := b.logFactory.NewLogger("outbound/" + depConfig.Type)
			if err := isoMgr.Create(
				buildCtx,
				nil, // router
				depLogger,
				depConfig.Tag,
				depConfig.Type,
				depConfig.Options,
			); err != nil {
				return nil, fmt.Errorf("create dependency outbound [%s/%s]: %w", depConfig.Type, depConfig.Tag, err)
			}

			// Run lifecycle stages manually (manager was never Start()-ed).
			if depOb, ok := isoMgr.Outbound(depConfig.Tag); ok {
				for _, stage := range adapter.ListStartStages {
					if err := adapter.LegacyStart(depOb, stage); err != nil {
						return nil, fmt.Errorf("dependency outbound start %s [%s/%s]: %w", stage, depConfig.Type, depConfig.Tag, err)
					}
				}
			}
		}
	}

	// 1. Parse via official option.Outbound path.
	var outboundConfig option.Outbound
	if err := sJson.UnmarshalContext(buildCtx, rawOptions, &outboundConfig); err != nil {
		return nil, fmt.Errorf("parse outbound options: %w", err)
	}

	// 2. Create the outbound instance via the registry.
	logger := b.logFactory.NewLogger("outbound/" + outboundConfig.Type)
	ob, err := b.registry.CreateOutbound(
		buildCtx,
		nil, // router — not needed for simple dialing
		logger,
		outboundConfig.Tag,
		outboundConfig.Type,
		outboundConfig.Options,
	)
	if err != nil {
		return nil, fmt.Errorf("create outbound [%s]: %w", outboundConfig.Type, err)
	}

	// 3. Run lifecycle start stages. On failure, close and return error.
	for _, stage := range adapter.ListStartStages {
		if err := adapter.LegacyStart(ob, stage); err != nil {
			_ = common.Close(ob)
			return nil, fmt.Errorf("outbound start %s [%s]: %w", stage, outboundConfig.Type, err)
		}
	}

	return ob, nil
}

// makeIsolatedContext creates a child context with a fresh service registry
// and its own OutboundManager. All other services (DNS, protocol registries,
// etc.) are copied from the parent context so protocol constructors can
// resolve them normally.
func (b *SingboxBuilder) makeIsolatedContext() (context.Context, adapter.OutboundManager, error) {
	// Create a new registry that shadows the parent.
	childCtx := service.ContextWithRegistry(b.ctx, service.NewRegistry())

	// Copy protocol registries from parent (needed for option parsing and outbound creation).
	service.MustRegister[adapter.OutboundRegistry](childCtx, service.FromContext[adapter.OutboundRegistry](b.ctx))
	service.MustRegister[option.OutboundOptionsRegistry](childCtx, service.FromContext[option.OutboundOptionsRegistry](b.ctx))
	service.MustRegister[adapter.InboundRegistry](childCtx, service.FromContext[adapter.InboundRegistry](b.ctx))
	service.MustRegister[option.InboundOptionsRegistry](childCtx, service.FromContext[option.InboundOptionsRegistry](b.ctx))
	service.MustRegister[adapter.EndpointRegistry](childCtx, service.FromContext[adapter.EndpointRegistry](b.ctx))
	service.MustRegister[option.EndpointOptionsRegistry](childCtx, service.FromContext[option.EndpointOptionsRegistry](b.ctx))
	service.MustRegister[adapter.DNSTransportRegistry](childCtx, service.FromContext[adapter.DNSTransportRegistry](b.ctx))
	service.MustRegister[option.DNSTransportOptionsRegistry](childCtx, service.FromContext[option.DNSTransportOptionsRegistry](b.ctx))

	// Copy service managers from parent (DNS, endpoint, inbound).
	service.MustRegister[adapter.EndpointManager](childCtx, service.FromContext[adapter.EndpointManager](b.ctx))
	service.MustRegister[adapter.InboundManager](childCtx, service.FromContext[adapter.InboundManager](b.ctx))
	service.MustRegister[adapter.DNSTransportManager](childCtx, service.FromContext[adapter.DNSTransportManager](b.ctx))
	service.MustRegister[adapter.DNSRouter](childCtx, service.FromContext[adapter.DNSRouter](b.ctx))

	// Create an isolated OutboundManager for this Build call.
	isoLogger := b.logFactory.NewLogger("outbound-iso")
	isoMgr := sbOutbound.NewManager(
		isoLogger,
		service.FromContext[adapter.OutboundRegistry](b.ctx),
		b.endpointMgr,
		"",
	)
	service.MustRegister[adapter.OutboundManager](childCtx, isoMgr)

	return childCtx, isoMgr, nil
}

// removeDeps removes previously registered dependency outbounds from the
// OutboundManager (best-effort cleanup on build failure).
func (b *SingboxBuilder) removeDeps(tags []string) {
	for _, tag := range tags {
		_ = b.outboundMgr.Remove(tag)
	}
}

// Close shuts down the builder's internal DNS services.
func (b *SingboxBuilder) Close() error {
	var errs []error
	if b.dnsRouter != nil {
		errs = append(errs, b.dnsRouter.Close())
	}
	if b.dnsTransportManager != nil {
		errs = append(errs, b.dnsTransportManager.Close())
	}
	return errors.Join(errs...)
}
