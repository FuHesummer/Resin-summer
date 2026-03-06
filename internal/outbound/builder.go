package outbound

import (
	"context"
	"encoding/json"
	"fmt"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sJson "github.com/sagernet/sing/common/json"
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
// SingboxBuilder — creates real sing-box adapter.Outbound instances via box.New().
// ---------------------------------------------------------------------------

// SingboxBuilder builds real sing-box outbound instances by delegating to
// sing-box's official box.New() API. Each Build() call creates a dedicated
// Box instance with its own OutboundManager, DNS, and router — ensuring
// proper lifecycle and detour tag isolation across nodes.
type SingboxBuilder struct{}

// NewSingboxBuilder creates a SingboxBuilder. No global state is held;
// each Build() call creates its own box.Box instance.
func NewSingboxBuilder() (*SingboxBuilder, error) {
	return &SingboxBuilder{}, nil
}

// boxOutbound wraps an adapter.Outbound extracted from a box.Box, holding a
// reference to the Box so its lifecycle is tied to this outbound's Close().
type boxOutbound struct {
	adapter.Outbound
	box *box.Box
}

func (b *boxOutbound) Close() error {
	return b.box.Close()
}

// Build parses rawOptions (a complete sing-box outbound JSON object with
// type/tag fields) into a real adapter.Outbound using box.New().
//
// If dependencyBundle is non-nil, all dependency outbounds are included in
// the same Box instance so that detour tag resolution works correctly.
// Each Build() call gets its own Box, preventing tag collisions across nodes.
func (b *SingboxBuilder) Build(rawOptions json.RawMessage, dependencyBundle json.RawMessage) (adapter.Outbound, error) {
	// Create a fresh context with all protocol registries.
	ctx := include.Context(context.Background())

	// Parse the main outbound config to get its tag.
	var mainConfig option.Outbound
	if err := sJson.UnmarshalContext(ctx, rawOptions, &mainConfig); err != nil {
		return nil, fmt.Errorf("parse outbound options: %w", err)
	}

	// Collect all outbounds: dependencies first, then the main outbound.
	var outbounds []option.Outbound

	if len(dependencyBundle) > 0 {
		var bundle dependencyBundleJSON
		if err := json.Unmarshal(dependencyBundle, &bundle); err != nil {
			return nil, fmt.Errorf("parse dependency bundle: %w", err)
		}
		for _, depRaw := range bundle.Outbounds {
			var depConfig option.Outbound
			if err := sJson.UnmarshalContext(ctx, depRaw, &depConfig); err != nil {
				return nil, fmt.Errorf("parse dependency outbound options: %w", err)
			}
			outbounds = append(outbounds, depConfig)
		}
	}

	outbounds = append(outbounds, mainConfig)

	// Create a Box with all outbounds.
	// Route.Final must point to the main outbound so that internal DNS queries
	// and any other unmatched traffic route through the proxy chain instead of
	// falling back to the auto-created "direct" outbound. Without this, domain-
	// based server addresses may be resolved via direct DNS (subject to pollution).
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: outbounds,
			Route: &option.RouteOptions{
				Final: mainConfig.Tag,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}

	// Start the Box to run full lifecycle (DNS, outbound manager, dependency wiring).
	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return nil, fmt.Errorf("start sing-box instance: %w", err)
	}

	// Extract the main outbound by tag.
	ob, found := instance.Outbound().Outbound(mainConfig.Tag)
	if !found {
		_ = instance.Close()
		return nil, fmt.Errorf("outbound [%s] not found after box start", mainConfig.Tag)
	}

	return &boxOutbound{Outbound: ob, box: instance}, nil
}

// Close is a no-op; SingboxBuilder holds no global state.
// Individual outbound lifetimes are managed by their boxOutbound wrappers.
func (b *SingboxBuilder) Close() error {
	return nil
}
