// Licensed to Apache Software Foundation (ASF) under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Apache Software Foundation (ASF) licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ztunnel

import (
	"fmt"
)

// OffsetSource records HOW a set of offsets was obtained, so the periodic stats can
// report which rung of the fallback ladder a node ended up on.
type OffsetSource string

const (
	// OffsetSourceDWARF is the ztunnel binary's own debug info. Only self-built ztunnels
	// carry it: every official istio release image, and the vendor rebuilds measured so far,
	// are compiled with `cargo build --release` whose profile leaves `debug` off, so they
	// ship a symbol table but NO .debug_* sections.
	OffsetSourceDWARF OffsetSource = "dwarf"
	// OffsetSourceTable is the pre-generated table, matched on the binary's GNU build ID.
	OffsetSourceTable OffsetSource = "table"
	// OffsetSourceCalibrated is the runtime calibration, which recovers the offsets for a
	// binary nobody generated a table entry for(a vendor or locally patched ztunnel).
	OffsetSourceCalibrated OffsetSource = "calibrated"
)

// Offsets locates the fields the identity addition needs inside the ztunnel `ConnectionResult`
// struct, as observed at the `ConnectionResult::record_internal` uprobe.
//
// This is the RESOLVED, in-memory form: absolute positions relative to the pointer the probe
// copies. It is never persisted - a table stores per-type Layouts under the Rust type and field
// names, and Layouts.Resolve composes them into this.
//
// Why this struct and this probe: `record_internal` is the function that WRITES the ztunnel
// access log, and `&self` gives it every value the log line carries - the peer addresses and
// the whole `CommonTrafficLabels`. It is present in every ztunnel measured(1.24 through
// master, and the vendor rebuild running in production), takes `&self` in PARM1 with no
// sret shift, and fires at the same moment the access-log line would be written - but without
// the kubelet round trip and the tailer's poll interval behind it.
//
// All CommonTrafficLabels offsets are ABSOLUTE from the start of ConnectionResult(the
// extractor folds in the `tl` field offset), so a consumer never has to add two numbers.
//
// Reference values measured from ztunnel release-1.28 (aarch64, dev profile):
//
//	ConnectionResult size=408: tl=+0 src=+248 dst=+288 hbone_target=+328
//	CommonTrafficLabels size=232: source_principal=+72 source_cluster=+112
//	                              destination_principal=+176 destination_cluster=+216
//	                              reporter=+224 connection_security_policy=+226
//	Identity::Spiffe size=24: trust_domain=+0 namespace=+8 service_account=+16
//
// The `zt:"<RustType>.<field>"` tags are the SINGLE source of truth for where each offset comes
// from: DWARF extraction(which types to decode), layout validation(which fields must exist) and
// resolution(reading each field out of the layouts) are all driven off these tags by reflection,
// so teaching the probe to read another label is one tagged field here and nothing else. Fields
// tagged `zt:"-"` are derived, not read from a layout(see Layouts.Resolve). Every CommonTrafficLabels
// field is rebased onto ConnectionResult automatically(it is embedded at ConnectionResult.tl).
type Offsets struct {
	// Source records which rung produced these offsets; not persisted in the table file.
	Source OffsetSource `zt:"-"`

	// Window is sizeof(ConnectionResult): how many bytes the probe must copy out of `&self`
	// for every offset below to be inside the copied buffer.
	Window int `zt:"-"`

	// Src and Dst are the (SocketAddr, Option<RichStrng>) tuples holding the connection's
	// peer addresses, used to key the mapping onto a monitored socket.
	Src int `zt:"ConnectionResult.src"`
	Dst int `zt:"ConnectionResult.dst"`
	// HboneTarget is Option<HboneAddress>: the real backend pod behind an HBONE hop.
	HboneTarget int `zt:"ConnectionResult.hbone_target"`

	// HasDirection reports whether Reporter and SecurityPolicy are meaningful. Both are single
	// byte enums holding 0 or 1, which carry no signature to recognize them by, so runtime
	// calibration cannot recover them - it produces an offset set with HasDirection false, and
	// the consumer then takes the direction from the monitored socket's own role instead.
	HasDirection bool `zt:"-"`
	// Reporter is the enum deciding the direction: source(0) = outbound, destination(1) = inbound.
	Reporter int `zt:"CommonTrafficLabels.reporter"`
	// SecurityPolicy is the enum whose mutual_tls(1) value gates whether the principals are
	// trustworthy - ztunnel applies the same filter before printing them to the access log.
	SecurityPolicy int `zt:"CommonTrafficLabels.connection_security_policy"`

	// SourcePrincipal / DestinationPrincipal are DefaultedUnknown<Identity>: three inline
	// ArcStr pointers(no discriminant, the Option is niche encoded into a null pointer).
	SourcePrincipal      int `zt:"CommonTrafficLabels.source_principal"`
	DestinationPrincipal int `zt:"CommonTrafficLabels.destination_principal"`
	// SourceNamespace / DestinationNamespace are DefaultedUnknown<RichStrng>: one nullable
	// ArcStr pointer. They repeat what the principal carries, and are the fallback for a
	// connection whose principals are absent because it is not mTLS.
	SourceNamespace      int `zt:"CommonTrafficLabels.source_workload_namespace"`
	DestinationNamespace int `zt:"CommonTrafficLabels.destination_workload_namespace"`
	// SourceCluster / DestinationCluster are DefaultedUnknown<RichStrng>. These are the reason
	// the uprobe beats the access log outright: the cluster lives in CommonTrafficLabels from
	// ztunnel 1.26 on, but upstream only started PRINTING src.cluster/dst.cluster in 1.31, so
	// on 1.26-1.30 the access log structurally cannot supply DST_CLUSTER and this probe can.
	SourceCluster      int `zt:"CommonTrafficLabels.source_cluster"`
	DestinationCluster int `zt:"CommonTrafficLabels.destination_cluster"`

	// IdentitySpiffeSize is sizeof(Identity::Spiffe), taken from the resolved layout(the table/DWARF
	// records it) so validation of the identity members below is bounded by the real size rather
	// than a compiled-in assumption. It is derived, not a field offset. A calibrated set has no
	// layout to read it from and sets the compiled-in IdentitySpiffeSize instead.
	IdentitySpiffeSize int `zt:"-"`

	// Identity* are offsets WITHIN an Identity::Spiffe value, applied on top of a principal
	// offset. Rust is free to reorder repr(Rust) fields, so these are extracted rather than
	// assumed to be declaration order.
	IdentityTrustDomain    int `zt:"Identity::Spiffe.trust_domain"`
	IdentityNamespace      int `zt:"Identity::Spiffe.namespace"`
	IdentityServiceAccount int `zt:"Identity::Spiffe.service_account"`
}

// maxWindow bounds the buffer the probe copies per connection. The measured
// ConnectionResult is 408 bytes; a value far above that means the extraction latched onto the
// wrong type, and copying it would waste a large per-event payload for nothing.
const maxWindow = 2048

// IdentitySpiffeSize is sizeof(Identity::Spiffe): three inline ArcStr pointers.
const IdentitySpiffeSize = 24

// OffsetAbsent marks an optional field this offset set could not locate. Reading it yields
// "field not present" rather than whatever byte happens to live at offset zero.
const OffsetAbsent = -1

// field-name labels used in Validate's error messages, kept as named constants so the same labels
// the offset tests assert on are not duplicated string literals.
const (
	fieldSrc                    = "src"
	fieldDst                    = "dst"
	fieldDestinationPrincipal   = "destinationPrincipal"
	fieldDestinationCluster     = "destinationCluster"
	fieldReporter               = "reporter"
	fieldIdentityServiceAccount = "identityServiceAccount"
)

// Validate rejects an offset set that cannot describe a real ConnectionResult. It runs on
// EVERY source - a hand-edited table file and a mis-converged calibration are just as capable
// of producing nonsense as a mismatched binary - so that a bad set is refused up front instead
// of silently reading garbage out of ztunnel's memory and reporting it as an identity.
func (o *Offsets) Validate() error {
	if o.Window <= 0 || o.Window > maxWindow {
		return fmt.Errorf("window %d is out of range (0, %d]", o.Window, maxWindow)
	}
	// a resolved set records the real Identity::Spiffe size(from the table/DWARF); a calibrated set
	// or an older entry that did not carry it falls back to the compiled-in size
	spiffeSize := o.IdentitySpiffeSize
	if spiffeSize <= 0 {
		spiffeSize = IdentitySpiffeSize
	}
	if err := o.validatePointerFields(spiffeSize); err != nil {
		return err
	}
	if err := o.validateDirectionEnums(); err != nil {
		return err
	}
	return o.validateIdentityMembers(spiffeSize)
}

// validatePointerFields checks every pointer-sized field is 8-byte aligned and leaves room for its
// own value inside the window.
func (o *Offsets) validatePointerFields(spiffeSize int) error {
	for _, f := range []struct {
		name     string
		off      int
		size     int
		required bool
	}{
		// Src and the destination identity are what the outbound DST_* addition is built from,
		// so an offset set that cannot locate them is useless and refused.
		{fieldSrc, o.Src, 8, true},
		{fieldDestinationPrincipal, o.DestinationPrincipal, spiffeSize, true},
		// The rest are optional: runtime calibration anchors itself on a connection whose real
		// destination is already known, which pins the destination side but leaves the source
		// side unanchored - and ztunnel leaves source_principal unset on an outbound connection
		// anyway. OffsetAbsent marks a field this particular set could not locate; the decoder
		// reads it as "field not present" rather than reading some arbitrary byte.
		{fieldDst, o.Dst, 8, false},
		{"hboneTarget", o.HboneTarget, 8, false},
		{"sourcePrincipal", o.SourcePrincipal, spiffeSize, false},
		{"sourceNamespace", o.SourceNamespace, 8, false},
		{"destinationNamespace", o.DestinationNamespace, 8, false},
		{"sourceCluster", o.SourceCluster, 8, false},
		{fieldDestinationCluster, o.DestinationCluster, 8, false},
	} {
		if f.off == OffsetAbsent && !f.required {
			continue
		}
		if f.off < 0 || f.off+f.size > o.Window {
			return fmt.Errorf("%s offset %d does not fit in the %d byte window", f.name, f.off, o.Window)
		}
		if f.off%8 != 0 {
			return fmt.Errorf("%s offset %d is not 8 byte aligned", f.name, f.off)
		}
	}
	return nil
}

// validateDirectionEnums checks the two single-byte direction enums, each gated INDEPENDENTLY by
// whether it was resolved: a table/DWARF set carries both; runtime calibration can recover the
// reporter(it flips between outbound and inbound) but not the security policy(constant on mesh
// traffic), so it sets one and leaves the other absent. An absent enum is "not present"(the decoder
// defaults it), a present one only has to sit inside the window.
func (o *Offsets) validateDirectionEnums() error {
	for _, f := range []struct {
		name string
		off  int
	}{
		{fieldReporter, o.Reporter},
		{"securityPolicy", o.SecurityPolicy},
	} {
		if f.off == OffsetAbsent {
			continue
		}
		if f.off < 0 || f.off >= o.Window {
			return fmt.Errorf("%s offset %d is outside the %d byte window", f.name, f.off, o.Window)
		}
	}
	return nil
}

// validateIdentityMembers checks the three Identity members are distinct and inside one Spiffe value.
func (o *Offsets) validateIdentityMembers(spiffeSize int) error {
	ids := map[int]string{}
	for _, f := range []struct {
		name string
		off  int
	}{
		{"identityTrustDomain", o.IdentityTrustDomain},
		{"identityNamespace", o.IdentityNamespace},
		{fieldIdentityServiceAccount, o.IdentityServiceAccount},
	} {
		if f.off < 0 || f.off+8 > spiffeSize {
			return fmt.Errorf("%s offset %d does not fit in a %d byte Identity", f.name, f.off, spiffeSize)
		}
		if f.off%8 != 0 {
			return fmt.Errorf("%s offset %d is not 8 byte aligned", f.name, f.off)
		}
		if other, dup := ids[f.off]; dup {
			return fmt.Errorf("%s and %s share offset %d", f.name, other, f.off)
		}
		ids[f.off] = f.name
	}
	return nil
}
