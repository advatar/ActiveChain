package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
)

const (
	errHolderBinding   envelopeError = "holder_binding"
	errActionSet       envelopeError = "action_set"
	errScope           envelopeError = "scope"
	errRateLimit       envelopeError = "rate_limit"
	errBoolean         envelopeError = "boolean"
	errSelfParent      envelopeError = "self_parent"
	errDelegationState envelopeError = "delegation_state"
	errSignatureLength envelopeError = "signature_length"
	errAttenuation     envelopeError = "attenuation"
)

type capCursor struct {
	body []byte
	pos  int
}

func (c *capCursor) take(n int) ([]byte, envelopeError) {
	if n < 0 || c.pos+n > len(c.body) {
		return nil, errUnexpectedEnd
	}
	out := c.body[c.pos : c.pos+n]
	c.pos += n
	return out, ""
}

func (c *capCursor) byte() (byte, envelopeError) {
	b, err := c.take(1)
	if err != "" {
		return 0, err
	}
	return b[0], ""
}

func (c *capCursor) length(max uint32) (uint32, envelopeError) {
	value, width, err := decodeLength(c.body[c.pos:])
	if err != "" {
		return 0, err
	}
	if value > max {
		return 0, errBodyLimit
	}
	c.pos += width
	return value, ""
}

func (c *capCursor) u64() (uint64, envelopeError) {
	b, err := c.take(8)
	if err != "" {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), ""
}

type optionalBytes struct {
	set   bool
	value []byte
}
type optionalU64 struct {
	set   bool
	value uint64
}
type optionalU128 struct {
	set   bool
	value [16]byte
}
type rateLimit struct {
	set          bool
	uses, window uint64
}

func (c *capCursor) optionBytes(n int) (optionalBytes, envelopeError) {
	tag, err := c.byte()
	if err != "" {
		return optionalBytes{}, err
	}
	if tag == 0 {
		return optionalBytes{}, ""
	}
	if tag != 1 {
		return optionalBytes{}, errInvalidOption
	}
	b, err := c.take(n)
	if err != "" {
		return optionalBytes{}, err
	}
	return optionalBytes{true, append([]byte(nil), b...)}, ""
}

func (c *capCursor) optionU64() (optionalU64, envelopeError) {
	tag, err := c.byte()
	if err != "" {
		return optionalU64{}, err
	}
	if tag == 0 {
		return optionalU64{}, ""
	}
	if tag != 1 {
		return optionalU64{}, errInvalidOption
	}
	v, err := c.u64()
	if err != "" {
		return optionalU64{}, err
	}
	return optionalU64{true, v}, ""
}

func (c *capCursor) optionU128() (optionalU128, envelopeError) {
	tag, err := c.byte()
	if err != "" {
		return optionalU128{}, err
	}
	if tag == 0 {
		return optionalU128{}, ""
	}
	if tag != 1 {
		return optionalU128{}, errInvalidOption
	}
	b, err := c.take(16)
	if err != "" {
		return optionalU128{}, err
	}
	var v [16]byte
	copy(v[:], b)
	return optionalU128{true, v}, ""
}

type holder struct {
	kind  byte
	value []byte
}
type scope struct {
	kind  byte
	bits  uint16
	value []byte
}

func (c *capCursor) holder() (holder, envelopeError) {
	tag, err := c.byte()
	if err != "" {
		return holder{}, err
	}
	if tag == 2 {
		return holder{kind: tag}, ""
	}
	if tag > 2 {
		return holder{}, errHolderBinding
	}
	b, err := c.take(48)
	if err != "" {
		return holder{}, err
	}
	return holder{tag, append([]byte(nil), b...)}, ""
}

func (c *capCursor) scope() (scope, envelopeError) {
	tag, err := c.byte()
	if err != "" {
		return scope{}, err
	}
	if tag == 0 {
		return scope{kind: 0}, ""
	}
	if tag == 1 {
		b, err := c.take(48)
		if err != "" {
			return scope{}, err
		}
		return scope{1, 384, append([]byte(nil), b...)}, ""
	}
	if tag != 2 {
		return scope{}, errScope
	}
	bitsBytes, err := c.take(2)
	if err != "" {
		return scope{}, err
	}
	bits := binary.BigEndian.Uint16(bitsBytes)
	b, err := c.take(48)
	if err != "" {
		return scope{}, err
	}
	if bits == 0 || bits >= 384 || !normalizedPrefix(b, bits) {
		return scope{}, errScope
	}
	return scope{2, bits, append([]byte(nil), b...)}, ""
}

func normalizedPrefix(value []byte, bits uint16) bool {
	full, rem := int(bits/8), uint8(bits%8)
	start := full
	if rem != 0 {
		if value[full]&((1<<(8-rem))-1) != 0 {
			return false
		}
		start++
	}
	for _, b := range value[start:] {
		if b != 0 {
			return false
		}
	}
	return true
}

type capability struct {
	id, issuer        []byte
	holder            holder
	parent            optionalBytes
	actions           [][]byte
	resource, data    scope
	monetary, compute optionalU128
	rate              rateLimit
	uses              optionalU64
	validFrom         uint64
	validUntil        optionalU64
	depth             byte
	delegation        bool
	revocation        optionalBytes
	constraint        []byte
}

type capabilityOffsets struct {
	issuer, parentValue, actionCount, firstAction, resourceTag   int
	monetaryValue, computeValue, rateUses, rateWindow, usesValue int
	validFrom, validUntilValue, depth, delegation                int
	revocationValue, constraint, signatureSuite                  int
}

func decodeCapabilityEnvelope(input []byte) (capability, capabilityOffsets, envelopeError) {
	if _, err := inspectEnvelope(input, 0x0030, 1, 22024); err != "" {
		return capability{}, capabilityOffsets{}, err
	}
	_, width, _ := decodeLength(input[4:])
	c := capCursor{body: input[4+width:]}
	var out capability
	var offsets capabilityOffsets
	var err envelopeError
	if out.id, err = c.take(48); err != "" {
		return out, offsets, err
	}
	out.id = append([]byte(nil), out.id...)
	offsets.issuer = c.pos
	if out.issuer, err = c.take(48); err != "" {
		return out, offsets, err
	}
	out.issuer = append([]byte(nil), out.issuer...)
	if out.holder, err = c.holder(); err != "" {
		return out, offsets, err
	}
	parentTagOffset := c.pos
	if out.parent, err = c.optionBytes(48); err != "" {
		return out, offsets, err
	}
	if out.parent.set {
		offsets.parentValue = parentTagOffset + 1
	}
	offsets.actionCount = c.pos
	count, err := c.length(32)
	if err != "" {
		return out, offsets, err
	}
	if count == 0 {
		return out, offsets, errActionSet
	}
	offsets.firstAction = c.pos
	for i := uint32(0); i < count; i++ {
		action, e := c.take(48)
		if e != "" {
			return out, offsets, e
		}
		copyAction := append([]byte(nil), action...)
		if len(out.actions) > 0 && bytes.Compare(out.actions[len(out.actions)-1], copyAction) >= 0 {
			return out, offsets, errActionSet
		}
		out.actions = append(out.actions, copyAction)
	}
	offsets.resourceTag = c.pos
	if out.resource, err = c.scope(); err != "" {
		return out, offsets, err
	}
	if out.data, err = c.scope(); err != "" {
		return out, offsets, err
	}
	monetaryTag := c.pos
	if out.monetary, err = c.optionU128(); err != "" {
		return out, offsets, err
	}
	if out.monetary.set {
		offsets.monetaryValue = monetaryTag + 1
	}
	computeTag := c.pos
	if out.compute, err = c.optionU128(); err != "" {
		return out, offsets, err
	}
	if out.compute.set {
		offsets.computeValue = computeTag + 1
	}
	rateTag, err := c.byte()
	if err != "" {
		return out, offsets, err
	}
	if rateTag > 1 {
		return out, offsets, errInvalidOption
	}
	if rateTag == 1 {
		offsets.rateUses = c.pos
		out.rate.set = true
		if out.rate.uses, err = c.u64(); err != "" {
			return out, offsets, err
		}
		offsets.rateWindow = c.pos
		if out.rate.window, err = c.u64(); err != "" {
			return out, offsets, err
		}
		if out.rate.uses == 0 || out.rate.window == 0 {
			return out, offsets, errRateLimit
		}
	}
	usesTag := c.pos
	if out.uses, err = c.optionU64(); err != "" {
		return out, offsets, err
	}
	if out.uses.set {
		offsets.usesValue = usesTag + 1
	}
	offsets.validFrom = c.pos
	if out.validFrom, err = c.u64(); err != "" {
		return out, offsets, err
	}
	validTagOffset := c.pos
	if out.validUntil, err = c.optionU64(); err != "" {
		return out, offsets, err
	}
	if out.validUntil.set {
		offsets.validUntilValue = validTagOffset + 1
	}
	offsets.depth = c.pos
	if out.depth, err = c.byte(); err != "" {
		return out, offsets, err
	}
	offsets.delegation = c.pos
	delegation, err := c.byte()
	if err != "" {
		return out, offsets, err
	}
	if delegation > 1 {
		return out, offsets, errBoolean
	}
	out.delegation = delegation == 1
	revocationTag := c.pos
	if out.revocation, err = c.optionBytes(48); err != "" {
		return out, offsets, err
	}
	if out.revocation.set {
		offsets.revocationValue = revocationTag + 1
	}
	offsets.constraint = c.pos
	if out.constraint, err = c.take(48); err != "" {
		return out, offsets, err
	}
	out.constraint = append([]byte(nil), out.constraint...)
	offsets.signatureSuite = c.pos
	suiteBytes, err := c.take(6)
	if err != "" {
		return out, offsets, err
	}
	suite, suiteErr := registeredSuite(suiteBytes)
	if suiteErr != "" || suite.signatureLength == 0 {
		return out, offsets, errCryptoSuite
	}
	sigLength, err := c.length(20000)
	if err != "" {
		return out, offsets, err
	}
	if int(sigLength) != suite.signatureLength {
		return out, offsets, errSignatureLength
	}
	if _, err = c.take(int(sigLength)); err != "" {
		return out, offsets, err
	}
	if c.pos != len(c.body) {
		return out, offsets, errTrailingData
	}
	if out.parent.set && bytes.Equal(out.parent.value, out.id) {
		return out, offsets, errSelfParent
	}
	if out.validUntil.set && out.validUntil.value < out.validFrom {
		return out, offsets, errValidityInversion
	}
	if (out.delegation && out.depth == 0) || (!out.delegation && out.depth != 0) {
		return out, offsets, errDelegationState
	}
	return out, offsets, ""
}

func scopeSubset(child, parent scope) bool {
	if parent.kind == 0 {
		return true
	}
	if child.kind == 0 {
		return false
	}
	if parent.kind == 1 {
		return child.kind == 1 && bytes.Equal(child.value, parent.value)
	}
	if child.bits < parent.bits {
		return false
	}
	full, rem := int(parent.bits/8), uint8(parent.bits%8)
	if !bytes.Equal(child.value[:full], parent.value[:full]) {
		return false
	}
	return rem == 0 || child.value[full]&(0xff<<(8-rem)) == parent.value[full]&(0xff<<(8-rem))
}

func optional128Attenuated(parent, child optionalU128) bool {
	return !parent.set || (child.set && bytes.Compare(child.value[:], parent.value[:]) <= 0)
}
func optional64Attenuated(parent, child optionalU64) bool {
	return !parent.set || (child.set && child.value <= parent.value)
}

func verifyCapabilityAttenuation(parent, child capability) bool {
	if !parent.delegation || !child.parent.set || !bytes.Equal(child.parent.value, parent.id) {
		return false
	}
	if parent.holder.kind != 0 || !bytes.Equal(child.issuer, parent.holder.value) || child.holder.kind == 2 {
		return false
	}
	for _, action := range child.actions {
		found := false
		for _, allowed := range parent.actions {
			if bytes.Equal(action, allowed) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !scopeSubset(child.resource, parent.resource) || !scopeSubset(child.data, parent.data) {
		return false
	}
	if !optional128Attenuated(parent.monetary, child.monetary) || !optional128Attenuated(parent.compute, child.compute) {
		return false
	}
	if parent.rate.set && (!child.rate.set || child.rate.window != parent.rate.window || child.rate.uses > parent.rate.uses) {
		return false
	}
	if !optional64Attenuated(parent.uses, child.uses) || child.validFrom < parent.validFrom {
		return false
	}
	if !optional64Attenuated(parent.validUntil, child.validUntil) || child.depth >= parent.depth {
		return false
	}
	if !bytes.Equal(child.constraint, parent.constraint) {
		return false
	}
	if parent.revocation.set && (!child.revocation.set || !bytes.Equal(child.revocation.value, parent.revocation.value)) {
		return false
	}
	return true
}

func applyCapabilityMutation(envelope []byte, mutation string) ([]byte, error) {
	if mutation == "none" || mutation == "truncate:1" || mutation == "append:00" {
		return mutateEnvelopeBody(envelope, mutation)
	}
	capability, offsets, err := decodeCapabilityEnvelope(envelope)
	if err != "" {
		return nil, fmt.Errorf("base capability: %s", err)
	}
	switch mutation {
	case "self_parent":
		if !capability.parent.set {
			return nil, fmt.Errorf("self-parent mutation requires delegated capability")
		}
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_hex:%d:%x", offsets.parentValue, capability.id))
	case "empty_actions":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:00", offsets.actionCount))
	case "duplicate_action":
		if len(capability.actions) < 2 {
			return nil, fmt.Errorf("duplicate-action mutation requires two actions")
		}
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_hex:%d:%x", offsets.firstAction+48, capability.actions[0]))
	case "malformed_resource":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:02", offsets.resourceTag))
	case "wrong_parent":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:ff", offsets.parentValue))
	case "wrong_issuer":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:ff", offsets.issuer))
	case "unsupported_action":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:ff", offsets.firstAction))
	case "monetary_escalation":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_hex:%d:ffffffffffffffffffffffffffffffff", offsets.monetaryValue))
	case "compute_escalation":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_hex:%d:ffffffffffffffffffffffffffffffff", offsets.computeValue))
	case "rate_escalation":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:101", offsets.rateUses))
	case "rate_window_change":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:51", offsets.rateWindow))
	case "uses_escalation":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:501", offsets.usesValue))
	case "early_validity":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:0", offsets.validFrom))
	case "late_expiry":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:1001", offsets.validUntilValue))
	case "depth_escalation":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:02", offsets.depth))
	case "revocation_change":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:ff", offsets.revocationValue))
	case "constraint_change":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:ff", offsets.constraint))
	case "zero_rate":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:0", offsets.rateUses))
	case "validity_inversion":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set_u64:%d:0", offsets.validUntilValue))
	case "zero_depth_allowed":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:00", offsets.depth))
	case "depth_forbidden":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:00", offsets.delegation))
	case "signature_suite":
		return mutateEnvelopeBody(envelope, fmt.Sprintf("set:%d:04", offsets.signatureSuite))
	default:
		return nil, fmt.Errorf("unknown capability mutation %q", mutation)
	}
}

func verifyCapabilityVector(path string, v vector) error {
	if len(v.fields) != 6 {
		return fmt.Errorf("case %q: expected 6 fields", v.name)
	}
	source := filepath.Join(filepath.Dir(path), filepath.FromSlash(v.fields[1]))
	parentBytes, err := readNamedHex(source, v.fields[2])
	if err != nil {
		return err
	}
	childBytes, err := readNamedHex(source, v.fields[3])
	if err != nil {
		return err
	}
	mutation := v.fields[4]
	if len(mutation) > 7 && mutation[:7] == "parent:" {
		parentBytes, err = applyCapabilityMutation(parentBytes, mutation[7:])
	} else {
		childBytes, err = applyCapabilityMutation(childBytes, mutation)
	}
	if err != nil {
		return err
	}
	parent, _, parentErr := decodeCapabilityEnvelope(parentBytes)
	child, _, childErr := decodeCapabilityEnvelope(childBytes)
	actual := parentErr
	if actual == "" {
		actual = childErr
	}
	expected := envelopeError(v.fields[5])
	if expected == "ok" {
		expected = ""
	}
	if actual == "" && !verifyCapabilityAttenuation(parent, child) {
		actual = errAttenuation
	}
	if actual != expected {
		return fmt.Errorf("case %q: expected %q, got %q", v.name, expected, actual)
	}
	return nil
}
