package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	errAPLLanguage      envelopeError = "apl_language"
	errAPLEffect        envelopeError = "apl_effect"
	errAPLPredicate     envelopeError = "apl_predicate"
	errAPLObligation    envelopeError = "apl_obligation"
	errAPLRequest       envelopeError = "apl_request"
	errAPLDecision      envelopeError = "apl_decision"
	errAPLDecisionDrift envelopeError = "apl_decision_drift"
	errAPLZeroThreshold envelopeError = "apl_zero_threshold"
	errAPLFactOrder     envelopeError = "apl_fact_order"
)

type aplCursor struct {
	body []byte
	pos  int
}

func (c *aplCursor) take(n int) ([]byte, envelopeError) {
	if n < 0 || c.pos+n > len(c.body) {
		return nil, errUnexpectedEnd
	}
	out := c.body[c.pos : c.pos+n]
	c.pos += n
	return out, ""
}

func (c *aplCursor) byte() (byte, envelopeError) {
	b, err := c.take(1)
	if err != "" {
		return 0, err
	}
	return b[0], ""
}

func (c *aplCursor) u16() (uint16, envelopeError) {
	b, err := c.take(2)
	if err != "" {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), ""
}

func (c *aplCursor) u64() (uint64, envelopeError) {
	b, err := c.take(8)
	if err != "" {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), ""
}

func (c *aplCursor) u128() ([16]byte, envelopeError) {
	var out [16]byte
	b, err := c.take(16)
	if err != "" {
		return out, err
	}
	copy(out[:], b)
	return out, ""
}

func (c *aplCursor) length(max uint32) (uint32, envelopeError) {
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

type aplActor struct {
	kind  byte
	value [48]byte
}

type aplSelector struct {
	kind  byte
	bits  uint16
	value [48]byte
}

type aplPredicate struct {
	kind     byte
	actor    aplActor
	digest   [48]byte
	selector aplSelector
	amount   [16]byte
	height   uint64
	minimum  byte
	freeze   byte
}

type aplObligation struct {
	raw []byte
}

type aplRule struct {
	effect      byte
	predicates  []aplPredicate
	obligations []aplObligation
}

type aplPolicy struct {
	rules []aplRule
}

type aplApproval struct {
	role  [48]byte
	count byte
}

type aplRequest struct {
	actor            aplActor
	action, resource [48]byte
	height           uint64
	value            [16]byte
	freeze           byte
	purpose          *[48]byte
	credentials      [][48]byte
	capabilities     [][48]byte
	approvals        []aplApproval
}

type aplDecision struct {
	result, permits, forbids byte
	steps                    uint16
	obligations              []aplObligation
}

type aplOffsets struct {
	firstEffect, firstPredicate int
	actorValue, height, value   int
	freeze                      int
}

func aplDigest(c *aplCursor) ([48]byte, envelopeError) {
	var out [48]byte
	b, err := c.take(48)
	if err != "" {
		return out, err
	}
	copy(out[:], b)
	return out, ""
}

func aplDecodeActor(c *aplCursor) (aplActor, envelopeError) {
	kind, err := c.byte()
	if err != "" {
		return aplActor{}, err
	}
	if kind > 1 {
		return aplActor{}, errAPLRequest
	}
	value, err := aplDigest(c)
	return aplActor{kind: kind, value: value}, err
}

func aplDecodeSelector(c *aplCursor) (aplSelector, envelopeError) {
	kind, err := c.byte()
	if err != "" {
		return aplSelector{}, err
	}
	if kind == 0 {
		return aplSelector{kind: kind}, ""
	}
	if kind == 1 {
		value, err := aplDigest(c)
		return aplSelector{kind: kind, bits: 384, value: value}, err
	}
	if kind != 2 {
		return aplSelector{}, errAPLPredicate
	}
	bits, err := c.u16()
	if err != "" {
		return aplSelector{}, err
	}
	value, err := aplDigest(c)
	if err != "" {
		return aplSelector{}, err
	}
	if bits == 0 || bits >= 384 || !normalizedPrefix(value[:], bits) {
		return aplSelector{}, errAPLPredicate
	}
	return aplSelector{kind: kind, bits: bits, value: value}, ""
}

func aplDecodePredicate(c *aplCursor) (aplPredicate, envelopeError) {
	kind, err := c.byte()
	if err != "" {
		return aplPredicate{}, err
	}
	out := aplPredicate{kind: kind}
	switch kind {
	case 0:
		out.actor, err = aplDecodeActor(c)
	case 1, 7, 8, 11:
		out.digest, err = aplDigest(c)
	case 2:
		out.selector, err = aplDecodeSelector(c)
	case 3, 4:
		out.amount, err = c.u128()
	case 5, 6:
		out.height, err = c.u64()
	case 9:
		out.digest, err = aplDigest(c)
		if err == "" {
			out.minimum, err = c.byte()
			if err == "" && out.minimum == 0 {
				err = errAPLZeroThreshold
			}
		}
	case 10:
		out.freeze, err = c.byte()
		if err == "" && out.freeze > 2 {
			err = errAPLPredicate
		}
	default:
		return aplPredicate{}, errAPLPredicate
	}
	return out, err
}

func aplDecodeObligation(c *aplCursor) (aplObligation, envelopeError) {
	start := c.pos
	kind, err := c.byte()
	if err != "" {
		return aplObligation{}, err
	}
	switch kind {
	case 0:
		_, err = c.take(48 + 16)
	case 1, 2, 5:
		_, err = c.take(48)
	case 3:
		if _, err = c.take(48); err == "" {
			var minimum byte
			minimum, err = c.byte()
			if err == "" && minimum == 0 {
				err = errAPLZeroThreshold
			}
		}
	case 4:
		_, err = c.take(8)
	default:
		return aplObligation{}, errAPLObligation
	}
	if err != "" {
		return aplObligation{}, err
	}
	return aplObligation{raw: append([]byte(nil), c.body[start:c.pos]...)}, ""
}

func decodeAPLPolicy(input []byte) (aplPolicy, aplOffsets, envelopeError) {
	if _, err := inspectEnvelope(input, 0x0040, 1, 52771); err != "" {
		return aplPolicy{}, aplOffsets{}, err
	}
	_, width, _ := decodeLength(input[4:])
	c := aplCursor{body: input[4+width:]}
	language, err := c.u16()
	if err != "" {
		return aplPolicy{}, aplOffsets{}, err
	}
	if language != 1 {
		return aplPolicy{}, aplOffsets{}, errAPLLanguage
	}
	count, err := c.length(32)
	if err != "" {
		return aplPolicy{}, aplOffsets{}, err
	}
	out := aplPolicy{rules: make([]aplRule, 0, count)}
	var offsets aplOffsets
	for i := uint32(0); i < count; i++ {
		if i == 0 {
			offsets.firstEffect = c.pos
		}
		effect, e := c.byte()
		if e != "" || effect > 1 {
			return aplPolicy{}, offsets, errAPLEffect
		}
		predicateCount, e := c.length(16)
		if e != "" {
			return aplPolicy{}, offsets, e
		}
		rule := aplRule{effect: effect, predicates: make([]aplPredicate, 0, predicateCount)}
		for j := uint32(0); j < predicateCount; j++ {
			if i == 0 && j == 0 {
				offsets.firstPredicate = c.pos
			}
			predicate, e := aplDecodePredicate(&c)
			if e != "" {
				return aplPolicy{}, offsets, e
			}
			rule.predicates = append(rule.predicates, predicate)
		}
		obligationCount, e := c.length(4)
		if e != "" {
			return aplPolicy{}, offsets, e
		}
		if effect == 1 && obligationCount != 0 {
			return aplPolicy{}, offsets, errAPLObligation
		}
		for j := uint32(0); j < obligationCount; j++ {
			obligation, e := aplDecodeObligation(&c)
			if e != "" {
				return aplPolicy{}, offsets, e
			}
			rule.obligations = append(rule.obligations, obligation)
		}
		out.rules = append(out.rules, rule)
	}
	if c.pos != len(c.body) {
		return aplPolicy{}, offsets, errTrailingData
	}
	return out, offsets, ""
}

func decodeAPLRequest(input []byte) (aplRequest, aplOffsets, envelopeError) {
	if _, err := inspectEnvelope(input, 0x0041, 1, 4078); err != "" {
		return aplRequest{}, aplOffsets{}, err
	}
	_, width, _ := decodeLength(input[4:])
	c := aplCursor{body: input[4+width:]}
	var out aplRequest
	var offsets aplOffsets
	var err envelopeError
	offsets.actorValue = c.pos + 1
	if out.actor, err = aplDecodeActor(&c); err != "" {
		return out, offsets, err
	}
	if out.action, err = aplDigest(&c); err != "" {
		return out, offsets, err
	}
	if out.resource, err = aplDigest(&c); err != "" {
		return out, offsets, err
	}
	offsets.height = c.pos
	if out.height, err = c.u64(); err != "" {
		return out, offsets, err
	}
	offsets.value = c.pos
	if out.value, err = c.u128(); err != "" {
		return out, offsets, err
	}
	offsets.freeze = c.pos
	if out.freeze, err = c.byte(); err != "" || out.freeze > 2 {
		return out, offsets, errAPLRequest
	}
	present, err := c.byte()
	if err != "" || present > 1 {
		return out, offsets, errInvalidOption
	}
	if present == 1 {
		purpose, e := aplDigest(&c)
		if e != "" {
			return out, offsets, e
		}
		out.purpose = &purpose
	}
	if out.credentials, err = aplDecodeDigestSet(&c, 32); err != "" {
		return out, offsets, err
	}
	if out.capabilities, err = aplDecodeDigestSet(&c, 32); err != "" {
		return out, offsets, err
	}
	approvalCount, err := c.length(16)
	if err != "" {
		return out, offsets, err
	}
	for i := uint32(0); i < approvalCount; i++ {
		role, e := aplDigest(&c)
		if e != "" {
			return out, offsets, e
		}
		count, e := c.byte()
		if e != "" || count == 0 {
			return out, offsets, errAPLZeroThreshold
		}
		if len(out.approvals) > 0 && bytes.Compare(out.approvals[len(out.approvals)-1].role[:], role[:]) >= 0 {
			return out, offsets, errAPLFactOrder
		}
		out.approvals = append(out.approvals, aplApproval{role: role, count: count})
	}
	if c.pos != len(c.body) {
		return out, offsets, errTrailingData
	}
	return out, offsets, ""
}

func aplDecodeDigestSet(c *aplCursor, maximum uint32) ([][48]byte, envelopeError) {
	count, err := c.length(maximum)
	if err != "" {
		return nil, err
	}
	out := make([][48]byte, 0, count)
	for i := uint32(0); i < count; i++ {
		value, e := aplDigest(c)
		if e != "" {
			return nil, e
		}
		if len(out) > 0 && bytes.Compare(out[len(out)-1][:], value[:]) >= 0 {
			return nil, errAPLFactOrder
		}
		out = append(out, value)
	}
	return out, ""
}

func decodeAPLDecision(input []byte) (aplDecision, envelopeError) {
	if _, err := inspectEnvelope(input, 0x0042, 1, 8327); err != "" {
		return aplDecision{}, err
	}
	_, width, _ := decodeLength(input[4:])
	c := aplCursor{body: input[4+width:]}
	result, err := c.byte()
	if err != "" || result > 1 {
		return aplDecision{}, errAPLDecision
	}
	permits, err := c.byte()
	if err != "" {
		return aplDecision{}, err
	}
	forbids, err := c.byte()
	if err != "" || int(permits)+int(forbids) > 32 {
		return aplDecision{}, errAPLDecision
	}
	steps, err := c.u16()
	if err != "" || steps > 544 || int(steps) < int(permits)+int(forbids) {
		return aplDecision{}, errAPLDecision
	}
	count, err := c.length(128)
	if err != "" {
		return aplDecision{}, err
	}
	out := aplDecision{result: result, permits: permits, forbids: forbids, steps: steps}
	for i := uint32(0); i < count; i++ {
		obligation, e := aplDecodeObligation(&c)
		if e != "" {
			return aplDecision{}, e
		}
		out.obligations = append(out.obligations, obligation)
	}
	wantResult := byte(0)
	if permits > 0 && forbids == 0 {
		wantResult = 1
	}
	if result != wantResult || (result == 0 && len(out.obligations) != 0) || c.pos != len(c.body) {
		return aplDecision{}, errAPLDecision
	}
	return out, ""
}

func evaluateAPL(policy aplPolicy, request aplRequest) aplDecision {
	var out aplDecision
	for _, rule := range policy.rules {
		out.steps++
		matches := true
		for _, predicate := range rule.predicates {
			out.steps++
			matches = aplPredicateMatches(predicate, request) && matches
		}
		if !matches {
			continue
		}
		if rule.effect == 0 {
			out.permits++
			out.obligations = append(out.obligations, rule.obligations...)
		} else {
			out.forbids++
		}
	}
	if out.permits > 0 && out.forbids == 0 {
		out.result = 1
	} else {
		out.obligations = nil
	}
	return out
}

func aplPredicateMatches(predicate aplPredicate, request aplRequest) bool {
	switch predicate.kind {
	case 0:
		return predicate.actor == request.actor
	case 1:
		return predicate.digest == request.action
	case 2:
		return aplSelectorContains(predicate.selector, request.resource)
	case 3:
		return bytes.Compare(request.value[:], predicate.amount[:]) <= 0
	case 4:
		return bytes.Compare(request.value[:], predicate.amount[:]) >= 0
	case 5:
		return request.height >= predicate.height
	case 6:
		return request.height <= predicate.height
	case 7:
		return aplContainsDigest(request.credentials, predicate.digest)
	case 8:
		return aplContainsDigest(request.capabilities, predicate.digest)
	case 9:
		for _, approval := range request.approvals {
			if approval.role == predicate.digest {
				return approval.count >= predicate.minimum
			}
		}
		return false
	case 10:
		return request.freeze == predicate.freeze
	case 11:
		return request.purpose != nil && *request.purpose == predicate.digest
	default:
		return false
	}
}

func aplContainsDigest(values [][48]byte, target [48]byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func aplSelectorContains(selector aplSelector, resource [48]byte) bool {
	switch selector.kind {
	case 0:
		return true
	case 1:
		return selector.value == resource
	case 2:
		full, rem := int(selector.bits/8), uint8(selector.bits%8)
		if !bytes.Equal(selector.value[:full], resource[:full]) {
			return false
		}
		return rem == 0 || selector.value[full]>>(8-rem) == resource[full]>>(8-rem)
	default:
		return false
	}
}

func aplDecisionEqual(left, right aplDecision) bool {
	if left.result != right.result || left.permits != right.permits || left.forbids != right.forbids || left.steps != right.steps || len(left.obligations) != len(right.obligations) {
		return false
	}
	for i := range left.obligations {
		if !bytes.Equal(left.obligations[i].raw, right.obligations[i].raw) {
			return false
		}
	}
	return true
}

func applyAPLMutation(policy, request []byte, policyOffsets, requestOffsets aplOffsets, mutation string) ([]byte, []byte, error) {
	policy = append([]byte(nil), policy...)
	request = append([]byte(nil), request...)
	if mutation == "none" {
		return policy, request, nil
	}
	_, policyWidth, _ := decodeLength(policy[4:])
	_, requestWidth, _ := decodeLength(request[4:])
	policyBody := 4 + policyWidth
	requestBody := 4 + requestWidth
	switch mutation {
	case "request_actor":
		request[requestBody+requestOffsets.actorValue] ^= 0xff
	case "request_value_50", "request_value_2000":
		value := uint64(50)
		if mutation == "request_value_2000" {
			value = 2000
		}
		for i := 0; i < 16; i++ {
			request[requestBody+requestOffsets.value+i] = 0
		}
		binary.BigEndian.PutUint64(request[requestBody+requestOffsets.value+8:], value)
	case "request_height_30", "request_height_70":
		value := uint64(30)
		if mutation == "request_height_70" {
			value = 70
		}
		binary.BigEndian.PutUint64(request[requestBody+requestOffsets.height:], value)
	case "request_frozen":
		request[requestBody+requestOffsets.freeze] = 2
	case "invalid_effect":
		policy[policyBody+policyOffsets.firstEffect] = 2
	case "invalid_predicate":
		policy[policyBody+policyOffsets.firstPredicate] = 0xff
	case "policy_truncated":
		policy = policy[:len(policy)-1]
	case "request_trailing":
		request = append(request, 0)
	default:
		return nil, nil, fmt.Errorf("unknown APL mutation %q", mutation)
	}
	return policy, request, nil
}

func parseAPLExpected(value string) (aplDecision, envelopeError, error) {
	if value == "apl_effect" || value == "apl_predicate" || value == "body_length_mismatch" || value == "trailing_data" {
		return aplDecision{}, envelopeError(value), nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 5 {
		return aplDecision{}, "", fmt.Errorf("invalid APL expectation %q", value)
	}
	result := byte(0)
	if parts[0] == "permit" {
		result = 1
	} else if parts[0] != "deny" {
		return aplDecision{}, "", fmt.Errorf("invalid APL result %q", parts[0])
	}
	numbers := make([]uint64, 4)
	for i := range numbers {
		parsed, err := strconv.ParseUint(parts[i+1], 10, 16)
		if err != nil {
			return aplDecision{}, "", err
		}
		numbers[i] = parsed
	}
	return aplDecision{result: result, permits: byte(numbers[0]), forbids: byte(numbers[1]), steps: uint16(numbers[2]), obligations: make([]aplObligation, numbers[3])}, "", nil
}

func verifyAPLVector(path string, v vector) error {
	if len(v.fields) != 7 {
		return fmt.Errorf("case %q: expected 7 fields", v.name)
	}
	source := filepath.Join(filepath.Dir(path), filepath.FromSlash(v.fields[1]))
	policyBytes, err := readNamedHex(source, v.fields[2])
	if err != nil {
		return err
	}
	requestBytes, err := readNamedHex(source, v.fields[3])
	if err != nil {
		return err
	}
	decisionBytes, err := readNamedHex(source, v.fields[4])
	if err != nil {
		return err
	}
	_, policyOffsets, decodeErr := decodeAPLPolicy(policyBytes)
	if decodeErr != "" {
		return fmt.Errorf("source policy: %s", decodeErr)
	}
	_, requestOffsets, decodeErr := decodeAPLRequest(requestBytes)
	if decodeErr != "" {
		return fmt.Errorf("source request: %s", decodeErr)
	}
	policyBytes, requestBytes, err = applyAPLMutation(policyBytes, requestBytes, policyOffsets, requestOffsets, v.fields[5])
	if err != nil {
		return err
	}
	policy, _, policyErr := decodeAPLPolicy(policyBytes)
	request, _, requestErr := decodeAPLRequest(requestBytes)
	actualErr := policyErr
	if actualErr == "" {
		actualErr = requestErr
	}
	expected, expectedErr, err := parseAPLExpected(v.fields[6])
	if err != nil {
		return err
	}
	if expectedErr != "" {
		if actualErr != expectedErr {
			return fmt.Errorf("case %q: expected %s, got %s", v.name, expectedErr, actualErr)
		}
		return nil
	}
	if actualErr != "" {
		return fmt.Errorf("case %q: unexpected decode error %s", v.name, actualErr)
	}
	actual := evaluateAPL(policy, request)
	if actual.result != expected.result || actual.permits != expected.permits || actual.forbids != expected.forbids || actual.steps != expected.steps || len(actual.obligations) != len(expected.obligations) {
		return fmt.Errorf("case %q: decision got %d:%d:%d:%d:%d", v.name, actual.result, actual.permits, actual.forbids, actual.steps, len(actual.obligations))
	}
	if v.fields[5] == "none" {
		published, err := decodeAPLDecision(decisionBytes)
		if err != "" {
			return fmt.Errorf("published decision: %s", err)
		}
		if !aplDecisionEqual(actual, published) {
			return fmt.Errorf("case %q: %s", v.name, errAPLDecisionDrift)
		}
	}
	return nil
}
