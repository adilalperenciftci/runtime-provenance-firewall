package rpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxDocumentBytes = 64 << 20
	maxEventBytes    = 256 << 10
	maxStringBytes   = 32 << 10
	maxDepth         = 16
	maxValues        = 2000
	maxEvents        = 1_000_000
)

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func canonicalDigest(value any) (string, error) {
	raw, err := canonical(value)
	if err != nil {
		return "", err
	}
	return Digest(raw), nil
}

func decodeStrict(raw []byte, dst any, limit int64) error {
	if len(raw) == 0 || int64(len(raw)) > limit {
		return fmt.Errorf("document size %d outside accepted range", len(raw))
	}
	if err := validateJSONShape(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("strict JSON decode: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return err
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are forbidden")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func validateJSONShape(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	if err := walkJSON(decoder, 0, &count); err != nil {
		return err
	}
	return requireEOF(decoder)
}

func walkJSON(decoder *json.Decoder, depth int, count *int) error {
	if depth > maxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	*count++
	if *count > maxValues {
		return errors.New("JSON value count exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		if value, isString := token.(string); isString && len(value) > maxStringBytes {
			return errors.New("JSON string exceeds limit")
		}
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if len(key) > maxStringBytes {
				return errors.New("JSON object key exceeds string limit")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, depth+1, count); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkJSON(decoder, depth+1, count); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func decodeStatement(raw []byte) (Statement, error) {
	var statement Statement
	if err := decodeStrict(raw, &statement, maxDocumentBytes); err != nil {
		return Statement{}, err
	}
	if statement.Type != StatementType {
		return Statement{}, fmt.Errorf("unsupported statement type %q", statement.Type)
	}
	if len(statement.Subject) == 0 {
		return Statement{}, errors.New("statement has no subjects")
	}
	return statement, nil
}

func decodePolicy(raw []byte) (Policy, error) {
	var policy Policy
	if err := decodeStrict(raw, &policy, maxDocumentBytes); err != nil {
		return Policy{}, err
	}
	if policy.SchemaVersion != "0.1" {
		return Policy{}, fmt.Errorf("unsupported policy version %q", policy.SchemaVersion)
	}
	if policy.IncompleteDecision != "REVIEW" && policy.IncompleteDecision != "REJECT" {
		return Policy{}, errors.New("incomplete_decision must be REVIEW or REJECT")
	}
	if policy.ExpectedProvider == "" || len(policy.AllowedBuilderIDs) == 0 || len(policy.AllowedArtifactProducers) == 0 || len(policy.AllowedRepositories) == 0 {
		return Policy{}, errors.New("provider, builder, artifact producer, and repository allowlists are required")
	}
	return policy, nil
}
