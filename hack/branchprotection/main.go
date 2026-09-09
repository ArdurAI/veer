package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
)

const maximumPolicyBytes = 64 * 1024

const expectedPolicy = `{
  "required_status_checks": {
    "strict": true,
    "contexts": [],
    "checks": [
      {"context": "DCO exact-head", "app_id": 15368},
      {"context": "Clean checkout contract", "app_id": 15368},
      {"context": "Race and coverage", "app_id": 15368},
      {"context": "Supported platform (Linux arm64)", "app_id": 15368},
      {"context": "Supported platform (macOS arm64)", "app_id": 15368},
      {"context": "Supported platform (macOS Intel)", "app_id": 15368},
      {"context": "Dependency review", "app_id": 15368},
      {"context": "Repository scan", "app_id": 15368},
      {"context": "CodeQL", "app_id": 15368},
      {"context": "SBOM", "app_id": 15368}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismissal_restrictions": {},
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true
}`

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "veer-branch-protection: %v\n", err)
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	policy, err := io.ReadAll(io.LimitReader(input, maximumPolicyBytes+1))
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if len(policy) > maximumPolicyBytes {
		return fmt.Errorf("policy exceeds %d bytes", maximumPolicyBytes)
	}
	if err := verifyPolicy(policy); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "veer-branch-protection status=passed")
	return err
}

func verifyPolicy(policy []byte) error {
	actual, err := decodeJSON(policy)
	if err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	required, err := decodeJSON([]byte(expectedPolicy))
	if err != nil {
		return fmt.Errorf("invalid embedded policy: %w", err)
	}
	if !reflect.DeepEqual(actual, required) {
		return errors.New("policy differs from required effective policy")
	}
	return nil
}

func decodeJSON(document []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	value, err := decodeValue(decoder, "$")
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected token after policy: %v", token)
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, path string) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}

	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("%s: object key is not a string", path)
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("%s: duplicate object key %q", path, key)
			}
			value, err := decodeValue(decoder, path+"."+key)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		var array []any
		for index := 0; decoder.More(); index++ {
			value, err := decodeValue(decoder, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("%s: unexpected delimiter %q", path, delimiter)
	}
}
