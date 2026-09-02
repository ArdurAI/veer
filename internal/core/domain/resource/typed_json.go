package resource

import (
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"reflect"
	"sync"
)

type typedJSONContractResult struct {
	err error
}

var (
	typedJSONContractCache sync.Map
	typedRawMessageType    = reflect.TypeFor[json.RawMessage]()
	typedJSONTextValueType = reflect.TypeFor[jsontext.Value]()
)

func validateTypedJSONContractFor[Value any](field string) error {
	target := reflect.TypeFor[Value]()
	if cached, ok := typedJSONContractCache.Load(target); ok {
		if err := cached.(typedJSONContractResult).err; err != nil {
			return fmt.Errorf("decode %s with exact JSON names or unknown fields: %w", field, err)
		}
		return nil
	}

	result := typedJSONContractResult{
		err: validateTypedJSONType(target, make(map[reflect.Type]bool)),
	}
	actual, _ := typedJSONContractCache.LoadOrStore(target, result)
	if err := actual.(typedJSONContractResult).err; err != nil {
		return fmt.Errorf("decode %s with exact JSON names or unknown fields: %w", field, err)
	}
	return nil
}

func validateTypedJSONType(target reflect.Type, visited map[reflect.Type]bool) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == typedRawMessageType || target == typedJSONTextValueType {
		return fmt.Errorf("unstructured %s is reserved for resource-envelope transport capture", target)
	}
	if target.Kind() == reflect.Interface || visited[target] {
		return nil
	}
	visited[target] = true

	switch target.Kind() {
	case reflect.Struct:
		for index := range target.NumField() {
			field := target.Field(index)
			tag, tagged := field.Tag.Lookup("json")
			if tag == "-" || (!field.IsExported() && !field.Anonymous) {
				continue
			}
			if tagged {
				for _, option := range splitJSONTagOptions(tag) {
					if option == "case:ignore" || option == "embed" || option == "inline" {
						return fmt.Errorf(
							"go type %s field %s cannot use JSON tag option %q in a closed typed boundary",
							target,
							field.Name,
							option,
						)
					}
				}
			}
			if err := validateTypedJSONType(field.Type, visited); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice, reflect.Map:
		return validateTypedJSONType(target.Elem(), visited)
	}
	return nil
}

func splitJSONTagOptions(tag string) []string {
	var parts []string
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(tag); index++ {
		character := tag[index]
		if quoted {
			switch {
			case escaped:
				escaped = false
			case character == '\\':
				escaped = true
			case character == '\'':
				quoted = false
			}
			continue
		}
		switch character {
		case '\'':
			quoted = true
		case ',':
			parts = append(parts, tag[start:index])
			start = index + 1
		}
	}
	parts = append(parts, tag[start:])
	if len(parts) < 2 {
		return nil
	}
	return parts[1:]
}
