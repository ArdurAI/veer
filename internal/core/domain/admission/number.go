package admission

import (
	"encoding/json"
	"math"
	"strings"
)

// nonNegativeInt64 parses the exact mathematical value of a JSON number. It
// accepts integral decimal and exponent spellings such as 1.0 and 1e0 without
// converting through binary floating point.
func nonNegativeInt64(number json.Number) (int64, bool) {
	text := string(number)
	if text == "" {
		return 0, false
	}
	negative := text[0] == '-'
	if negative {
		text = text[1:]
		if text == "" {
			return 0, false
		}
	}

	mantissa := text
	exponent := 0
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		mantissa = text[:index]
		var valid bool
		exponent, valid = clampedDecimalExponent(text[index+1:])
		if !valid {
			return 0, false
		}
	}
	integerPart := mantissa
	fractionPart := ""
	hasFraction := false
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		hasFraction = true
		integerPart = mantissa[:index]
		fractionPart = mantissa[index+1:]
	}
	if integerPart == "" || (len(integerPart) > 1 && integerPart[0] == '0') || !decimalDigits(integerPart) ||
		(hasFraction && (fractionPart == "" || !decimalDigits(fractionPart))) {
		return 0, false
	}
	digits := integerPart + fractionPart
	allZero := true
	for index := 0; index < len(digits); index++ {
		if digits[index] != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return 0, true
	}
	if negative {
		return 0, false
	}

	scale := exponent - len(fractionPart)
	if scale < 0 {
		drop := -scale
		if drop >= len(digits) {
			return 0, false
		}
		for index := len(digits) - drop; index < len(digits); index++ {
			if digits[index] != '0' {
				return 0, false
			}
		}
		digits = digits[:len(digits)-drop]
		scale = 0
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0, true
	}
	if scale > 19 || len(digits)+scale > 19 {
		return 0, false
	}

	var result int64
	for index := 0; index < len(digits); index++ {
		digit := int64(digits[index] - '0')
		if result > (math.MaxInt64-digit)/10 {
			return 0, false
		}
		result = result*10 + digit
	}
	for ; scale > 0; scale-- {
		if result > math.MaxInt64/10 {
			return 0, false
		}
		result *= 10
	}
	return result, true
}

func clampedDecimalExponent(text string) (int, bool) {
	if text == "" {
		return 0, false
	}
	sign := 1
	if text[0] == '+' || text[0] == '-' {
		if text[0] == '-' {
			sign = -1
		}
		text = text[1:]
		if text == "" {
			return 0, false
		}
	}
	value := 0
	limit := MaxRawBytes + 1
	for index := 0; index < len(text); index++ {
		if text[index] < '0' || text[index] > '9' {
			return 0, false
		}
		digit := int(text[index] - '0')
		if value > (limit-digit)/10 {
			value = limit
			continue
		}
		value = value*10 + digit
		if value > limit {
			value = limit
		}
	}
	return sign * value, true
}

func decimalDigits(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] < '0' || text[index] > '9' {
			return false
		}
	}
	return true
}
