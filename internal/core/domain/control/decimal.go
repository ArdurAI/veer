package control

import (
	"errors"
	"math/big"
	"regexp"
)

// MaxDecimalLength bounds canonical amount and quota parsing work.
const MaxDecimalLength = 64

var (
	canonicalDecimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$`)
	ErrInvalidDecimal       = errors.New("invalid canonical non-negative decimal")
)

func validateCanonicalDecimal(value string) error {
	if len(value) == 0 || len(value) > MaxDecimalLength || !canonicalDecimalPattern.MatchString(value) {
		return ErrInvalidDecimal
	}
	return nil
}

func compareCanonicalDecimals(left, right string) (int, error) {
	if err := validateCanonicalDecimal(left); err != nil {
		return 0, err
	}
	if err := validateCanonicalDecimal(right); err != nil {
		return 0, err
	}
	leftValue, ok := new(big.Rat).SetString(left)
	if !ok {
		return 0, ErrInvalidDecimal
	}
	rightValue, ok := new(big.Rat).SetString(right)
	if !ok {
		return 0, ErrInvalidDecimal
	}
	return leftValue.Cmp(rightValue), nil
}
