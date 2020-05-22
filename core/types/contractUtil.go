package types

import (
	"github.com/taiyuechain/taiyuechain/common"
	"math/big"

	"bytes"
	"errors"
	"fmt"
)

var (
	CACertListAddress = common.BytesToAddress([]byte("CACertList"))
	PermiTableAddress = common.BytesToAddress([]byte("PermiTableAddress"))
	baseUnit          = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	fbaseUnit         = new(big.Float).SetFloat64(float64(baseUnit.Int64()))
)

var (
	ErrForbidAddress = errors.New("Forbidding Address")
)

func ForbidAddress(addr common.Address) error {
	if bytes.Equal(addr[:], CACertListAddress[:]) {
		return errors.New(fmt.Sprint("addr error:", addr, ErrForbidAddress))
	}
	return nil
}

func ToTai(val *big.Int) *big.Float {
	return new(big.Float).Quo(new(big.Float).SetInt(val), fbaseUnit)
}
