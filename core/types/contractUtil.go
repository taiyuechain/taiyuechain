package types

import (
	"github.com/taiyuechain/taiyuechain/common"

	"bytes"
	"errors"
	"fmt"
)

var (
	CACertListAddress = common.BytesToAddress([]byte("CACertList"))
	PermiTableAddress = common.BytesToAddress([]byte("PermiTableAddress"))
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
