package types

import (
	"github.com/ethereum/go-ethereum/common"

	"bytes"
	"errors"
	"fmt"
)


var (
	CACertListAddress = common.BytesToAddress([]byte("CACertList"))
)

var(
	ErrForbidAddress     = errors.New("Forbidding Address")
)

func ForbidAddress(addr common.Address) error {
	if bytes.Equal(addr[:], CACertListAddress[:]) {
		return errors.New(fmt.Sprint("addr error:", addr, ErrForbidAddress))
	}
	return nil
}