package tbft

import (
	"github.com/tendermint/go-amino"
	"github.com/taiyuechain/taiyuechain/consensus/tbft/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterConsensusMessages(cdc)
	// RegisterWALMessages(cdc)
	types.RegisterBlockAmino(cdc)
}
