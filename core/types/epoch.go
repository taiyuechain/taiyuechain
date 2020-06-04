package types

import "math/big"

const (
	EpochSize          = uint64(1000)
	EpochElectionPoint = uint64(100) //Notice election validator before switch epoch
)

func GetEpochIDFromHeight(height *big.Int) *big.Int {
	return new(big.Int).Div(height, big.NewInt(int64(EpochSize)))
}
func GetEpochHeigth(eid *big.Int) (*big.Int, *big.Int) {
	begin := new(big.Int).Mul(eid, big.NewInt(int64(EpochSize)))
	return begin, new(big.Int).Add(begin, big.NewInt(int64(EpochSize-1)))
}
