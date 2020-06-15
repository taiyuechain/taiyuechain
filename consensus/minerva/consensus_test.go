// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package minerva

import (
	"encoding/json"
	"math/big"
	"testing"

	"fmt"
	osMath "math"

	"github.com/taiyuechain/taiyuechain/common/math"
)

var (
	FrontierBlockReward = big.NewInt(5e+18) // Block reward in wei for successfully mining a block
	//SnailBlockRewardsInitial Snail block rewards initial 116.48733*10^18
	SnailBlockRewardsInitial = new(big.Int).Mul(big.NewInt(11648733), big.NewInt(1e13))
)

type diffTest struct {
	ParentTimestamp    uint64
	ParentDifficulty   *big.Int
	CurrentTimestamp   uint64
	CurrentBlocknumber *big.Int
	CurrentDifficulty  *big.Int
}

func (d *diffTest) UnmarshalJSON(b []byte) (err error) {
	var ext struct {
		ParentTimestamp    string
		ParentDifficulty   string
		CurrentTimestamp   string
		CurrentBlocknumber string
		CurrentDifficulty  string
	}
	if err := json.Unmarshal(b, &ext); err != nil {
		return err
	}

	d.ParentTimestamp = math.MustParseUint64(ext.ParentTimestamp)
	d.ParentDifficulty = math.MustParseBig256(ext.ParentDifficulty)
	d.CurrentTimestamp = math.MustParseUint64(ext.CurrentTimestamp)
	d.CurrentBlocknumber = math.MustParseBig256(ext.CurrentBlocknumber)
	d.CurrentDifficulty = math.MustParseBig256(ext.CurrentDifficulty)

	return nil
}

//func (d *diffTest) MakeSnailChain（）{
//	blocks := snailchain.GenerateChain

//}

func TestAccountDiv(t *testing.T) {
	r := new(big.Int)
	println(r.Uint64())
	r = big.NewInt(600077777777777)
	println(r.Uint64())
	r.Div(r, big2999999)
	println(r.Uint64(), FrontierBlockReward.Uint64(), SnailBlockRewardsInitial.Bytes())
	fmt.Printf("%v", new(big.Int).Exp(new(big.Int).SetInt64(2),
		new(big.Int).Div(new(big.Int).Add(new(big.Int).SetInt64(5000), new(big.Int).SetInt64(12)), new(big.Int).SetInt64(5000)), nil))
}

func TestOutSqrt(t *testing.T) {
	var AConstSqrt []ConstSqrt
	var ARR []float64
	for i := 1; i <= 10000; i++ {

		tmp := osMath.Sqrt(float64(i)) / (osMath.Sqrt(float64(i)) + float64(MiningConstant))

		if tmp > 0.8 {
			break
		}

		if tmp < 0.2 {
			ARR = append(ARR, tmp)
			continue
		}
		ARR = append(ARR, tmp)
		AConstSqrt = append(AConstSqrt, ConstSqrt{Num: i, Sqrt: tmp})
	}

	b, _ := json.Marshal(AConstSqrt)
	fmt.Println(ARR)
	fmt.Println(string(b))
}
