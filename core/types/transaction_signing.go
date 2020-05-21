// Copyright 2016 The go-ethereum Authors
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

package types

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/taiyuechain/taiyuechain/crypto"
	//"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/common"
	"github.com/taiyuechain/taiyuechain/log"
	"math/big"
	//"github.com/taiyuechain/taiyuechain/crypto"
	"github.com/taiyuechain/taiyuechain/params"
)

var (
	ErrInvalidChainId = errors.New("invalid chain id for signer")
)

// sigCache is used to cache the derived sender and contains
// the signer used to derive it.
type sigCache struct {
	signer Signer
	from   common.Address
}

type sigCache_payment struct {
	signer  Signer
	payment common.Address
}

// MakeSigner returns a Signer based on the given chain config and block number.
func MakeSigner(config *params.ChainConfig, blockNumber *big.Int) Signer {
	signer := NewCommonSigner(config.ChainID)
	return signer
}

// SignTx signs the transaction using the given signer and private key
func SignTx(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature(s, sig)
}

/*func SignTxBy266(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	//sig, err := crypto.Sign(h[:], prv)
	sig, err := p256.SignP256(prv, h[:])
	if err != nil {
		return nil, err
	}
	tx.data.Sig = sig
	//tx.data.ChainID  = s.GetChainID()
	cpy := &Transaction{data: tx.data}
	return cpy, nil
}

func VerfiySignTxBy266(tx *Transaction, s Signer) error {
	h := s.Hash(tx)
	//VerifyP256(public ecdsa.PublicKey, hash []byte, sign []byte) bool
	cert, err := x509.ParseCertificate(tx.data.Cert)
	if err != nil {
		return err
	}
	var pubk *ecdsa.PublicKey
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubk.Curve = pub.Curve
		pubk.X = pub.X
		pubk.Y = pub.Y
	}

	if p256.VerifyP256(pubk, h[:], tx.data.Sig) {
		return nil
	}
	return errors.New("verfiy p256 err")
}

func SignTxBySM(tx *Transaction, s Signer, prv *sm2.PrivateKey) (*Transaction, error) {
	h := s.Hash(tx)
	//sig, err := crypto.Sign(h[:], prv)
	sig, err := sm2.Sign(prv, nil, h[:])
	if err != nil {
		return nil, err
	}
	tx.data.Sig = sig
	//tx.data.ChainID  = s.GetChainID()
	cpy := &Transaction{data: tx.data}
	return cpy, nil
}

func VerfiySignTxBySM(tx *Transaction, s Signer) error {
	h := s.Hash(tx)
	//VerifyP256(public ecdsa.PublicKey, hash []byte, sign []byte) bool
	cert, err := sm2_cert.ParseCertificateRequest(tx.data.Cert)
	if err != nil {
		return err
	}
	var topubk sm2.PublicKey
	switch pub := cert.PublicKey.(type) {
	case *sm2.PublicKey:
		topubk.Curve = pub.Curve
		topubk.X = pub.X
		topubk.Y = pub.Y
	}

	if sm2.Verify(&topubk, nil, h[:], tx.data.Sig) {
		return nil
	}
	return errors.New("verfiy tx sm2 err")
}*/

func SignTx_Payment(tx *Transaction, s Signer, prv *ecdsa.PrivateKey) (*Transaction, error) {
	h := s.Hash_Payment(tx)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return tx.WithSignature_Payment(s, sig)
}

// PSender returns the address derived from the signature (PV, PR, PS) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
func Payer(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.payment.Load(); sc != nil {
		sigCache_payment := sc.(sigCache_payment)
		if sigCache_payment.signer.Equal(signer) {
			return sigCache_payment.payment, nil
		}
	}
	if tx.data.Payer == nil {
		return params.EmptyAddress, nil
	}
	addr, err := signer.Payer(tx)
	if err != nil {
		return params.EmptyAddress, err
	}
	if addr != *tx.data.Payer {
		log.Error("Payer err,signed_addr !=tx.data.Payer ", "signed_payer", addr, "tx_payer", *tx.data.Payer)
		return params.EmptyAddress, ErrPayersign
	}
	tx.payment.Store(sigCache_payment{signer: signer, payment: addr})
	return addr, nil
}

// Sender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
// Sender may cache the address, allowing it to be used regardless of
// signing method. The cache is invalidated if the cached signer does
// not match the signer used in the current call.
func Sender(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}

	addr, err := signer.Sender(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil
}

/*func SenderP256(signer Signer, tx *Transaction) (common.Address, error) {
	if sc := tx.from.Load(); sc != nil {
		sigCache := sc.(sigCache)
		// If the signer used to derive from in a previous
		// call is not the same as used current, invalidate
		// the cache.
		if sigCache.signer.Equal(signer) {
			return sigCache.from, nil
		}
	}
	//verify tx sign
	err := VerfiySignTxBy266(tx, signer)
	if err != nil {
		return common.Address{}, err
	}

	addr, err := signer.SenderP256(tx)
	if err != nil {
		return common.Address{}, err
	}
	tx.from.Store(sigCache{signer: signer, from: addr})
	return addr, nil

}
*/
// Signer encapsulates transaction signature handling. Note that this interface is not a
// stable API and may change at any time to accommodate new protocol rules.
type Signer interface {
	// Sender returns the sender address of the transaction.
	Sender(tx *Transaction) (common.Address, error)
	// PSender returns the paid address of the transaction.
	Payer(tx *Transaction) (common.Address, error)
	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error)
	// Hash returns the hash to be signed.
	Hash(tx *Transaction) common.Hash

	Hash_Payment(tx *Transaction) common.Hash
	// Equal returns true if the given signer is the same as the receiver.
	Equal(Signer) bool

	//SenderP256(tx *Transaction) (common.Address, error)
}

func NewSigner(chainId *big.Int) Signer {
	if chainId == nil {
		chainId = new(big.Int)
	}
	CommonSigner := CommonSigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
	return CommonSigner
}

type CommonSigner struct {
	chainId, chainIdMul *big.Int
}

func NewCommonSigner(chainId *big.Int) Signer {
	return NewSigner(chainId)
}

func (s CommonSigner) Equal(s2 Signer) bool {
	tip1, ok := s2.(CommonSigner)
	return ok && tip1.chainId.Cmp(s.chainId) == 0
}

var big8 = big.NewInt(8)

func (s CommonSigner) Sender(tx *Transaction) (common.Address, error) {
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	V := new(big.Int).Sub(tx.data.V, s.chainIdMul)
	V.Sub(V, big8)
	return recoverPlain(s.Hash(tx), tx.data.Sig, tx.data.Cert)
}

func (s CommonSigner) Payer(tx *Transaction) (common.Address, error) {
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, ErrInvalidChainId
	}
	PV := new(big.Int).Sub(tx.data.PV, s.chainIdMul)
	PV.Sub(PV, big8)
	return recoverPlain(s.Hash_Payment(tx), tx.data.Sig, tx.data.Cert)
}

// WithSignature returns a new transaction with the given signature. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s CommonSigner) SignatureValues(tx *Transaction, sig []byte) (R, S, V *big.Int, err error) {
	tx.data.Sig = sig
	R, S, V, err = SignatureValues(tx, sig)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.chainId.Sign() != 0 {
		V = big.NewInt(int64(sig[64] + 35))
		V.Add(V, s.chainIdMul)
	}
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s CommonSigner) GetChainID() *big.Int {
	return s.chainId
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s CommonSigner) Hash(tx *Transaction) common.Hash {
	//fmt.Println("Hash method,tx.data.Payer", tx.data.Payer)
	var hash common.Hash
	//payer and fee is nil or default value
	if tx.data.Fee != nil && tx.data.Fee.Uint64() == 0 {
		tx.data.Fee = nil
	}
	if (tx.data.Payer == nil || *tx.data.Payer == (common.Address{})) && tx.data.Fee == nil {
		hash = rlpHash([]interface{}{
			tx.data.AccountNonce,
			tx.data.Price,
			tx.data.GasLimit,
			tx.data.Recipient,
			tx.data.Amount,
			tx.data.Payload,
			s.chainId, uint(0), uint(0),
		})
	} else { //payer is not nil
		hash = rlpHash([]interface{}{
			tx.data.AccountNonce,
			tx.data.Price,
			tx.data.GasLimit,
			tx.data.Recipient,
			tx.data.Amount,
			tx.data.Payload,
			tx.data.Payer,
			tx.data.Fee,
			s.chainId, uint(0), uint(0),
		})
	}
	return hash
}

func (s CommonSigner) Hash_Payment(tx *Transaction) common.Hash {
	return rlpHash([]interface{}{
		tx.data.AccountNonce,
		tx.data.Price,
		tx.data.GasLimit,
		tx.data.Recipient,
		tx.data.Amount,
		tx.data.Payload,
		tx.data.Payer,
		tx.data.Fee,
		tx.data.V,
		tx.data.R,
		tx.data.S,
		s.chainId, uint(0), uint(0),
	})
}

func SignatureValues(tx *Transaction, sig []byte) (r, s, v *big.Int, err error) {
	if len(sig) != 98 {
		panic(fmt.Sprintf("wrong size for signature: got %d, want 65", len(sig)))
	}
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + 27})
	return r, s, v, nil
}

func recoverPlain(sighash common.Hash, sig, cert []byte) (common.Address, error) {
	// encode the snature in uncompressed format
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// deriveChainId derives the chain id from the given v parameter
func deriveChainId(v *big.Int, vv byte) *big.Int {
	if v.BitLen() <= 64 {
		v := v.Uint64()
		if v == 27 || v == 28 {
			return new(big.Int)
		}
		return new(big.Int).SetUint64((v - uint64(vv) - 35) / 2)
	}
	v = new(big.Int).Sub(v, big.NewInt(35-int64(vv)))
	return v.Div(v, big.NewInt(2))
}
