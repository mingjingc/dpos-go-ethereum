package dpos

import (
	"bytes"
	"errors"
	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
)

func (d *Dpos) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, d.signatures)
}

func (d *Dpos) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}

func (d *Dpos) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for i, header := range headers {
			err := d.verifyHeader(chain, header, headers[:i])
			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (d *Dpos) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

func (d *Dpos) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// 准备挖的区块number
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	snap, err := d.snapshot(chain, number-1, parent.Hash(), nil)
	if err != nil {
		return err
	}
	header.Coinbase = common.Address{}
	header.Nonce = types.BlockNonce{}

	header.Time = parent.Time + d.config.Period
	if now := uint64(time.Now().Unix()); header.Time < now {
		header.Time = now
	}
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x0}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	// 计算难度值header.Time这里暂时用不着，
	header.Difficulty = d.CalcDifficulty(chain, header.Time, parent)
	header.MixDigest = common.Hash{}

	dposData := DposData{
		Signers:     map[common.Address]struct{}{},
		Votes:       map[common.Address]Vote{},
		CancelVotes: map[common.Address]Vote{},
	}
	if number%d.config.Epoch == 0 {
		dposData.Signers = snap.getNewSignersAfterAEpoch()
	}
	header.Extra = append(header.Extra, DposDataEncode(dposData)...)
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)
	return nil
}

func (d *Dpos) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	dposData := DposData{}
	// 已经在头部已验证
	_ = DposDataDecode(header.Extra[extraVanity:len(header.Extra)-extraSeal], &dposData)
	extraSealBytes := make([]byte, extraSeal)
	copy(extraSealBytes, header.Extra[len(header.Extra)-extraSeal:])
	header.Extra = header.Extra[:extraVanity]
	dposData.Votes, dposData.CancelVotes = d.calVote(chain, header, state, txs)
	header.Extra = append(header.Extra, DposDataEncode(dposData)...)
	header.Extra = append(header.Extra, extraSealBytes...)

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
}

func (d *Dpos) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	dposData := DposData{}
	err := DposDataDecode(header.Extra[extraVanity:len(header.Extra)-extraSeal], &dposData)
	extraSealBytes := make([]byte, extraSeal)
	copy(extraSealBytes, header.Extra[len(header.Extra)-extraSeal:])
	header.Extra = header.Extra[:extraVanity]
	if err != nil {
		return nil, err
	}
	dposData.Votes, dposData.CancelVotes = d.calVote(chain, header, state, txs)
	header.Extra = append(header.Extra, DposDataEncode(dposData)...)
	header.Extra = append(header.Extra, extraSealBytes...)

	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil)), nil
}

func (d *Dpos) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	d.lock.Lock()
	signer, signFn := d.signer, d.signFn
	d.lock.Unlock()

	snap, err := d.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	for seen, recent := range snap.Recents {
		if recent == signer {
			if limit := uint64(len(snap.Signers)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others")
				return nil
			}
		}
	}
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now())
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		wiggle := time.Duration(len(snap.Signers)/2+1) * 500 * time.Millisecond
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}

	sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, DposRLP(header))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}
		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()
	return nil
}

func (d *Dpos) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

func (d *Dpos) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := d.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	if snap.inturn(snap.Number+1, d.signer) {
		return diffInTurn
	}
	return diffNoTurn
}

// APIs 共识引擎提供的RPC接口
func (d *Dpos) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "dpos",
		Version:   "1.0",
		Service:   &API{chain: chain, dpos: d},
		Public:    false,
	}}
}

// Close 用于结束共识引擎的后台程序, dpos暂时不需要
func (d *Dpos) Close() error {
	return nil
}
