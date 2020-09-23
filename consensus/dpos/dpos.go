package dpos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"

	"github.com/ethereum/go-ethereum/accounts"

	"golang.org/x/crypto/sha3"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	lru "github.com/hashicorp/golang-lru"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory
)

// Clique proof-of-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending Votes

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	// 除了POW共识外，叔块在其他算法中总是无效的
	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1)
)

var (
	// errUnknownBlock is returned when the list of Signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of Signers (i.e. non divisible by 20 bytes).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errMismatchingCheckpointSigners is returned if a checkpoint block contains a
	// list of Signers different than the one the local node calculated.
	errMismatchingCheckpointSigners = errors.New("mismatching signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the signer.
	errWrongDifficulty = errors.New("wrong difficulty")

	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	errInvalidDposData = errors.New("invalid dpos data")

	errRecentlySigned = errors.New("recently signed")
)

type Dpos struct {
	config     *params.DposConfig // Consensus engine configuration parameters
	db         ethdb.Database     // Database to store and retrieve snapshot checkpoints
	recents    *lru.ARCCache      // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache      // Signatures of recent blocks to speed up mining

	signer common.Address // Ethereum address of the signing key
	signFn SignerFn       // Signer function to authorize hashes with

	lock sync.RWMutex // Protects the signer fields
}

func New(config *params.DposConfig, db ethdb.Database) *Dpos {
	conf := *config
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)
	return &Dpos{
		config:     &conf,
		db:         db,
		recents:    recents,
		signatures: signatures,
	}
}

type DposData struct {
	Signers map[common.Address]struct{} `json:"signers"` //每到一个Epoch，区块将本地排序的singers填充到这里

	Votes       map[common.Address]Vote `json:"votes"`
	CancelVotes map[common.Address]Vote `json:"cancel_votes"`
}

// 一次投票信息，包含投给的候选人，投的票数
// 撤销票，票数Tally为空,To也为空
type Vote struct {
	To   common.Address
	Tall *big.Int
}

type SignerFn func(accounts.Account, string, []byte) ([]byte, error)

func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {

	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var signer common.Address
	copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, signer)
	return signer, nil
}

func (d *Dpos) Author(header *types.Header) (common.Address, error) {
	return ecrecover(header, d.signatures)
}

func (d *Dpos) Authorize(signer common.Address, signFn SignerFn) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.signer = signer
	d.signFn = signFn
}

func (d *Dpos) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return d.verifyHeader(chain, header, nil)
}
func (d *Dpos) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	if now := uint64(time.Now().Unix()); now < header.Time {
		return consensus.ErrFutureBlock
	}

	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0 && header.Difficulty.Cmp(diffNoTurn) != 0) {
			return errInvalidMixDigest
		}
	}

	return d.verifyCascadingFields(chain, header, parents)
}
func (d *Dpos) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()

	if number == 0 {
		return nil
	}
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+d.config.Period > header.Time {
		return ErrInvalidTimestamp
	}

	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	dposData := DposData{}
	err = DposDataDecode(header.Extra[extraVanity:len(header.Extra)-extraSeal], &dposData)
	if err != nil {
		return err
	}
	if dposData.Votes == nil || dposData.CancelVotes == nil {
		return errInvalidDposData
	}
	if number%d.config.Epoch == 0 {
		newSigners := snap.getNewSignersAfterAEpoch()
		if !reflect.DeepEqual(newSigners, snap.getNewSignersAfterAEpoch()) {
			return errMismatchingCheckpointSigners
		}
	}

	return d.verifySeal(chain, header, parents)
}
func (d *Dpos) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	snap, err := d.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}
	signer, err := ecrecover(header, d.signatures)
	if err != nil {
		return err
	}
	if _, ok := snap.Signers[signer]; !ok {
		return errUnauthorizedSigner
	}
	for seen, recent := range snap.Recents {
		if recent == signer {
			if limit := uint64(len(snap.Signers)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}
	return nil
}

func (d *Dpos) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
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

func (d *Dpos) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

func (d *Dpos) Prepare(chain consensus.ChainReader, header *types.Header) error {
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

func (d *Dpos) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
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

func (d *Dpos) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
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
	return types.NewBlock(header, txs, nil, receipts), nil
}

func (d *Dpos) calVote(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction) (votes map[common.Address]Vote, cancelVotes map[common.Address]Vote) {
	votes = map[common.Address]Vote{}
	cancelVotes = map[common.Address]Vote{}
	number := header.Number.Uint64()
	var snap *Snapshot
	if number > 0 {
		snap, _ = d.snapshot(chain, number-1, header.ParentHash, nil)
		if snap == nil {
			return
		}
	}
walk:
	for _, tx := range txs {
		sender, _ := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
		voteInfo := strings.Split(string(tx.Data()), ":")
		if len(voteInfo) == 0 {
			continue
		}

		vote := Vote{}
		switch voteInfo[0] {
		case "vote":
			if len(voteInfo) != 2 {
				continue walk
			}
			if number != 0 && snap.hasVoted(sender) {
				continue walk
			}
			tally, ok := big.NewInt(0).SetString(voteInfo[1], 10)
			if !ok || tally.Cmp(big.NewInt(0)) < 0 {
				continue walk
			}
			vote.Tall = tally
			if state.GetBalance(sender).Cmp(tally) <= 0 {
				continue walk
			}
			vote.To = *tx.To()
			votes[sender] = vote
			log.Info(fmt.Sprintf("vote from: %s, to: %s, tally: %s", sender.Hex(), vote.To.Hex(), vote.Tall.String()))
			state.SubBalance(sender, tally)
		case "cancel":
			if number == 0 || !snap.hasVoted(sender) {
				continue walk
			}
			vote.To = *tx.To()
			state.AddBalance(sender, snap.getVoteTally(sender))
			cancelVotes[sender] = vote
		default:
			continue walk
		}
	}
	return
}

func (d *Dpos) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
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

func (d *Dpos) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
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
func (d *Dpos) APIs(chain consensus.ChainReader) []rpc.API {
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

func (d *Dpos) snapshot(chain consensus.ChainReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := d.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}

		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(d.config, d.signatures, d.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}

		if number == 0 {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				// 从区块头中解析出Dpos共识有关数据
				dposData := DposData{}
				dposDataBytes := checkpoint.Extra[extraVanity : len(checkpoint.Extra)-extraSeal]
				DposDataDecode(dposDataBytes, &dposData)

				snap = newSnapshot(d.config, d.signatures, number, hash, dposData.Signers)
				if err := snap.store(d.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}

		var header *types.Header
		if len(parents) > 0 {
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			header = chain.GetHeader(hash, number)
			//fmt.Printf("期望获取的区块号%d, has %s\n 实际获取的区块号 %d 区块hash %s\n", number, hash.Hex(), header.Number.Uint64(), header.Hash().Hex())
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}

		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}

	// 把headers中保存的头从按高度从小到大排序。
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}

	snap, err := snap.apply(headers)
	if err != nil {
		return nil, err
	}
	d.recents.Add(snap.Hash, snap)

	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(d.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// SealHash 返回区块被签名封装之前的Hash值
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

// DposRLP 返回需要签名header的 rlp 编码
func DposRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}
func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}

func DposDataEncode(dpos DposData) []byte {
	bytes, _ := json.Marshal(dpos)
	return bytes
}
func DposDataDecode(bytes []byte, data *DposData) error {
	return json.Unmarshal(bytes, &data)
}
