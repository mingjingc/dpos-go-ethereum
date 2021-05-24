package dpos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"

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

var (
	// 在不到21个节点参与投票时，可以用baseSigner作为填充，保证系统正常运行
	baseSigners = []common.Address{
		common.HexToAddress("8dd4fcd1244431c009ab19dfcaad45808af0b5d0"),
		common.HexToAddress("002dd817a05983c7371bccd498d8dce6b1910295"),
		common.HexToAddress("f35556fef87d70f23dc42b948baa15d4df6b1223"),
	}
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

// rlp不支持自定义结构，我们用json代替
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

func (d *Dpos) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	return d.verifySeal(chain, header, nil)
}

func (d *Dpos) Authorize(signer common.Address, signFn SignerFn) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.signer = signer
	d.signFn = signFn
}

func (d *Dpos) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
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
func (d *Dpos) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
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
func (d *Dpos) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
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

func (d *Dpos) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
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

// when meet a epoch, refund to all accounts. and clean up vote in the snapshot of this block
func (d *Dpos) cleanUpVote(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) {
	number := header.Number.Uint64()
	if number == 0 {
		return
	}
	snap, _ := d.snapshot(chain, number-1, header.ParentHash, nil)
	if snap == nil {
		return
	}
	votes := snap.getVotes()
	for addr, vote := range votes {
		state.AddBalance(addr, vote.Tall)
	}
}

func (d *Dpos) calVote(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction) (votes map[common.Address]Vote, cancelVotes map[common.Address]Vote) {
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
