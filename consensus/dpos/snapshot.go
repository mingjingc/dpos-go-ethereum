package dpos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	lru "github.com/hashicorp/golang-lru"
)

const (
	prefixKeyOfSnapshot = "dpos-"
	maxSignerNumber     = 21
)

type Snapshot struct {
	config   *params.DposConfig
	sigcache *lru.ARCCache               // Cache of recent block signatures to speed up ecrecover
	Number   uint64                      `json:"number"`  // Block number where the snapshot was created
	Hash     common.Hash                 `json:"hash"`    // Block hash where the snapshot was created
	Signers  map[common.Address]struct{} `json:"Signers"` // Set of authorized Signers at this moment
	Recents  map[uint64]common.Address   `json:"recents"` // Set of recent Signers for spam protections

	CandidateTally map[common.Address]*big.Int `json:"candidate_tally"`
	Votes          map[common.Address]*Vote    `json:"Votes"`
}

func newSnapshot(config *params.DposConfig, sigcache *lru.ARCCache, number uint64, hash common.Hash, signers map[common.Address]struct{}) *Snapshot {
	snap := &Snapshot{
		config:         config,
		sigcache:       sigcache,
		Number:         number,
		Hash:           hash,
		Signers:        signers,
		Recents:        map[uint64]common.Address{},
		CandidateTally: map[common.Address]*big.Int{},
		Votes:          map[common.Address]*Vote{},
	}
	return snap
}

func loadSnapshot(config *params.DposConfig, sigcache *lru.ARCCache, db ethdb.Database, hash common.Hash) (*Snapshot, error) {
	blob, err := db.Get(append([]byte(prefixKeyOfSnapshot), hash[:]...))
	if err != nil {
		return nil, err
	}
	snap := new(Snapshot)
	if err := json.Unmarshal(blob, snap); err != nil {
		return nil, err
	}
	snap.config = config
	snap.sigcache = sigcache
	return snap, nil
}

func (s *Snapshot) store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append([]byte(prefixKeyOfSnapshot), s.Hash[:]...), blob)
}

func (s *Snapshot) copy() *Snapshot {
	cpy := &Snapshot{
		config:         s.config,
		sigcache:       s.sigcache,
		Number:         s.Number,
		Hash:           s.Hash,
		Signers:        map[common.Address]struct{}{},
		Recents:        map[uint64]common.Address{},
		CandidateTally: map[common.Address]*big.Int{},
		Votes:          map[common.Address]*Vote{},
	}
	for signer := range s.Signers {
		cpy.Signers[signer] = struct{}{}
	}
	for block, signer := range s.Recents {
		cpy.Recents[block] = signer
	}
	for address, tally := range s.CandidateTally {
		cpy.CandidateTally[address] = big.NewInt(0).Set(tally)
	}
	for sender, vote := range s.Votes {
		cpy.Votes[sender] = &Vote{
			To:   vote.To,
			Tall: big.NewInt(0).Set(vote.Tall),
		}
	}

	return cpy
}

// apply 通过给的的区块头，创建合法的快照
func (s *Snapshot) apply(headers []*types.Header) (*Snapshot, error) {
	if len(headers) == 0 {
		return s, nil
	}
	for i := 0; i < len(headers)-1; i++ {
		if headers[i].Number.Uint64()+1 != headers[i+1].Number.Uint64() {
			return nil, errInvalidVotingChain
		}
	}

	if headers[0].Number.Uint64() != s.Number+1 {
		return nil, errInvalidVotingChain
	}

	snap := s.copy()
	for _, header := range headers {
		number := header.Number.Uint64()
		if limit := uint64(len(snap.Signers)/2 + 1); number >= limit {
			delete(snap.Recents, number-limit)
		}

		signer, err := ecrecover(header, snap.sigcache)
		if err != nil {
			return nil, err
		}
		if _, ok := s.Signers[signer]; !ok {
			return nil, errUnauthorizedSigner
		}
		for _, recent := range snap.Recents {
			if recent == signer {
				return nil, errRecentlySigned
			}
		}
		snap.Recents[number] = signer

		dposData := DposData{}
		//fmt.Printf("生成快照的header %d长度：%d\n", header.Number.Uint64(), len(header.Extra))
		DposDataDecode(header.Extra[extraVanity:len(header.Extra)-extraSeal], &dposData)
		if number%snap.config.Epoch == 0 {
			snap.Signers = dposData.Signers
		}
		votes, cancelVotes := dposData.Votes, dposData.CancelVotes
		for sender, vote := range votes {
			fmt.Println("Snapshot统计票数")
			snap.Votes[sender] = &Vote{
				To:   vote.To,
				Tall: vote.Tall,
			}
			if snap.CandidateTally[vote.To] == nil {
				snap.CandidateTally[vote.To] = big.NewInt(0)
			}
			snap.CandidateTally[vote.To].Add(snap.CandidateTally[vote.To], vote.Tall)
			fmt.Println("统计票数后，snapshot为：", snap.CandidateTally[vote.To].String(), snap.Votes[sender].Tall)
		}
		for sender := range cancelVotes {
			vote := snap.Votes[sender]
			delete(snap.Votes, sender)
			snap.CandidateTally[vote.To].Sub(snap.CandidateTally[vote.To], vote.Tall)
			if snap.CandidateTally[vote.To].Cmp(big.NewInt(0)) == 0 {
				delete(snap.CandidateTally, vote.To)
			}
		}
	}

	snap.Number += uint64(len(headers))
	snap.Hash = headers[len(headers)-1].Hash()
	return snap, nil
}

// signer数量在变化，不是绝对公平，此算法有待优化
func (s *Snapshot) inturn(number uint64, signer common.Address) bool {
	signers := s.signers()
	i := 0
	for ; i < len(signers) && signers[i] != signer; i++ {
	}
	return number%uint64(len(signers)) == uint64(i)
}

// Signers retrieves the list of authorized Signers in ascending order.
func (s *Snapshot) signers() []common.Address {
	sigs := make([]common.Address, 0, len(s.Signers))
	for sig := range s.Signers {
		sigs = append(sigs, sig)
	}
	sort.Sort(signersAscending(sigs))
	return sigs
}

// 经过一个Epoch, 从投票结果中返回新的签名者
func (s *Snapshot) getNewSignersAfterAEpoch() map[common.Address]struct{} {
	newSigners := map[common.Address]struct{}{}

	candidates := []Candidate{}
	for addr, tall := range s.CandidateTally {
		candidate := Candidate{
			address: addr,
			tall:    tall,
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].tall.Cmp(candidates[j].tall) < 0
	})
	if len(candidates) > maxSignerNumber {
		candidates = candidates[:maxSignerNumber]
	}
	for _, candidate := range candidates {
		newSigners[candidate.address] = struct{}{}
	}

	return newSigners
}

func (s *Snapshot) hasVoted(voter common.Address) bool {
	return s.Votes[voter] != nil
}

// 获取一个用户投的票数
func (s *Snapshot) getVoteTally(user common.Address) *big.Int {
	tally := big.NewInt(0)
	if s.Votes[user] != nil {
		tally.Set(s.Votes[user].Tall)
	}
	return tally
}

// signersAscending implements the sort interface to allow sorting a list of addresses
type signersAscending []common.Address

func (s signersAscending) Len() int           { return len(s) }
func (s signersAscending) Less(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 }
func (s signersAscending) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type Candidate struct {
	address common.Address
	tall    *big.Int
}
