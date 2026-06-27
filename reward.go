package outscript

import (
	"errors"
	"math/big"
)

// rewardModel is a custom enum to distinguish
// how we calculate block rewards & cumulative sums.
type rewardModel int

const (
	modelHalving rewardModel = iota
	modelDoge
	modelDash
	modelZero
)

// chainRewardInfo holds the parameters needed to compute
// both single-block and cumulative rewards for each network.
type chainRewardInfo struct {
	model           rewardModel
	initialReward   *big.Int // e.g. 50 BTC in satoshis, or 5 DASH in duffs
	halvingInterval uint64   // for halving-based networks

	// For Dogecoin or Dash, we might store extra info, but we can keep it simple
	// if their logic is mostly fixed, e.g. "600k -> forever 10k DOGE" is hard-coded.
}

// chainConfigs is a global map of network name -> chainRewardInfo
var chainConfigs = map[string]*chainRewardInfo{
	// Halving-based (Bitcoin, LTC, Monacoin, BCH, Testnet)
	"bitcoin": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000), // 50 BTC in satoshis
		halvingInterval: 210_000,
	},
	"namecoin": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000), // 50 NMC
		halvingInterval: 210_000,
	},
	"bitcoin-cash": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000),
		halvingInterval: 210_000,
	},
	"bitcoin-testnet": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000),
		halvingInterval: 210_000,
	},
	"litecoin": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000), // 50 LTC in litoshis
		halvingInterval: 840_000,
	},
	"monacoin": {
		model:           modelHalving,
		initialReward:   big.NewInt(50_0000_0000), // 50 MONA in watoshi
		halvingInterval: 1_051_200,
	},

	// Dogecoin
	"dogecoin": {
		model: modelDoge,
		// We won’t store initialReward or halvingInterval
		// because Dogecoin is unique (1,000,000 -> halving -> 10,000).
		// But you *could* store them if you wanted to parametrize more.
	},

	// Dash
	"dash": {
		model:         modelDash,
		initialReward: big.NewInt(5 * 100_000_000), // 5 DASH in duffs
		// halvingInterval not used; Dash has 210,240-block "years" but reduces by 13/14, so logic is custom
	},

	// Always zero
	"electraproto": {
		model: modelZero,
	},
}

// BlockReward returns the block reward at the given blockHeight
// for the specified network, reading from chainConfigs.
func BlockReward(network string, blockHeight uint64) (*big.Int, error) {
	info, ok := chainConfigs[network]
	if !ok {
		return nil, errors.New("unsupported network: " + network)
	}

	switch info.model {
	case modelHalving:
		return halvingBlockReward(info.initialReward, info.halvingInterval, blockHeight), nil
	case modelDoge:
		return dogeBlockReward(blockHeight), nil
	case modelDash:
		return dashBlockReward(info.initialReward, blockHeight), nil
	case modelZero:
		return big.NewInt(0), nil
	default:
		return nil, errors.New("unknown reward model")
	}
}

// halvingBlockReward returns the block reward for a typical halving coin.
//   - baseReward: e.g. 50 BTC in satoshis
//   - halvingInterval: e.g. 210,000 blocks for Bitcoin
func halvingBlockReward(baseReward *big.Int, halvingInterval, blockHeight uint64) *big.Int {
	// Convert int64-based shift logic:
	//   halvingCount = blockHeight / halvingInterval
	//   reward = baseReward >> halvingCount  (using integer shift)
	halvingCount := blockHeight / halvingInterval

	// For safety, clamp halvingCount at ~32 so we don't shift into oblivion.
	// But in practice once it’s large, the reward is basically 0.
	if halvingCount > 32 {
		return big.NewInt(0)
	}
	// We'll do a copy so we don't mutate the original baseReward.
	reward := new(big.Int).Set(baseReward)
	reward.Rsh(reward, uint(halvingCount)) // Right shift by halvingCount
	return reward
}

// dogeBlockReward for blockHeight in simplified Doge model:
//   - 1,000,000 DOGE halving every 100,000 blocks for 6 intervals (until block 600k).
//   - after block 600,000 => 10,000 DOGE forever
//   - 1 DOGE = 100,000,000 shibes
func dogeBlockReward(blockHeight uint64) *big.Int {
	// Past block 600,000 => always 10,000 DOGE
	if blockHeight >= 600_000 {
		return big.NewInt(10_000 * 100_000_000)
	}

	// figure out which halving interval blockHeight is in
	halvingIndex := blockHeight / 100_000 // 0..5
	// initial reward 1,000,000 DOGE >> halvingIndex
	doge := int64(1_000_000 >> halvingIndex)
	return big.NewInt(doge * 100_000_000)
}

// dashBlockReward calculates the block reward for Dash at a given height
// with the "7.14% yearly reduction" by factor (13/14).
//   - baseReward = 5 DASH in duffs
//   - each 210,240 blocks => multiply by 13/14
//
// The block reward is the floor of: baseReward * (13/14)^yearIndex
func dashBlockReward(baseReward *big.Int, blockHeight uint64) *big.Int {
	blocksPerYear := uint64(210_240)
	yearsElapsed := blockHeight / blocksPerYear

	// reward = floor( baseReward * (13/14)^yearsElapsed )
	numerator := new(big.Int).Exp(big.NewInt(13), big.NewInt(int64(yearsElapsed)), nil)
	denominator := new(big.Int).Exp(big.NewInt(14), big.NewInt(int64(yearsElapsed)), nil)

	reward := new(big.Int).Mul(baseReward, numerator)
	reward.Div(reward, denominator)
	return reward
}

// CumulativeReward returns the total minted coins from block 0 through blockHeight
// (inclusive) for the specified network.
func CumulativeReward(network string, blockHeight uint64) (*big.Int, error) {
	info, ok := chainConfigs[network]
	if !ok {
		return nil, errors.New("unsupported network: " + network)
	}

	switch info.model {
	case modelHalving:
		return cumulativeHalvingRewards(info.initialReward, info.halvingInterval, blockHeight), nil
	case modelDoge:
		return cumulativeDogeRewards(blockHeight), nil
	case modelDash:
		return cumulativeDashRewards(info.initialReward, blockHeight), nil
	case modelZero:
		return big.NewInt(0), nil
	default:
		return nil, errors.New("unknown reward model")
	}
}

// cumulativeHalvingRewards sums up the total minted coins from block 0
// through blockHeight (inclusive) for a halving coin like BTC or LTC.
func cumulativeHalvingRewards(baseReward *big.Int, halvingInterval, blockHeight uint64) *big.Int {
	// number of blocks we need to account for is (blockHeight + 1)
	blocksNeeded := blockHeight + 1

	total := new(big.Int)
	reward := new(big.Int).Set(baseReward) // copy

	// loop over halving intervals, up to ~32
	for i := 0; i < 33 && blocksNeeded > 0 && reward.Sign() > 0; i++ {
		intervalSize := halvingInterval
		if blocksNeeded < intervalSize {
			intervalSize = blocksNeeded
		}

		// chunk = intervalSize * reward
		chunk := new(big.Int).Mul(big.NewInt(int64(intervalSize)), reward)
		total.Add(total, chunk)

		blocksNeeded -= intervalSize
		reward.Rsh(reward, 1) // halve it
	}

	return total
}

// cumulativeDogeRewards sums up Dogecoin’s block rewards
// from block 0 through blockHeight (inclusive).
//
// We do a small loop for the 6 intervals of halving (each 100k blocks),
// then all remaining blocks get 10,000 DOGE each.
func cumulativeDogeRewards(blockHeight uint64) *big.Int {
	total := new(big.Int)
	blocksAccounted := uint64(0)

	intervalSize := uint64(100_000)

	for i := 0; i < 6; i++ {
		intervalStart := intervalSize * uint64(i)
		intervalEnd := intervalSize * uint64(i+1) // exclusive
		if blockHeight < intervalStart {
			break
		}

		dogeReward := int64(1_000_000 >> i)
		dogeRewardShibes := new(big.Int).Mul(
			big.NewInt(dogeReward),
			big.NewInt(100_000_000),
		)

		effectiveEnd := intervalEnd
		if blockHeight+1 < intervalEnd {
			effectiveEnd = blockHeight + 1
		}
		blocksInInterval := effectiveEnd - intervalStart
		if blocksInInterval > 0 {
			chunk := new(big.Int).Mul(
				big.NewInt(int64(blocksInInterval)),
				dogeRewardShibes,
			)
			total.Add(total, chunk)
			blocksAccounted = effectiveEnd
			if blocksAccounted > blockHeight {
				return total
			}
		}
	}

	// After block 600,000 => 10,000 DOGE each
	if blocksAccounted <= blockHeight {
		leftover := (blockHeight + 1) - blocksAccounted
		chunk := new(big.Int).Mul(
			big.NewInt(int64(leftover)),
			big.NewInt(10_000*100_000_000),
		)
		total.Add(total, chunk)
	}

	return total
}

// cumulativeDashRewards sums up the total minted coins in Dash
// from block 0 through blockHeight (inclusive).
//
// Each 210,240-block "year," the block reward is multiplied by (13/14).
// So we sum all *full* years, then do partial blocks in the last (current) year.
func cumulativeDashRewards(baseReward *big.Int, blockHeight uint64) *big.Int {
	total := new(big.Int)

	blocksPerYear := uint64(210_240)
	yearsElapsed := blockHeight / blocksPerYear
	remainder := (blockHeight % blocksPerYear) + 1 // partial blocks in final year

	// Sum full years
	for i := uint64(0); i < yearsElapsed; i++ {
		yearlyReward := dashYearlyBlockReward(baseReward, i)
		// Full year chunk = yearlyReward * 210,240
		chunk := new(big.Int).Mul(yearlyReward, big.NewInt(int64(blocksPerYear)))
		total.Add(total, chunk)
	}

	// Partial year
	if remainder > 0 {
		partialYearReward := dashYearlyBlockReward(baseReward, yearsElapsed)
		chunk := new(big.Int).Mul(partialYearReward, big.NewInt(int64(remainder)))
		total.Add(total, chunk)
	}

	return total
}

// dashYearlyBlockReward = floor( baseReward * (13/14)^yearIndex )
func dashYearlyBlockReward(baseReward *big.Int, yearIndex uint64) *big.Int {
	if yearIndex == 0 {
		return new(big.Int).Set(baseReward)
	}
	numerator := new(big.Int).Exp(big.NewInt(13), big.NewInt(int64(yearIndex)), nil)
	denominator := new(big.Int).Exp(big.NewInt(14), big.NewInt(int64(yearIndex)), nil)

	reward := new(big.Int).Mul(baseReward, numerator)
	reward.Div(reward, denominator)
	return reward
}
