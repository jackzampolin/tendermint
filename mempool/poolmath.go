package mempool

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	gammtypes "github.com/osmosis-labs/osmosis/x/gamm/types"
)

var (
	powPrecision, _         = sdk.NewDecFromStr("0.00000001")
	zero            sdk.Dec = sdk.ZeroDec()
	one_half        sdk.Dec = sdk.MustNewDecFromStr("0.5")
	one             sdk.Dec = sdk.OneDec()
	two             sdk.Dec = sdk.MustNewDecFromStr("2")
)

func assetPair(p gammtypes.Pool) (atomAsset, pairAsset gammtypes.PoolAsset) {
	if p.PoolAssets[0].Token.Denom == atomDenom {
		atomAsset = p.PoolAssets[0]
		pairAsset = p.PoolAssets[1]
	} else if p.PoolAssets[1].Token.Denom == atomDenom {
		atomAsset = p.PoolAssets[1]
		pairAsset = p.PoolAssets[0]
	}
	return
}

func calcOut(pool gammtypes.Pool, amountIn sdk.Coin, tokenOutMinAmount sdk.Int) (updatedPool gammtypes.Pool, amountOut sdk.Coin, err error) {
	atomAsset, pairAsset := assetPair(pool)
	tokenOutAmount := calcOutGivenIn(
		atomAsset.Token.Amount.ToDec(),
		atomAsset.Weight.ToDec(),
		pairAsset.Token.Amount.ToDec(),
		pairAsset.Weight.ToDec(),
		amountIn.Amount.ToDec(),
		pool.GetPoolParams().SwapFee,
	).TruncateInt()

	if tokenOutAmount.LTE(sdk.ZeroInt()) {
		return gammtypes.Pool{}, sdk.Coin{}, fmt.Errorf("token amount is zero or negative")
	}

	if tokenOutAmount.LT(tokenOutMinAmount) {
		return gammtypes.Pool{}, sdk.Coin{}, fmt.Errorf("%s token is lesser than min amount", pairAsset.Token.Denom)
	}

	atomAsset.Token.Amount = atomAsset.Token.Amount.Add(amountIn.Amount)
	pairAsset.Token.Amount = pairAsset.Token.Amount.Sub(tokenOutAmount)
	if err := pool.UpdatePoolAssetBalances(sdk.NewCoins(atomAsset.Token, pairAsset.Token)); err != nil {
		return gammtypes.Pool{}, sdk.Coin{}, fmt.Errorf("updating pool balance: %s", err)
	}

	return pool, sdk.NewCoin(pairAsset.Token.Denom, tokenOutAmount), nil
}

func calcOutGivenIn(
	tokenBalanceIn,
	tokenWeightIn,
	tokenBalanceOut,
	tokenWeightOut,
	tokenAmountIn,
	swapFee sdk.Dec,
) sdk.Dec {
	weightRatio := tokenWeightIn.Quo(tokenWeightOut)
	adjustedIn := sdk.OneDec().Sub(swapFee)
	adjustedIn = tokenAmountIn.Mul(adjustedIn)
	y := tokenBalanceIn.Quo(tokenBalanceIn.Add(adjustedIn))
	foo := pow(y, weightRatio)
	bar := sdk.OneDec().Sub(foo)
	return tokenBalanceOut.Mul(bar)
}

func pow(base sdk.Dec, exp sdk.Dec) sdk.Dec {
	// Exponentiation of a negative base with an arbitrary real exponent is not closed within the reals.
	// You can see this by recalling that `i = (-1)^(.5)`. We have to go to complex numbers to define this.
	// (And would have to implement complex logarithms)
	// We don't have a need for negative bases, so we don't include any such logic.
	if !base.IsPositive() {
		panic(fmt.Errorf("base must be greater than 0"))
	}
	// TODO: Remove this if we want to generalize the function,
	// we can adjust the algorithm in this setting.
	if base.GTE(two) {
		panic(fmt.Errorf("base must be lesser than two"))
	}

	// We will use an approximation algorithm to compute the power.
	// Since computing an integer power is easy, we split up the exponent into
	// an integer component and a fractional component.
	integer := exp.TruncateDec()
	fractional := exp.Sub(integer)

	integerPow := base.Power(uint64(integer.TruncateInt64()))

	if fractional.IsZero() {
		return integerPow
	}

	fractionalPow := powApprox(base, fractional, powPrecision)

	return integerPow.Mul(fractionalPow)
}

// Contract: 0 < base <= 2
// 0 < exp < 1
func powApprox(base sdk.Dec, exp sdk.Dec, precision sdk.Dec) sdk.Dec {
	if exp.IsZero() {
		return sdk.ZeroDec()
	}

	// Common case optimization
	// Optimize for it being equal to one-half
	if exp.Equal(one_half) {
		output, err := base.ApproxSqrt()
		if err != nil {
			panic(err)
		}
		return output
	}
	// TODO: Make an approx-equal function, and then check if exp * 3 = 1, and do a check accordingly

	// We compute this via taking the maclaurin series of (1 + x)^a
	// where x = base - 1.
	// The maclaurin series of (1 + x)^a = sum_{k=0}^{infty} binom(a, k) x^k
	// Binom(a, k) takes the natural continuation on the first parameter, namely that
	// Binom(a, k) = N/D, where D = k!, and N = a(a-1)(a-2)...(a-k+1)
	// Next we show that the absolute value of each term is less than the last term.
	// Note that the change in term n's value vs term n + 1 is a multiplicative factor of
	// v_n = x(a - n) / (n+1)
	// So if |v_n| < 1, we know that each term has a lesser impact on the result than the last.
	// For our bounds on |x| < 1, |a| < 1,
	// it suffices to see for what n is |v_n| < 1,
	// in the worst parameterization of x = 1, a = -1.
	// v_n = |(-1 + epsilon - n) / (n+1)|
	// So |v_n| is always less than 1, as n ranges over the integers.
	//
	// Note that term_n of the expansion is 1 * prod_{i=0}^{n-1} v_i
	// The error if we stop the expansion at term_n is:
	// error_n = sum_{k=n+1}^{infty} term_k
	// At this point we further restrict a >= 0, so 0 <= a < 1.
	// Now we take the _INCORRECT_ assumption that if term_n < p, then
	// error_n < p.
	// This assumption is obviously wrong.
	// However our usages of this function don't use the full domain.
	// With a > 0, |x| << 1, and p sufficiently low, perhaps this actually is true.

	// TODO: Check with our parameterization
	// TODO: If theres a bug, balancer is also wrong here :thonk:
	a := exp
	x, xneg := absDifferenceWithSign(base, one)
	term := sdk.OneDec()
	sum := sdk.OneDec()
	negative := false

	// TODO: Document this computation via taylor expansion
	for i := 1; term.GTE(precision); i++ {
		bigK := sdk.OneDec().MulInt64(int64(i))
		c, cneg := absDifferenceWithSign(a, bigK.Sub(one))
		term = term.Mul(c.Mul(x))
		term = term.Quo(bigK)

		if term.IsZero() {
			break
		}
		if xneg {
			negative = !negative
		}

		if cneg {
			negative = !negative
		}

		if negative {
			sum = sum.Sub(term)
		} else {
			sum = sum.Add(term)
		}
	}
	return sum
}

// absDifferenceWithSign returns | a - b |, (a - b).sign()
func absDifferenceWithSign(a, b sdk.Dec) (sdk.Dec, bool) {
	if a.GTE(b) {
		return a.Sub(b), false
	} else {
		return b.Sub(a), true
	}
}
