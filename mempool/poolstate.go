package mempool

import (
	"bytes"
	"context"
	"os"
	"path"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	evidencetypes "github.com/cosmos/cosmos-sdk/x/evidence/types"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	ibctransfertypes "github.com/cosmos/cosmos-sdk/x/ibc/applications/transfer/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	osmoapp "github.com/osmosis-labs/osmosis/app/params"
	claimtypes "github.com/osmosis-labs/osmosis/x/claim/types"
	epochstypes "github.com/osmosis-labs/osmosis/x/epochs/types"
	gammtypes "github.com/osmosis-labs/osmosis/x/gamm/types"
	incentivestypes "github.com/osmosis-labs/osmosis/x/incentives/types"
	lockuptypes "github.com/osmosis-labs/osmosis/x/lockup/types"
	poolincentivestypes "github.com/osmosis-labs/osmosis/x/pool-incentives/types"
	tmhttp "github.com/tendermint/tendermint/rpc/client/http"
	"github.com/tendermint/tendermint/types"
	"golang.org/x/sync/errgroup"
)

var (
	atomDenom     = "ibc/27394FB092D2ECCD56123C74F36E4C1F926001CEADA9CA97EA622B25F41E5EB2"
	keyname       = "fundskey"
	selectedPools = []uint64{1, 4, 6, 8, 10, 13, 22}
	swapgas       = uint64(300000)
)

// TODO: probably not needed? but maybe just to be safe?
// could cause panic when starting application
func init() {
	setSDKContext()
}

type poolstate struct {
	pools   map[uint64]gammtypes.Pool
	account client.Account
	balance sdk.Coin
	cli     client.Context
}

func (ss *poolstate) nonAtomDenom(id uint64) (outDenom string) {
	if ss.pools[id].PoolAssets[0].Token.Denom != atomDenom {
		outDenom = ss.pools[id].PoolAssets[0].Token.Denom
	} else if ss.pools[id].PoolAssets[0].Token.Denom == atomDenom {
		outDenom = ss.pools[id].PoolAssets[1].Token.Denom
	}
	// TODO: maybe return some error if the two cases above don't get hit?
	return
}

func (ss *poolstate) createTransaction(pool uint64, tokenIn sdk.Coin, tokenOutDenom string) types.Tx {
	txf := tx.NewFactory(ss.cli, ss.account.GetAccountNumber(), ss.account.GetSequence(), swapgas)

	msg := &gammtypes.MsgSwapExactAmountIn{
		Sender: ss.cli.FromAddress.String(),
		Routes: []gammtypes.SwapAmountInRoute{{
			PoolId:        pool,
			TokenOutDenom: tokenOutDenom,
		}},
		TokenIn:           tokenIn,
		TokenOutMinAmount: sdk.ZeroInt(),
	}
	var txbz *bytes.Buffer
	ss.cli.Output = txbz
	if err := tx.GenerateTx(ss.cli, txf, msg); err != nil {
		// TODO: log this
		return types.Tx{}
	}
	return txbz.Bytes()
}

func (mem *CListMempool) transactionBundle() []types.Tx {
	var txmap map[uint64][]sdk.Tx
	for e := mem.txs.Front(); e != nil; e = e.Next() {
		d := types.Data{Txs: []types.Tx{}}
		memTx := e.Value.(*mempoolTx)
		d.Txs = append(d.Txs, memTx.tx)
		txb, err := mem.ss.cli.TxConfig.TxDecoder()(d.ToProto().Txs[0])
		if err != nil {
			mem.logger.Error("failed to decode mempool transaction bytes into sdk transaction")
			return []types.Tx{}
		}
		for _, msg := range txb.GetMsgs() {
			switch swp := msg.(type) {
			case *gammtypes.MsgSwapExactAmountIn:
				// for any transactions routing through the pools
				// that are beginning their trade with atom
				if swp.TokenIn.Denom == atomDenom && len(swp.Routes) > 0 {
					// we want the first pool because we know users are bringing
					// atom, this front running bot isn't too advanced
					if pool, ok := mem.ss.pools[swp.Routes[0].PoolId]; ok && profitable(pool, swp) {
						// sort the transactions into a map by pool id
						if val, ok := txmap[pool.Id]; ok {
							txmap[pool.Id] = append(val, txb)
						} else {
							txmap[pool.Id] = []sdk.Tx{txb}
						}
					}
				}
			default:
			}
		}
	}

	// if there are some transactions that we want,
	// find the pool this block with the most activity
	highpool := uint64(0)
	if len(txmap) > 0 {
		highprice := sdk.ZeroInt()
		for pid, txs := range txmap {
			tradeAmount := sdk.ZeroInt()
			for _, tx := range txs {
				for _, msg := range tx.GetMsgs() {
					switch swp := msg.(type) {
					case *gammtypes.MsgSwapExactAmountIn:
						tradeAmount.Add(swp.TokenIn.Amount)
					default:
					}
				}
			}
			if tradeAmount.GT(highprice) {
				highprice = tradeAmount
				highpool = pid
			}
		}
	}

	var bundle []types.Tx
	if highpool > 0 {
		input := mem.ss.balance
		// TODO: if its not valid, try again
		// TODO: if its not profitable, don't output transactions
		valid, funds := validInputAmount(mem.ss.pools[highpool], input, txmap[highpool])
		if valid {
			// append first transaction to bundle
			bundle = append(bundle, mem.ss.createTransaction(highpool, input, mem.ss.nonAtomDenom(highpool)))

			// append target transactions to bundle
			// TODO: calculate gas here
			for _, tx := range txmap[highpool] {
				bz, err := mem.ss.cli.TxConfig.TxEncoder()(tx)
				if err != nil {
					// log this error
					return []types.Tx{}
				}
				bundle = append(bundle, bz)
			}

			// append final transaction to bundle
			bundle = append(bundle, mem.ss.createTransaction(highpool, funds, atomDenom))
		}
	}
	return bundle
}

func validInputAmount(pool gammtypes.Pool, amountIn sdk.Coin, txs []sdk.Tx) (bool, sdk.Coin) {
	updatedPool, amountOut, err := calcOut(pool, amountIn, sdk.ZeroInt())
	if err != nil {
		return false, sdk.Coin{}
	}
	for _, tx := range txs {
		for _, msg := range tx.GetMsgs() {
			switch swp := msg.(type) {
			case *gammtypes.MsgSwapExactAmountIn:
				updatedPool, _, err = calcOut(updatedPool, swp.TokenIn, swp.TokenOutMinAmount)
				if err != nil {
					return false, sdk.Coin{}
				}
			}
		}
	}
	return true, amountOut
}

func (ss *poolstate) updatepoolstate() {
	var eg errgroup.Group
	eg.Go(func() error { return ss.updatePools() })
	eg.Go(func() error { return ss.updateBalance() })
	eg.Go(func() error { return ss.updateAccount() })
	if err := eg.Wait(); err != nil {
		// log this don't error
	}
}

func (ss *poolstate) updatePools() error {
	var eg errgroup.Group
	for _, id := range selectedPools {
		id := id
		eg.Go(func() error {
			p, err := ss.getPool(id)
			if err != nil {
				return err
			}
			ss.pools[id] = p
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func (ss *poolstate) updateBalance() error {
	res, err := banktypes.NewQueryClient(ss.cli).Balance(context.Background(), &banktypes.QueryBalanceRequest{Address: ss.cli.GetFromAddress().String(), Denom: atomDenom})
	if err != nil {
		return err
	}
	ss.balance = *res.Balance
	return nil
}

func (ss *poolstate) updateAccount() error {
	acc, err := ss.cli.AccountRetriever.GetAccount(ss.cli, ss.cli.FromAddress)
	if err != nil {
		return err
	}
	ss.account = acc
	return nil
}

func (ss *poolstate) getPool(id uint64) (gammtypes.Pool, error) {
	res, err := gammtypes.NewQueryClient(ss.cli).Pool(context.Background(), &gammtypes.QueryPoolRequest{PoolId: id})
	if err != nil {
		return gammtypes.Pool{}, err
	}
	var pool gammtypes.Pool
	pool.XXX_Unmarshal(res.GetPool().Value)
	if err != nil {
		return gammtypes.Pool{}, err
	}
	return pool, nil
}

// TODO: maybe not needed
func setSDKContext() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("osmo", "osmopub")
	config.SetBech32PrefixForValidator("osmovaloper", "osmovaloperpub")
	config.SetBech32PrefixForConsensusNode("osmovalcons", "osmovalconspub")
}

func cliCtx() client.Context {
	ec := encodingConfig()
	out, err := tmhttp.New("http://localhost:26657", "/websocket")
	if err != nil {
		// log this don't exit
	}

	kr, err := keyring.New("osmosis", "test", path.Join(os.ExpandEnv("$HOME"), ".osmosisd"), os.Stdin)
	if err != nil {
		panic(err)
	}
	info, err := kr.Key(keyname)
	if err != nil {
		panic(err)
	}
	return client.Context{
		Client:            out,
		ChainID:           "osmosis-1",
		FromAddress:       info.GetAddress(),
		FromName:          keyname,
		From:              keyname,
		JSONMarshaler:     ec.Marshaler,
		Keyring:           kr,
		InterfaceRegistry: ec.InterfaceRegistry,
		Input:             os.Stdin,
		Output:            os.Stdout,
		Simulate:          false,
		OutputFormat:      "json",
		NodeURI:           "http://localhost:26657",
		LegacyAmino:       ec.Amino,
	}
}

func encodingConfig() osmoapp.EncodingConfig {
	ec := osmoapp.MakeEncodingConfig()
	authtypes.RegisterInterfaces(ec.InterfaceRegistry)
	banktypes.RegisterInterfaces(ec.InterfaceRegistry)
	gammtypes.RegisterInterfaces(ec.InterfaceRegistry)
	crisistypes.RegisterInterfaces(ec.InterfaceRegistry)
	distrtypes.RegisterInterfaces(ec.InterfaceRegistry)
	evidencetypes.RegisterInterfaces(ec.InterfaceRegistry)
	govtypes.RegisterInterfaces(ec.InterfaceRegistry)
	ibctransfertypes.RegisterInterfaces(ec.InterfaceRegistry)
	slashingtypes.RegisterInterfaces(ec.InterfaceRegistry)
	stakingtypes.RegisterInterfaces(ec.InterfaceRegistry)
	upgradetypes.RegisterInterfaces(ec.InterfaceRegistry)
	claimtypes.RegisterInterfaces(ec.InterfaceRegistry)
	epochstypes.RegisterInterfaces(ec.InterfaceRegistry)
	incentivestypes.RegisterInterfaces(ec.InterfaceRegistry)
	lockuptypes.RegisterInterfaces(ec.InterfaceRegistry)
	poolincentivestypes.RegisterInterfaces(ec.InterfaceRegistry)
	std.RegisterInterfaces(ec.InterfaceRegistry)
	return ec
}

func profitable(pool gammtypes.Pool, swp *gammtypes.MsgSwapExactAmountIn) bool {
	// then we want to get the price in the pool
	// estimate how much will be needed to be profitable
	return false
}
