package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/protocol/keepalive"
	"github.com/cardano-community/koios-go-client/v3"

	"github.com/safanaj/cardano-go"
	"github.com/safanaj/cardano-go/bech32"
	koioscli "github.com/safanaj/cardano-go/koios"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:           "cardano-pinger",
	Short:         "A CLI application to ping cardano nodes and get tip.",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runE,
}

func init() {
	rootCmd.Flags().String("node", "", "target node as <ip:port> or <dns:port>")
	rootCmd.Flags().String("pool", "", "target pool as bech32 or hex")
	rootCmd.Flags().Uint16P("count", "c", 1, "Pings count (default 1)")
	rootCmd.Flags().DurationP("interval", "i", 1*time.Second, "Pings interval (default 1 second)")
	rootCmd.Flags().Bool("tip", false, "")
	rootCmd.Flags().BoolP("verbose", "v", false, "")
}

func runE(cmd *cobra.Command, args []string) error {
	node, _ := cmd.Flags().GetString("node")
	pool, _ := cmd.Flags().GetString("pool")
	count, _ := cmd.Flags().GetUint16("count")
	interval, _ := cmd.Flags().GetDuration("interval")
	alsoTip, _ := cmd.Flags().GetBool("tip")
	verbose, _ := cmd.Flags().GetBool("verbose")

	targets := []string{}
	if pool != "" {
		relays, err := discoverRelays(cmd.Context(), pool)
		if err != nil {
			return err
		}
		targets = append(targets, relays...)
	} else if node != "" {
		// return checkNode(cmd.Context(), node, count, interval, alsoTip, verbose)
		targets = append(targets, node)
	} else if len(args) == 0 {
		return fmt.Errorf("At least a node or a pool have to be specified")
	}

	for _, arg := range args {
		if strings.Contains(arg, ":") {
			targets = append(targets, arg)
		} else {
			relays, err := discoverRelays(cmd.Context(), arg)
			if err != nil {
				return err
			}
			targets = append(targets, relays...)
		}
	}

	type result struct {
		n string
		r bool
	}
	results := map[string]bool{}
	resCh := make(chan result)
	go func() {
		for res := range resCh {
			results[res.n] = res.r
		}
	}()

	var wg sync.WaitGroup
	wg.Add(len(targets))
	for _, relay := range targets {
		go func(relay string) {
			defer wg.Done()
			if err := checkNode(cmd.Context(), relay, count, interval, alsoTip, verbose); err != nil {
				fmt.Fprintf(os.Stderr, "Error for %s: %v\n", relay, err)
				resCh <- result{n: relay, r: false}
			} else {
				resCh <- result{n: relay, r: true}
			}
		}(relay)
	}
	wg.Wait()
	close(resCh)

	for r, v := range results {
		if v {
			fmt.Printf("Node %s is UP and responsive\n", r)
		} else {
			fmt.Printf("Node %s is DOWN and not responsive\n", r)
		}
	}

	return nil
}

func dedupStrings(elts []string) []string {
	elts_map := map[string]struct{}{}
	for _, elt := range elts {
		elts_map[elt] = struct{}{}
	}
	elts = []string{}
	for elt := range elts_map {
		elts = append(elts, elt)
	}
	return elts
}

func dieOnError(errorChan chan error) {
	for {
		err, ok := <-errorChan
		if !ok {
			return
		}
		fmt.Printf("ERROR: %s\n", err)
		os.Exit(1)
	}
}

type pingResponse struct {
	t time.Time
	e error
}

type pingResult struct {
	d time.Duration
	e error
}

type pingStats struct {
	count             uint16
	minT, maxT, meanT time.Duration
	results           []pingResult
	errors            []error
}

const maxDuration = time.Duration(1<<63 - 1)

func checkNode(ctx context.Context, address string, count uint16, interval time.Duration, alsoTip, verbose bool) error {
	cookie := uint16(0)
	waitResponse := make(chan pingResponse)
	stats := pingStats{count: count}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	o, err := ouroboros.New(
		ouroboros.WithConnection(conn),
		ouroboros.WithNetwork(ouroboros.NetworkByName("mainnet")),
		ouroboros.WithNodeToNode(true),
		ouroboros.WithKeepAlive(true),
		ouroboros.WithKeepAliveConfig(
			keepalive.NewConfig(
				keepalive.WithTimeout(time.Second),
				keepalive.WithPeriod(maxDuration),
				keepalive.WithKeepAliveResponseFunc(func(c uint16) error {
					if c != cookie {
						err := fmt.Errorf("KeepAliveFunc got wrong cookie: %d expected %d", c, cookie)
						waitResponse <- pingResponse{t: time.Now(), e: err}
						return err
					}
					waitResponse <- pingResponse{t: time.Now(), e: nil}
					return nil
				}),
			)),
	)
	if err != nil {
		return err
	}
	go dieOnError(o.ErrorChan())

	for {
		s := time.Now()
		o.KeepAlive().Client.SendMessage(keepalive.NewMsgKeepAlive(cookie))
		r := <-waitResponse
		res := pingResult{d: r.t.Sub(s), e: nil}
		stats.results = append(stats.results, res)
		if r.e != nil {
			stats.errors = append(stats.errors, r.e)
		}
		if verbose {
			fmt.Printf("node: %s responded at ping = %d in %s with error = %v\n", address, cookie, res.d, res.e)
		}
		cookie += 1
		if cookie >= count {
			break
		}
		time.Sleep(interval)
	}
	close(waitResponse)

	sumT := time.Duration(0)
	counting := len(stats.results) - len(stats.errors)
	for i, r := range stats.results {
		sumT += r.d
		if i == 0 {
			stats.minT = r.d
		}
		stats.maxT = time.Duration(int64(math.Max(float64(r.d), float64(stats.maxT))))
	}
	if counting > 0 {
		stats.meanT = sumT / time.Duration(counting)
	}
	fmt.Printf("node: %s stats for %d pings: min = %v, max = %v, mean = %v\n",
		address, stats.count, stats.minT, stats.maxT, stats.meanT)

	if alsoTip {
		o.ChainSync().Client.Start()
		tip, err := o.ChainSync().Client.GetCurrentTip()
		if err != nil {
			o.Close()
			return err
		}
		fmt.Printf("node: %s tip: slot = %d, hash = %x\n", address, tip.Point.Slot, tip.Point.Hash)
	}

	return o.Close()
}

func discoverRelays(ctx context.Context, pool string) ([]string, error) {
	var poolId koios.PoolID
	if strings.HasPrefix(pool, "pool1") {
		poolId = koios.PoolID(pool)
	} else {
		data, err := hex.DecodeString(pool)
		if err != nil {
			return nil, err
		}
		pool, err = bech32.EncodeFromBase256("pool", data)
		if err != nil {
			return nil, err
		}
		poolId = koios.PoolID(pool)
	}
	node := koioscli.NewNode(cardano.Mainnet, ctx)
	kc := node.(*koioscli.KoiosCli)
	resp, err := kc.GetPoolInfo(ctx, poolId, nil)
	if err != nil {
		return nil, err
	}
	nodes := []string{}
	for _, r := range resp.Data.Relays {
		if r.DNS != "" {
			nodes = append(nodes, fmt.Sprintf("%s:%d", r.DNS, r.Port))
		} else if r.Ipv4 != "" {
			nodes = append(nodes, fmt.Sprintf("%s:%d", r.Ipv4, r.Port))
		} else if r.Ipv6 != "" {
			nodes = append(nodes, fmt.Sprintf("%s:%d", r.Ipv6, r.Port))
		} else if r.Srv != "" {
			_, srvs, err := net.DefaultResolver.LookupSRV(ctx, "", "", r.Srv)
			// _, srvs, err := (&net.Resolver{}).LookupSRV(ctx, "", "", r.Srv)
			if err != nil {
				return dedupStrings(nodes), err
			}
			for _, r := range srvs {
				nodes = append(nodes, fmt.Sprintf("%s:%d", strings.TrimSuffix(r.Target, "."), r.Port))
			}
		}
	}
	return dedupStrings(nodes), nil
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}
