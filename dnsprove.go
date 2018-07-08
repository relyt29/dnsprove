// Copyright 2017 Nick Johnson. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// dnsprove is a utility that submits DNSSEC signatures to an Ethereum oracle,
// allowing you to prove the (non)existence and contents of DNS records onchain.
package main

import (
    "context"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/arachnid/dnsprove/oracle"
	"github.com/relyt29/dnsprove/proveAPI"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/miekg/dns"
	"github.com/ethereum/go-ethereum/ethclient"
	log "github.com/inconshreveable/log15"
	prompt "github.com/segmentio/go-prompt"
)

var (
	server          = flag.String("server", "https://dns.google.com/experimental", "The URL of the dns-over-https server to use")
	hashes          = flag.String("hashes", "SHA256", "a comma-separated list of supported hash algorithms")
	algorithms      = flag.String("algorithms", "RSASHA256", "a comma-separated list of supported digest algorithms")
	verbosity       = flag.Int("verbosity", 3, "logging level verbosity (0-4)")
	print           = flag.Bool("print", false, "don't upload to the contract, just print proof data")
	rpc             = flag.String("rpc", "http://localhost:8545", "RPC path to Ethereum node")
	address         = flag.String("address", "", "Contract address for DNSSEC oracle")
	keyfile         = flag.String("keyfile", "", "Path to JSON keyfile")
	gasprice        = flag.Float64("gasprice", 5.0, "Gas price, in gwei")
	yes             = flag.Bool("yes", false, "Do not prompt before sending transactions")
	trustAnchors = []*dns.DS{
		&dns.DS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag: 19036,
			Algorithm: 8,
			DigestType: 2,
			Digest: "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
		},
		&dns.DS{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
			KeyTag: 20326,
			Algorithm: 8,
			DigestType: 2,
			Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		},
	}
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] qtype name\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		return
	}

	log.Root().SetHandler(log.LvlFilterHandler(log.Lvl(*verbosity), log.StreamHandler(os.Stderr, log.TerminalFormat())))

	qtype, ok := dns.StringToType[flag.Arg(0)]
	if !ok {
		log.Crit("Unrecognised query type", "type", flag.Arg(0))
		os.Exit(1)
	}
	qclass := uint16(dns.ClassINET)
	name := flag.Arg(1)
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	hashmap := make(map[uint8]struct{})
	for _, hashname := range strings.Split(*hashes, ",") {
		hashmap[dns.StringToHash[hashname]] = struct{}{}
	}

	algmap := make(map[uint8]struct{})
	for _, algname := range strings.Split(*algorithms, ",") {
		algmap[dns.StringToAlgorithm[algname]] = struct{}{}
	}

	client := proveAPI.NewClient(*server, trustAnchors, algmap, hashmap)
	sets, found, err := client.QueryWithProof(qtype, qclass, name)
	if err != nil {
		log.Crit("Error resolving", "name", name, "err", err)
		os.Exit(1)
	}

	if *print {
		for _, proof := range sets {
			fmt.Printf("\n// %s\n", proof.Sig.String())
			for _, rr := range proof.Rrs {
				for _, line := range strings.Split(rr.String(), "\n") {
					fmt.Printf("// %s\n", line)
				}
			}
			data, err := proof.Pack()
			if err != nil {
				log.Crit("Error packing RRSet", "err", err)
				os.Exit(1)
			}
			sig, err := proof.PackSignature()
			if err != nil {
				log.Crit("Error packing RRSet signature", "err", err)
				os.Exit(1)
			}
			fmt.Printf("[\"%s\", \"%x\", \"%x\"],\n", proof.Name, data, sig)
		}
		os.Exit(0)
	}

	conn, err := ethclient.Dial(*rpc)
	if err != nil {
		log.Crit("Error connecting to Ethereum node", "err", err)
		os.Exit(1)
	}

	o, err := oracle.NewOracle(common.HexToAddress(*address), conn)
	if err != nil {
		log.Crit("Error creating oracle", "err", err)
		os.Exit(1)
	}

	if !found {
		// We're deleting a domain. If it's not already there, there's nothing to do.
		_, _, hash, err := o.Rrdata(qtype, name)
		if err != nil {
			log.Crit("Error checking RRDATA", "qtype", qtype, "name", name, "err", err)
			os.Exit(1)
		}
		if hash == [20]byte{} {
			fmt.Printf("RRSet not found in oracle. Nothing to do; exiting\n")
			os.Exit(0)
		}
	} else {
		// If the RRset already matches, there's nothing to do
		matches, err := o.RecordMatches(sets[len(sets) - 1])
		if err != nil {
			log.Crit("Error checking for record", "err", err)
			os.Exit(1)
		}
		if matches && found {
			fmt.Printf("Nothing to do; exiting.\n")
			os.Exit(0)
		}
	}

	known, err := o.FindFirstUnknownProof(sets, found)
	if err != nil {
		log.Crit("Error checking proofs against oracle", "err", err)
		os.Exit(1)
	}

	if !*yes {
		if !prompt.Confirm("Send %d transactions to prove %s %s onchain?", len(sets) - known, dns.TypeToString[sets[len(sets) - 1].Rrs[0].Header().Rrtype], name) {
			fmt.Printf("Exiting at user request.\n")
			return
		}
	}

	key, err := os.Open(*keyfile)
	if err != nil {
		log.Crit("Could not open keyfile", "err", err)
		os.Exit(1)
	}

	pass := prompt.Password("Password")
	auth, err := bind.NewTransactor(key, pass)
	if err != nil {
		log.Crit("Could not create transactor", "err", err)
		os.Exit(1)
	}
	auth.GasPrice = big.NewInt(int64(*gasprice * 1000000000))

	nonce, err := conn.PendingNonceAt(context.TODO(), auth.From)
    if err != nil {
		log.Crit("Could not fetch nonce", "err", err)
		os.Exit(1)
    }
	auth.Nonce = big.NewInt(int64(nonce))

	var txs []*types.Transaction
	if found {
		txs, _, err = o.SendProofs(auth, sets, known, found)
		if err != nil {
			log.Crit("Error sending proofs", "err", err)
			os.Exit(1)
		}
	} else {
		nsec := sets[len(sets) - 1]
		var proof []byte
		txs, proof, err = o.SendProofs(auth, sets[:len(sets) - 1], known, found)
		if err != nil {
			log.Crit("Error sending proofs", "err", err)
			os.Exit(1)
		}

		deletetx, err := o.DeleteRRSet(auth, qtype, name, nsec, proof)
		if err != nil {
			log.Crit("Error deleting RRSet", "err", err)
			os.Exit(1)
		}
		txs = append(txs, deletetx)
	}

	txids := make([]string, 0, len(txs))
	for _, tx := range txs {
		txids = append(txids, tx.Hash().String())
	}
	log.Info("Transactions sent", "txids", txids)
}
