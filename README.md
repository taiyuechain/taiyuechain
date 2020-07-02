## TaiyueChain

TaiyueChain is a truly fast, permissionless, secure and scalable public blockchain platform 
which is supported by hybrid consensus technology called Minerva and a global developer community. 
 
TaiyueChain uses hybrid consensus combining PBFT and fPoW to solve the biggest problem confronting public blockchain: 
the contradiction between decentralization and efficiency. 

TaiyueChain uses PBFT as fast-chain to process transactions, and leave the oversight and election of PBFT to the hands of PoW nodes. 
Besides, TaiyueChain integrates fruitchain technology into the traditional PoW protocol to become fPoW, 
to make the chain even more decentralized and fair. 
 
TaiyueChain also creates a hybrid consensus incentive model and a stable gas fee mechanism to lower the cost for the developers 
and operators of DApps, and provide better infrastructure for decentralized eco-system. 

<a href="https://github.com/taiyuechain/taiyuechain/blob/master/COPYING"><img src="https://img.shields.io/badge/license-GPL%20%20taiyuechain-lightgrey.svg"></a>

## Building the source


Building taiyue requires both a Go (version 1.9 or later) and a C compiler.
You can install them using your favourite package manager.
Once the dependencies are installed, run

    make taiyue

or, to build the full suite of utilities:

    make all

The execuable command taiyue will be found in the `cmd` directory.

## Running taiyue

Going through all the possible command line flags is out of scope here (please consult our
[CLI Wiki page](https://github.com/taiyuechain/taiyuechain/wiki/Command-Line-Options)), 
also you can quickly run your own taiyue instance with a few common parameter combos.

### Running on the Taiyuechain main network

```
$ taiyue console
```

This command will:

 * Start taiyue with network ID `19330` in full node mode(default, can be changed with the `--syncmode` flag after version 1.1).
 * Start up taiyue's built-in interactive console,
   (via the trailing `console` subcommand) through which you can invoke all official [`web3` methods](https://github.com/taiyuechain/taiyuechain/wiki/RPC-API)
   as well as Geth's own [management APIs](https://github.com/taiyuechain/taiyuechain/wiki/Management-API).
   This too is optional and if you leave it out you can always attach to an already running taiyue instance
   with `taiyue attach`.


### Running on the Taiyuechain test network

To test your contracts, you can join the test network with your node.

```
$ taiyue --testnet console
```

The `console` subcommand has the exact same meaning as above and they are equally useful on the
testnet too. Please see above for their explanations if you've skipped here.

Specifying the `--testnet` flag, however, will reconfigure your Geth instance a bit:

 * Test network uses different network ID `18928`
 * Instead of connecting the main TaiyueChain network, the client will connect to the test network, which uses testnet P2P bootnodes,  and genesis states.


### Configuration

As an alternative to passing the numerous flags to the `taiyue` binary, you can also pass a configuration file via:

```
$ taiyue --config /path/to/your_config.toml
```

To get an idea how the file should look like you can use the `dumpconfig` subcommand to export your existing configuration:

```
$ taiyue --your-favourite-flags dumpconfig
```

### Operating a private network

Maintaining your own private network is more involved as a lot of configurations taken for granted in
the official networks need to be manually set up.

more infomation:
[setup.md](https://github.com/taiyuechain/taiyuechain/blob/master/setup.md "setup.md")
