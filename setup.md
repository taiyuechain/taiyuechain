## 编译
linux下获取源码地址后进行如下操作，将在build目录下生成可执行程序。

 + git clone
 + cd taiyuechain
 + make taiyue
 
## 运行
程序首次运行需要初始化创世区块。

`taiyue --datadir "./data" init genesis.json "./certlist" ` 

使用指定的创世区块配置json文件和初始的根证书列表目录，初始化创世块后，就可以启动泰岳节点了。

`taiyue` 或者 `taiyue --config "./config.toml"`

> 注：确保初始化创世时的--datadir指定的目录与config.toml中指定的目录一致，同时根证书的数量与委员会的数量必须保持一致，在国密系统中证书的私钥和委员会的公钥所对应的私钥可以保持一致。
> 详细可以参见配置部署样例

### CA创建
证书的创建可以使用openssl，openssl的1.1.1之后的版本加上了sm1, sm2, sm3, sm4算法的支持。首先安装openssl v1.1.1之后的版本(可以自己编译一个发行版)。

> 使用`SM2`使用`国密`算法.

证书生成流程为:
> 生成CA私钥（.key）-->生成CA证书请求（.req）-->自签名得到CA根证书（.pem)
```
# openssl ecparam -out CA.key -name SM2 -genkey
# openssl req -config openssl.cnf -key CA.key -new -out CA.req
# openssl x509 -req -in CA.req -signkey CA.key -out CA.pem
```
签发证书：
```
# openssl ecparam -out site.key -name SM2 -genkey
# openssl req -config openssl.cnf -key site.key -new -out site.req
# openssl x509 -req -in site.req -CA CA.pem -CAkey CA.key  -out site.pem -CAcreateserial
```

### genesis参数
genesis.json文件指定了创世块的样式。创世中定义了chainid,密码库类型，链奖励参数，在有链奖励时，可以配置预分配地址与余额。

+ `CertList`: 创世根证书列表,该参数在json文件中可忽略，由CA列表指定。
+ `committee`: 创世委员会的公钥和奖励地址，委员会的数量与根证书的数量必须保持一致。
+ `useGas`: 0--不使用gas即gasprice=0,1--表示使用gas.
+ `isCoin`: 表示链是否有奖励(有币)，0--无，1--有。当isCoin=0时，useGas不能为 1.
+ `kindOfCrypto`: 表示加密系统类型1-ECC国际标准(p256曲线)，2--ECC国家标准(SM2)，3--ECC国际标准(s256曲线)


```
{
  "config": {
    "chainId": 1
  },

  "alloc":{
    "0x9d3c4a33d3bcbd2245a1bebd8e989b696e561eae" : { "balance" : "90000000000000000000000"},
    "0x35c9d83c3de709bbd2cb4a8a42b89e0317abe6d4" : { "balance" : "90000000000000000000000"}
  },
  
  "CertList" : [],
		
  "committee":[
    {
      "address": "0x76ea2f3a002431fede1141b660dbb75c26ba6d97",
      "publickey": "0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd"
    },
    {
      "address": "0x831151b7eb8e650dc442cd623fbc6ae20279df85",
      "publickey": "0x045e1711b6cd8550a5e5466f7f0868b5507929cb69c2f0fca84f8f94816eb40a808ea8a77c3d83c9d16341acb037fbea2f7d9d4af46326defa39b408f40f28fb98"
    },{
      "address": "0x1074f7deccf8c66efcd0106e034d3356b7db3f2c",
      "publickey": "0x041b931d350257e881f27bce2563d98c99b13ca4f525a0662f5e7d53f085edff0dca8ceaae550c9f4ceecf217f72806a48a48fb024916392ae41d7c45168e89b94"
    },{
      "address": "0xd985e9871d1be109af5a7f6407b1d6b686901fff",
      "publickey": "0x049923777d866fd80485be57a126d638cc7dda78a5d6958aff784ca7ed9d9c7be494125bf75fd0328490ae51020274427b9fbb07f59e4c9b5104ac6924721a4438"
    }
  ]
,
  "coinbase"   		: "0x0000000000000000000000000000000000000000",
  "useGas" 	   		: 1,
  "isCoin"  	: 1,
  "kindOfCrypto" 	: 2,
  "gasLimit"   		: "0x5400000",
  "parentHash" 		: "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp"  		: "0x00"
}
```

### 参数配置
config.toml文件配置了链的一些基础参数,下面是一些主要参数的介绍。

`taiyue.CommitteeKey`: 节点参与委员会的私钥。如果不参与可以忽略。
`taiyue.NodeCertFile`: 节点参与委员会的CA证书文件。如果不参与可以忽略。在国密标准下，可以与CommitteeKey公用相同的私钥。
`taiyue.Host`: 节点参与委员会的本机外网IP地址。如果不参与可以忽略。
`taiyue.Port`: 节点参与委员会的本机主端口。如果不参与可以忽略。
`taiyue.StandbyPort`: 节点参与委员会的本机附端口。如果不参与可以忽略。
`taiyue.NodeType`: 节点启动模式，false表示单节点模式。

`Node.DataDir`:  节点数据目录。
`Node.P2P.ListenAddr`： 节点网络通讯地址。
`Node.P2P.P2PNodeCertFile`： 节点网络通讯证书文件。
`Node.P2P.P2PKey`：节点网络通讯的nodekey,用于标识节点的身份，在国密标准下，可以与P2PNodeCertFile公用相同的私钥。
`Node.P2P.BootstrapNodes`： 节点初始网络发现的地址。

```
[taiyue]
NetworkId = 2812913
SyncMode = "full"
MinervaMode = 0
CommitteeKey = "0x7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75"
NodeCertFile = "./cert/nodecert.pem"
Host = "127.0.0.1"
Port = 8797
StandbyPort = 30311
CommitteeBase = "0x21C16f03bbF085D6908569d159Ad40BcafdB80C5"
GasPrice = 10000
EnablePreimageRecording = false
NodeType = false

[taiyue.TxPool]
NoLocals = false
Journal = "transactions.rlp"
Rejournal = 3600000000000
PriceLimit = 1000
PriceBump = 10
AccountSlots = 80
GlobalSlots = 100
AccountQueue = 100
GlobalQueue = 100
Lifetime = 10800000000000

[taiyue.GPO]
Blocks = 20
Percentile = 60

[Node]
DataDir = "data"
IPCPath = "geth.ipc"
HTTPHost = "127.0.0.1"
HTTPPort = 8545
HTTPVirtualHosts = ["localhost"]
HTTPModules = ["net", "web3", "yue", "shh", "etrue"]
WSPort = 8546
WSModules = ["net", "web3", "yue", "shh"]

[Node.P2P]
MaxPeers = 25
NoDiscovery = false
StaticNodes = []
TrustedNodes = []
ListenAddr = ":30303"
EnableMsgEvents = false
P2PNodeCertFile = "./cert/p2pnodecert.pem"
P2PKey = "0xd5939c73167cd3a815530fd8b4b13f1f5492c1c75e4eafb5c07e8fb7f4b09c7c"
BootstrapNodes = ["enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303", "enode://3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99@13.93.211.84:30303"]

```

### 4节点泰岳链配置部署样例
搭建4节点的泰岳联盟链，首先需要4个根证书，同时这4个节点都将被选入委员会中。

下载代码并编译：
> git clone https://github.com/taiyuechain/taiyuechain.git
> cd taiyuechain
> make taiyue
	
配置创世区块信息：
+ 首先生成4个国密的根证书(上述介绍方法)及4个SM2算法的`私钥`，并将4个根证书放入一个指定目录`./taiyue/certList`和指定一个数据目录`./taiyue/data`。
+ 拥有证书和私钥后，开始构建创世区块，根据源码中的genesis.json模板，拷贝一份并修改如下:
	在committee字段添加4个参数，如：
	```
	{
      "address": "0x76ea2f3a002431fede1141b660dbb75c26ba6d97",  // 奖励地址
      "publickey": "0x04bdf9699d20b4ebabe76e76260480e5492c87aaeda51b138bd22c6d66b69549313dc3eb8c96dc9a1cbbf3b347322c51c05afdd609622277444e0f07e6bd35d8bd"  //之前申请的私钥对应的公钥
    }
	```
+ 其他使用模板的默认参数即可，初始化创世区块 `gati init genesis.json "./taiyue/certList" --datadir "./taiyue/data" `

配置参数：

初始化创世区块后就可以配置参数了，由于本联盟链只有4个节点，所以我们将4节点都做成bootnode节点，这里需要4个SM2算法的私钥作为节点网络通讯的私钥(也可以直接使用之前的私钥和证书)，这里我们直接之前证书和私钥了。我们继续使用源码中的config.toml模板文件。

我们拷贝一份模板文件并分别修改4个节点的共用配置和独立配置。

共用配置：
模板中默认配置都是共用配置，唯一需要修改是的Node.P2P.BootstrapNodes字段，我们可以通过`taiyue`程序分别预生成4个节点的enode信息。

> taiyue enode privkey
privkey: 为之前生成的4个节点的私钥。
执行4次endoe命名分别生成4个如下的enode信息，并将enode信息中`127.0.0.1:30303`改成4个节点实际对应的`IP:Port`信息。
```
taiyue enode "c1581e25937d9ab91421a3e1a2667c85b0397c75a195e643109938e987acecfc"
INFO [06-23|10:53:07.668] Enabling metrics collection
enode://1004e21cf7e0013eb40a5c725c63e012d8c95bd5afa153336e223d5758ba5ad6202fb284c9bc4c979332f2db42a58e16a2b397bb56c217f1be8e2a4f9a1498e5@127.0.0.1:30303
```
并将其配置到BootstrapNodes字段
```
BootstrapNodes = ["enode://a979fb575495b8d6db44f750317d0f4622bf4c2aa3365d6af7c284339968eef29b69ad0dce72a4d8db5ebb4968de0e3bec910127f134779fbcb0cb6d3331163c@52.16.188.185:30303", "enode://3f1d12044546b76342d59d4a05532c14b85aa669704bfe1f864fe079415aa2c02d743e03218e57a33fb94523adb54032871a6c51b2cc5514cb7c7e35b3ed0a99@13.93.211.84:30303"]
```

独立配置：
`taiyue.CommitteeKey`: 4个节点每个节点配置一个私钥，十六进制表示的字符串私钥。
`taiyue.NodeCertFile`: 4个节点每个节点指定一个证书文件(证书文件完整路径)。
`taiyue.Host`: 4个节点各自的IP地址(如果需要连接外网，则需要外网IP地址)。
`Node.DataDir`: 4个节点各自的数据目录,(跟初始化创世时指定的目录一致)。
`Node.P2P.P2PNodeCertFile`： 4个节点每个节点指定一个证书文件，对应于NodeCertFile参数。
`Node.P2P.P2PKey`：4个节点每个节点配置一个私钥，十六进制表示的字符串私钥，对应于CommitteeKey参数。

配置完成开始顺序启动程序构建联盟链：
> `taiyue --config "./config.toml"`


