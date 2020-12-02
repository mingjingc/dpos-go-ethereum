## Dpos Go Ethereum
Dpos Go Ethereum is a project base on [go-ethereum](https://github.com/ethereum/go-ethereum). It's a product when I have learning go-ethereum.
Up to now, I write a Dpos consensus algorithm. I use header extra to wrap Dpos related information. Because nlp cannot encode complex type, therefore I 
chose json struct. Although it's work, but it not the best idea. 
After finish this target, my next step is to try to modify EVM for supporting Dpos vote. If you have any awesome idea, I love to hear i
这个项目基于[go-ethereum-1.9.8](https://github.com/ethereum/go-ethereum/tree/v1.9.8)，实现dpos算法，项目参考了以太坊项目的POA算法和[GTTC](https://github.com/TTCECO/gttc)
项目的Dpos算法，引入投票来选取候选人，有关的Dpos信息存在区块Header的Extra字段，利用其Token来投票，就是你有多少Eth，就可以投多少票，投票后扣除相应帐号的Eth，
经过一个Epoch，候选人重新从投票结果中产生。项目正在完善中，以后期望通过修改虚拟机，修改让Eth成为投票资源，类似[xuperchain](https://github.com/xuperchain/xuperchain)，项目还有很多不足之处，请多多指教和欢迎参与。

## 存在的问题
经常遇到节点同步停止，无法同步其他节点新的区块，无缘无故由恢复正常运行

## 部署流程

###  生成创世配置文件

```sh
$ puppeth
Please specify a network name to administer (no spaces, hyphens or capital letters please)
> mydpos
What would you like to do? (default = stats)
 1. Show network stats
 2. Configure new genesis
 3. Track new remote server
 4. Deploy network components
> 2
What would you like to do? (default = create)
 1. Create new genesis from scratch
 2. Import already existing genesis
> 1

Which consensus engine to use? (default = clique)
 1. Ethash - proof-of-work
 2. Clique - proof-of-authority
 3. Dpos - delegated-proof-of-stake
> 3
Which accounts are allowed to seal? (mandatory at least one)
> 0x002dd817a05983c7371bccd498d8dce6b1910295
> 0x8dd4fcd1244431c009ab19dfcaad45808af0b5d0
> 0xf35556fef87d70f23dc42b948baa15d4df6b1223
> 0x

Which accounts should be pre-funded? (advisable at least one)
> 0xf35556fef87d70f23dc42b948baa15d4df6b1223
> 0x002dd817a05983c7371bccd498d8dce6b1910295
> 0x8dd4fcd1244431c009ab19dfcaad45808af0b5d0
> 0x

Should the precompile-addresses (0x1 .. 0xff) be pre-funded with 1 wei? (advisable yes)
> yes      

Specify your chain/network ID if you want an explicit one (default = random)
> 
INFO [09-23|21:34:49.939] Configured new genesis block 

What would you like to do? (default = stats)
 1. Show network stats
 2. Manage existing genesis
 3. Track new remote server
 4. Deploy network components
> 2

 1. Modify existing configurations
 2. Export genesis configurations
 3. Remove genesis configuration
> 2

Which folder to save the genesis specs into? (default = current)
  Will create mydpos.json, mydpos-aleth.json, mydpos-harmony.json, mydpos-parity.json
> 
INFO [09-23|21:35:36.779] Saved native genesis chain spec          path=mydpos.json

```

### 使用创世文件初始化节点

```sh
for i in 2 3 3; do geth --datadir node$i init genesis/mydpos.json; done
```



### 启动节点

```sh
# 为了测试方便，使用bootnode发现，线上产品为了安全一般不要用
# 更详细文档https://github.com/ethereum/go-ethereum/wiki/Private-network
bootnode --genkey=boot.key #生成bootnode标识
bootnode --nodekey=boot.key #启动bootnode
```

```sh 
geth --datadir node1 --networkid 31745 --gasprice '1' --port 30312 --rpc --rpcaddr '0.0.0.0' --rpcport 8501 --rpcapi 'personal,db,eth,net,web3,txpool,miner,dpos' --nat extip:127.0.0.1  --bootnodes 'enode://e37fabfbf0744a934909602f2f8a7f3669fee10f7508c12d4524a051efa4aecec60fcb314e697f4f5ffcec6ea3859f03a6de66e20906353016fdff4d2b20768a@127.0.0.1:0?discport=30301' --allow-insecure-unlock --unlock 002dd817a05983c7371bccd498d8dce6b1910295
```

```sh
geth --datadir node2 --networkid 31745 --gasprice '1' --port 30313 --rpc --rpcaddr '0.0.0.0' --rpcport 8502 --rpcapi 'personal,db,eth,net,web3,txpool,miner,dpos' --nat extip:127.0.0.1  --bootnodes 'enode://e37fabfbf0744a934909602f2f8a7f3669fee10f7508c12d4524a051efa4aecec60fcb314e697f4f5ffcec6ea3859f03a6de66e20906353016fdff4d2b20768a@127.0.0.1:0?discport=30301' --allow-insecure-unlock --unlock 8dd4fcd1244431c009ab19dfcaad45808af0b5d0
```

```sh
geth --datadir node3 --networkid 31745 --gasprice '1' --port 30315 --rpc --rpcaddr '0.0.0.0' --rpcport 8504 --rpcapi 'personal,db,eth,net,web3,txpool,miner,dpos' --nat extip:127.0.0.1  --bootnodes 'enode://e37fabfbf0744a934909602f2f8a7f3669fee10f7508c12d4524a051efa4aecec60fcb314e697f4f5ffcec6ea3859f03a6de66e20906353016fdff4d2b20768a@127.0.0.1:0?discport=30301' --allow-insecure-unlock --unlock f35556fef87d70f23dc42b948baa15d4df6b1223
```

### 发送转账交易

```sh
 eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0], value:web3.toWei(1,'ether')});
```

### 投票交易

```sh
eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0], data:web3.toHex("vote:1000000")});
eth.sendTransaction({from:eth.accounts[0],to:eth.accounts[0], data:web3.toHex("cancel")})
```

### 查询
#### 查询某个区块快照
```
dpos.getSnapshot(blockNumber)
```
#### 查询某个候选人得票
```
dpos.getCandidateVote(blockNumber, candidateAddress)
```
#### 查询某个用户投票情况
```
dpos.GetVote(blockNumber, address)
```
#### 查询所有候选人
```
dpos.GetSingers(blockNumber)
```

