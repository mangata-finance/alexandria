// Import the API
// Import
import { ApiPromise, WsProvider } from "@polkadot/api";

import publicKeyToAddress from 'ethereum-public-key-to-address';
import createKeccakHash from 'keccak';
import { blake2AsU8a } from '@polkadot/util-crypto';
import { Provider, Contract, Account, ec, json, constants, stark, uint256, shortString, CallData, RpcProvider, cairo } from "starknet";
import fs from "fs";
// import {EncodedBeefyVersionedFinalityProof} from "@polkadot/types/interfaces";
// const { ApiPromise, WsProvider } = require ("@polkadot/api");

async function main () {
  // Here we don't pass the (optional) provider, connecting directly to the default
  // node/port, i.e. `ws://127.0.0.1:9944`. Await for the isReady promise to ensure
  // the API has connected to the node and completed the initialisation process
    // Construct
    const wsProvider = new WsProvider('wss://rococo-rpc.polkadot.io');
    // const wsProvider = new WsProvider('ws://127.0.0.1:9944');
    const api = await ApiPromise.create({ provider: wsProvider });

    const mangataWsProvider = new WsProvider('wss://collator-01-ws-rococo.mangata.online');
    const mangataApi = await ApiPromise.create({ provider: mangataWsProvider });

    const MANGATA_READ_STORAGE_KEY = "0xcbedab01919142839236b4c481d70adb4c72016d74b63ae83d79b02efdb5528ee96760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d";
    
    const MANGATA_PARA_ID = 2110;


  // // We only display a couple, then unsubscribe
  // let count = 0;

  // // Subscribe to the new headers on-chain. The callback is fired when new headers
  // // are found, the call itself returns a promise with a subscription that can be
  // // used to unsubscribe from the newHead subscription
  // const unsubscribe = await api.rpc.chain.subscribeNewHeads((header) => {
  //   console.log(`Chain is at block: #${header.number}`);

  //   if (++count === 256) {
  //     unsubscribe();
  //     process.exit(0);
  //   }
  // });
  const unsub = await api.rpc.beefy.subscribeJustifications(async (beefyjustification) => {
    unsub();

    // console.log(`${beefyjustification}`);
    // setTimeout(function () {
    //   console.log("Waited an additional 20s");},20000);

    let typed_beefyjustification = api.createType("EncodedBeefyVersionedFinalityProof", beefyjustification);

    let block_number = typed_beefyjustification.asV1.commitment.blockNumber;

    // todo - get last block number from starknet and check if block_number here is greater, if not error 'stale justification - maybe check starknet contract state'
    
    let block_hash = await api.rpc.chain.getBlockHash(block_number);
    // console.log(`${block_hash}`);

    let header = await api.rpc.chain.getHeader(block_hash);
//     let block_hash = header.hash;
    // let block_number = header.number;
    console.log(`${block_number}`);
    console.log(`${block_hash}`);


    console.log(`${typed_beefyjustification.asV1.commitment.payload}`);

    let polkatyped_validator_set_id = typed_beefyjustification.asV1.commitment.validatorSetId;
    let validator_set_id = BigInt(polkatyped_validator_set_id.toString());

    console.log(`${polkatyped_validator_set_id.toString()}`);
    console.log(`${validator_set_id}`);

//     // This should just be hex
//     let untyped_validator_set_id = 0;
//     let validator_set_id = BigInt(untyped_validator_set_id);


    let apiAt = await api.at(block_hash);

    // ordered by ascending para_id
    let parachains = await apiAt.query.paras.parachains();
    console.log(`${parachains.length}`);
    let para_heads_map = await apiAt.query.paras.heads.entries();

    console.log(`${para_heads_map[35][0].args}`);
    console.log(`${para_heads_map[35]}`);
    // console.log(`${para_heads_map}`);

    let para_heads_tuple_vec = api.createType("Vec<(ParaId, Bytes)>", "");
    console.log(`${para_heads_tuple_vec.length}`);

    let mangata_parachain_leaf;
    let mangata_parachain_block_hash;
    parachains.forEach(para_id => {
      // console.log(`${para_id.toHex()}`);
      //   console.log(`${Object.prototype.toString.call(para_id)}`);
        let head = para_heads_map.find(entry => para_id.eq(entry[0].args));
        if (head ===undefined){
        } else {
        let t = api.createType("(ParaId, Bytes)", [para_id, head[1].toString()]);
        if (para_id.eq(MANGATA_PARA_ID)){
          console.log(`${head[1].toString()}`);
          console.log("mangata_parachain_leaf: t =", t.toString());
          mangata_parachain_leaf = t.toU8a();
          mangata_parachain_block_hash = api.createType("[u8; 32]", blake2AsU8a(head[1].toString(), 256));
        }
        para_heads_tuple_vec.push(t);
        }
    });
    console.log(`${mangata_parachain_leaf}`);
    console.log(`${mangata_parachain_block_hash}`);

    let sorted_para_heads_tuple_vec = para_heads_tuple_vec.sort((a,b)=>{a[0].cmp(b[0])});
    console.log(`${sorted_para_heads_tuple_vec.toHuman()}`);

    let mangata_parachain_leaf_index = sorted_para_heads_tuple_vec.indexOf(mangata_parachain_leaf);
    console.log(`${mangata_parachain_leaf_index}`);

    let hashes = [];
    sorted_para_heads_tuple_vec.forEach( pair => {
      // The following input should be scale encoded hex
      let hash_hex = createKeccakHash('keccak256').update(Buffer.from(pair.toHex().substring(2), 'hex')).digest('hex');
      // console.log(`${Object.prototype.toString.call(hash_hex)}`);
      let hash_typed = api.createType("[u8; 32]", "0x" + hash_hex);
      hashes.push(hash_typed);
    }
    );

    console.log("sorted_para_heads_tuple_vec[mangata_parachain_leaf_index] =", sorted_para_heads_tuple_vec[mangata_parachain_leaf_index].toString());
    
    console.log(`${hashes[mangata_parachain_leaf_index].toHex()}`);

    let leaves_hashes=[];
    hashes.forEach( hash =>{

    // console.log(`${hash}`);
    // console.log(`${hash.toHex()}`);
    // console.log(`${hash.toU8a()}`);
      leaves_hashes.push.apply(leaves_hashes, hash.toU8a());
    }
    );
    console.log(`${leaves_hashes.length}`);

    // console.log(`${sorted_para_heads_tuple_vec === para_heads_tuple_vec}`);
    // console.log(`${para_heads_tuple_vec.length}`);
    // console.log(`${Object.prototype.toString.call(para_heads_tuple_vec)}`);
    // console.log(`${para_heads_tuple_vec.toHex()}`);
    // console.log(`${para_heads_tuple_vec.toU8a()}`);

    // console.log(`${para_heads_tuple_vec[0].toHex()}`);
    // console.log(`${para_heads_tuple_vec[0].toHuman()}`);
    // let test = api.createType("(Vec<u8>)", [12,34,5]);
    // console.log(`${test}`);
    // console.log(`${test.length}`);


    // OR JUST USE parent_hash. Is as it is will be the beefy_authorities repoerted by the parent
    let parent_hash = header.parentHash;
    let apiAtParent = await api.at(parent_hash);

    let this_session = await apiAt.query.session.currentIndex();
    let parent_session = await apiAtParent.query.session.currentIndex();

    let apiForBeefyAuthorities;

    if (this_session.eq(parent_session)){
      apiForBeefyAuthorities = apiAt;
    } else {
      apiForBeefyAuthorities = apiAtParent;
    }

    let beefy_authorities_addresses_vec_flat = [];
    let beefy_authorities_addresses_vec = api.createType("Vec<[u8; 20]>", "");
    let beefy_authorities = await apiForBeefyAuthorities.query.beefy.authorities();
    beefy_authorities.forEach( pub_key => {
    console.log(`${pub_key}`);
    console.log(`${pub_key.toHex()}`);
    console.log(`${pub_key.toString()}`);
    
    // We can use toHex() for input here as it seems that beefy_authorities is typed to [u8; 33]
      let address = 
                  publicKeyToAddress(
                    pub_key.toHex(),
                );
      console.log(`${address}`);
      let typed_address = api.createType("[u8; 20]", address);
      beefy_authorities_addresses_vec.push(typed_address);
      beefy_authorities_addresses_vec_flat.push(...typed_address.toU8a());
      }

    );
    console.log(`${beefy_authorities_addresses_vec.toHex()}`);
    console.log(`${beefy_authorities_addresses_vec_flat}`);
    // console.log(`${beefy_authorities[0].toU8a()}`);
    // console.log(`${beefy_authorities_addresses_vec}`);
    // console.log(`${beefy_authorities_addresses_vec.toU8a()}`);

    // let beefy_authorities_addresses_hashes_vec = [];
    // beefy_authorities_addresses_vec.forEach( address => {
    //   // We can use toHex here cause we are pushing in typed_address above
    //   let hash_hex = createKeccakHash('keccak256').update(Buffer.from(address.toHex(), 'hex')).digest('hex');
    //   // console.log(`${Object.prototype.toString.call(hash_hex)}`);
    //   let hash_typed = api.createType("[u8; 32]", "0x" + hash_hex);
    //   beefy_authorities_addresses_hashes_vec.push(hash_typed);
    // }

    // 0xb9014bd0f65e5e6d96d09b0c5f13d21bdfc11b47156c57dd8f7937997f8caf3d490239b99db0887c1c1d50c166aeb4d5a84c7cbb0eb0ffbc51811c5e41146703f32cb478188c24b8056fee627b3e83da3ca946d07b9ba00afc57f5da0c18e3feb15369fc4342fc7376ff5dc2952ade8dbca829cbbc30eaafd5a2cd14628595278c52f0d318b3bd8a93d26eb887dc462622cf59f093cad22bb7782103addea8b32e95dcbb96f85c490d6f8d075a51cae16a6df852bae42bc4baf4ffad9f4097876ad2fd3fea50db23aded81cec834d899351e83aee204d69b5dbee57942c770bcf5e89b29d13b66ca003f30aab82a535170d86c1e365d6ed0923839d45a6eac4330ef49307e790e51ac3957dbac6f546f2687f48f4d41ab788a1dd9bdcf800bb1888dd3e1c7a9e2fffdef85c4fdac6981b7c3408c9a54a7226b9f7cd206f8e83f9f6c15417f2b14586ac4742f4a54ded2a08d0d5e051761022a4adae7344a94a8153beab11bb97fdd88cc1175d70ceb62462763b293cfd9aafa9ee3ec58498be4ccd20d7090cc0292a045ab624e7a2971fc965abb61565e0cbc2a20eab790b5f9130cf8ccca93f60aa62afbd4e63764556c5ec9435e1ce2e688f75e1ae2ae9105993af1d41a1e2ef79f91fd12f07bc42070fe644215269d45017e0962bd619e97bdc92697f830a4d79ff148ed18ed44ae4f5ba1b34d38ff42854a09c72ad159184939737d85ced6d00888c5b21e81f75fe9876fb42611e14d385f23036e317ae14dd81cf7c3068588e7cec9f31ed95521edc999c88df2ba60c59d2b693b1a5da8bc874525f5aa6ca4d6d9040087ef7044e56557677aab5fb1e777a6d5e014c5bc4b09b233457e75c9459b5bf31b13322068ed35a70c608444eed8d43e7223570900cd0102bdf63dbdadb2d49a35177251791de0ba43a7d158386601d25a705fe4a2cd10421e0418289457a8ddd376ee666acaffbef08213658ce3824702eb663f299a119f1e81194f23ee50c6da7333dd570eac109a2fc4c4ccc1d0bac6f7b8965aaf0250471e20106202e12ea29520d4f259c8305430451299b3e00be0ad31c43ce2a876b04d4915853a719a6e9792d524fc94fd984fc687e721051f04deca86b41a68918ca37a5c17b3336a56eda404865220ba8428629280f9f4edf27673444ef3c64e721d615989936300cadb259d2a01b0d13d811f4c620c5e31b4442eec5eeaa1d0b05b3e3fb58a2dc586260c353ea151010d8890c3d075aa8b4c1cdd4d511e6cc35ff1ec7c3ef9b809a26b7cf38ddb46defed596b9d326edb4c6eb30914adf0e80fcdf2d44820b2785a0fc480386904e854085a4a8f4bb4c2fb0f716e9f84cc7cfb495e145ec5915cc43347735a1ea13516e09078d47c67293499e7c9abd2791e0b7e22adcf74e649ff5ec19affecfca4a09b2f215462a26f66ecee3f862d8e2926893217c82a01d2b9f8644d40e91116605de15f36b0f7c0fce6f1a16cda67d894ef0e0fed1801a0b3160f4d060c740c468d2629639015ac4948f8bd5a02c5cc6c699a4839e2f42e78b8f8f0531f427289222d57b0c76bb52d621d63d66e4b5c77c7e2d4bbf1fd94f292b1c5d18722b55ecf53da42f1c8e3cc2653a5513e6cd041ad114603fe6d75252c1198107b2cb1459d18834c3f604646c1907fc4c34329693661f603376a19fdb71e79df18b57b5dcdabf1db32706b6c45aedc880873752ba4cfbbff37b1c10c9bd6d28ffad705bc64d4a31b5e2fc0471ecba740839792e111b2842f734ae002726aa39d1045137a2bd35844ebb66def5ed16d8c558b95f26bd1c2f2384a081116b468d943e8ef3d1e392521a733140edcc34d8c54e3bd88d400b346028c9c4c22922ea4a1576a0268f940e9dde2a8ceef8ebf833a8154dab852aa6195143af8f836cabe4de0f45746d1fb8afbaccbdcdbd84b5056ccbc022d71d90446ea6ddae500e8dfed4340aa32e8460eae4745a79b021d20ec226c394592b79dfe4cff8cf141a6de08815ac2182461979beb3c1f484f9ccf9022c0c9aa22a54b5eeee62bf1157977a331be99a1a181279db26ef2e355e00e210e3a47ac524bdc39476d00e4cb4916e31d7581b100cff0532dae698b2144682d428adf4c0d36ad4cde27e392734c04ba9616466bae10ee6d27dc2bf61bdfcc7e22ee0b0ba9932512dc3fb72bc7b383d20a45cccdd365a85d12bd78411f7b915c5ef49bd81db5f7cbe15345c308f4df36178bd8233fa587dcfb8d28391b5db7e26f3648d1c5dcc0c8a799c53558babc09b72cd16646429437b690c5fec50f23692d4639a1a85d2c78931fcad5ccb68bf040c58110ff34f76d956cd3d537554ec1bc87ea6af7bb5a7b9f9a9acfdf5e262e4631c9e89e886977a5347952f49618e2680090eb974c85eeca69998f4cee0c61771ee320f6bb8122cdd04bf2724f19f87a6a90064241fde332506241f9e5289addab9f6f62749adfab36d9d909b7d3281a18459a3ddd30dfc9644457d8915757417946249f1b1dfcc70d5dee31aaf72a2c130cd099922722ef1fc8c29e484ebe4af7ff7208e80782d5ad4ce80b9ca38026aee1e25ec131dd9cde2c33833410a08101fc7408e4fcc82cc8fc2fc41cee2fed1997d2571d76742dfb6e583ced99afd1da3609e20dcde8190131404cb17858afb48a795c6efe2480f50d20076ae737d6424dc4924752c5c3cf2395b2a3e9bb793a19623ecaeb0daf2b374e1678707407a11803193450f998c307eeae5085b9389bb03ed1f5fa28eb6b092db57c9f5dadcf8abbafca063d6805ce907054b27e3b519bfc20082fc431326ecc9ca44122e900ff29a649b9c2d78f25cc9cd34c9921bc11d886d50cb9030c1b97938a47ce94faf56bc216a721740bc09cfacfbef8bbf1b3374e122ee782a3b57451df000eb5b4395e85fa25478493fd2625278e56b71d7bb032f28220b56a25a542d3c5dc8ad4378dfdd67ab5893c84f287ca466f6a6d6d8666b83ef7201248e0b6a1a04d53618bb2c526c9d033d43a056ca2db5280261130ef1e9aebe93855e70c4adb296fc84be8208279b6752cee3727f55819234bbce81012750cb156ebe00cadd6c5fd422e9e1cc7d02ff
    // b84056d5f05c309a2b4cb713385d1f1531376669
    // 04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39
    // 05e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39
    // );
    // let beefy_authorities_addresses_hashes=[];
    // beefy_authorities_addresses_hashes_vec.forEach( hash =>{
    //   // We can use toU8a here cause we are pushing in hash_typed above
    //   beefy_authorities_addresses_hashes.push.apply(beefy_authorities_addresses_hashes, hash.toU8a());
    // }
    // );
    // console.log(`${beefy_authorities_addresses_hashes.length}`);

    let beefy_next_authorities_addresses_vec_flat = [];
    let beefy_next_authorities_addresses_vec = api.createType("Vec<[u8; 20]>", "");
    let beefy_next_authorities = await apiForBeefyAuthorities.query.beefy.nextAuthorities();
    beefy_next_authorities.forEach( pub_key => {
      let address = 
                  publicKeyToAddress(
                    pub_key.toHex(),
                );
      let typed_address = api.createType("[u8; 20]", address);
      beefy_next_authorities_addresses_vec.push(typed_address);
      beefy_next_authorities_addresses_vec_flat.push(...typed_address.toU8a());
      }

    );
    console.log(`${beefy_authorities_addresses_vec.toHex()}`);
    console.log(`${beefy_next_authorities_addresses_vec_flat}`);
    // console.log(`${beefy_authorities[0].toU8a()}`);
    // console.log(`${beefy_authorities[0].toU8a()}`);
    // console.log(`${beefy_next_authorities_addresses_vec}`);
    // console.log(`${beefy_next_authorities_addresses_vec.toU8a()}`);

    // let beefy_next_authorities_addresses_hashes_vec = [];
    // beefy_next_authorities_addresses_vec.forEach( address => {
    //   let hash_hex = createKeccakHash('keccak256').update(Buffer.from(address.toHex(), 'hex')).digest('hex');
    //   // console.log(`${Object.prototype.toString.call(hash_hex)}`);
    //   let hash_typed = api.createType("[u8; 32]", "0x" + hash_hex);
    //   beefy_next_authorities_addresses_hashes_vec.push(hash_typed);
    // }

    // );
    // let beefy_next_authorities_addresses_hashes=[];
    // beefy_next_authorities_addresses_hashes_vec.forEach( hash =>{
    //   beefy_next_authorities_addresses_hashes.push.apply(beefy_next_authorities_addresses_hashes, hash.toU8a());
    // }
    // );
    // console.log(`${beefy_next_authorities_addresses_hashes.length}`);

    // api.createType("Vec<u64>", [block_number])
    let mmr_proof = await api.rpc.mmr.generateProof([block_number], block_number);
    let mmr_proof_leaves = mmr_proof.leaves;
    let mmr_proof_proof = mmr_proof.proof;
    console.log(`${mmr_proof_leaves}`);
    console.log(`${mmr_proof_proof}`);
    console.log(`${mmr_proof_leaves.toJSON()}`);
    console.log(`${mmr_proof_leaves.toHuman()}`);
    0x04c5010002de760067f6d6b23cf0e2b54be0123eb247e2c05fb158f226c0227413b54e1c392ea2ad32340000000000006e000000c55a8a7c09f6f5f60f0e6d493777beb0c9ea832a5a52b7d0e977886cf51b160357328c2a2eedeb29b00e947f17e1f06893a58cd254a0a8f39cffefea6e4fd67b
    let mmr_proof_leaves_hash_hex = createKeccakHash('keccak256').update(Buffer.from(mmr_proof_leaves.toHex().substring(2), 'hex')).digest('hex');
    console.log(`${mmr_proof_leaves_hash_hex}`);

    let mangata_read_proof = await mangataApi.rpc.state.getReadProof([MANGATA_READ_STORAGE_KEY], mangata_parachain_block_hash);
    let mangata_read_proof_proof = mangata_read_proof.proof;
    console.log(`${mangata_read_proof}`);
    console.log(`${mangata_read_proof_proof[0].length}`);

    let buffer_string = "";
    let buffer_index = api.createType("Vec<u32>", "");
    let acc =0;
    mangata_read_proof_proof.forEach( proof_item => {
      buffer_string = buffer_string + proof_item.toString().substring(2);
      buffer_index.push(acc);
      acc = acc + proof_item.length;
      // console.log(`${proof_item.toString().substring(2)}`);
      // console.log(`${proof_item.length}`);
    });

    // buffer_string = "0x" + buffer_string;
    let buffer = Uint8Array.from(Buffer.from(buffer_string, 'hex'));
    // let buffer_test = Uint8Array.from(Buffer.from(
    // "7e6760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d809f45a2fe2d96d6830000000000000000a8d89d35a54a943d5bcbbd3d000000008000508004463304a4facc9ff056ffa9097c8a91d68ca1cccb122eda70be6e44a003f8404c5e7b9012096b41c4eb3aaf947f6ea42908000080006880414799b544d2dbd64b09170174d5fe0a30a472dc1691f9986f6f8e59f48a735d800f0444421fb8ed91ede17ae6ed359b61d8d3a6a0a54f57234de976cc2dbede31803f5959b9a96b4c9e3344c3896909b5804959fb1ebedc5546655a1834b146ebb480020280b47dc0661365487b113b8a22cc22861cefc23633d833bae24bf19fc13d0c670980c0365e1a9f3b1e86bea53d6b695a04d4aaeaf1e86bc2e653291f5caf13b6f48480fff7807ed0b615709be462f58d72d85f917b9b776eec093b0f21b5710f87618534a74d802d667983a90c102f05657ca320290aa3fa89416c6cee682499192b0ce0c30b5e805e51e3f50de0f9e7abd56a17845aaf725ad40bae4b940e10013faa4c1e202eb1806a4fadb4797f694b3076e8dc81ceb93bf5fd8746c9ebc1eaa76957138de847698094eaa0b7c27c7a8b1aa0040990eee801b9e97f8bb00c5dd8c43c18d26b58f60380640921e9d871f472edfcabbf1d10603602885f5fe117828fa3742033b831ea8c80b34caaa336779570cd6f8e4778f0191ca125efe72e46c8f0c86fa279fba6d0288049820292abce31b8edf15d592d48abdbed310b99099594ed222685a4781df147803700bd4ab8bf0bdb798738639c62b12dc0c126659279c0dcb0a35d7f9d71ea678061dbd610d5eb109e6af1f9bfd8f3ef0ab4b2bcd0ad1c4b80f6e521f9270fe42b80ef6dfe36f1ab13cf13b0cf1af1ee84313447e5f56fae43edba4c0c6858444e5a80ed9c76eb06577fcf59b6de511c956eb2e5663d6d0c14e5325ab37de097b76e1d8097c0deffb6fbfcffa8c0a53a2f08516f2aa78c291ac97e49e59df8a7f4982eab806b5c36c449d222e68e2dff6509cd53de0229857e2918919213d60288ddede11e80fa5bacacdd84e7a603af8c08943f6beb42bb30b36db89c5efdf3f2c828647efd9e72016d74b63ae83d79b02efdb5528e2a5c8098acae6f085272bc6d0a40c7b93ea121c2fd2bc63a4e8483743aa68d636218be80e64ff2ff4d62878c028757c2aa7f623c142f37e6d19e3e8d5e85fdc103b1b48e80c481174bb612e6118bdc157049374467c7341c348d616dffdb0266314056ec2380d47138a5d6383ccbbb325677b0c442b1cfcaa6a49a8587813138e28fca815bd9805faed0d9fe0067b63cff309f58a7a3e45b43786891a75aaa10f497039268c13e807b07240b127aae6b8f01afc94292f10734ab39b6dd4d68b8f7e751b5deff84b38075cb4e7ff091f2513ddf20e033e2a0b8b0fd9e19322bc0ea2ad7d44ccf81894f9eedab01919142839236b4c481d70adbd00080cd5f4d0e7861d719ccb82d2bb1f07cc5def1fbb2f2464c4ad654d778bfdbb93580bb073bb3e34b3452e00d5462f2467ffd03d7ca6d0ebb5fa9ccf160428de843b6806c7b634ea600985f191004b4743f7a3b742837cef5c4503c1b1d41ef2831c724"
    // , 'hex'));
    // let buffer_test = Uint8Array.from(Buffer.from(
    //   "7e"
    //   , 'hex'));
    console.log(`${buffer_string}`);
    console.log(`${buffer_index}`);
    console.log(`${buffer}`);
    // console.log(`${buffer_test}`);
    let key_u8a = Uint8Array.from(Buffer.from(MANGATA_READ_STORAGE_KEY.substring(2), 'hex'));
    console.log(`${key_u8a}`);



    // const provider = new Provider({ sequencer: { baseUrl:"http://0.0.0.0:5050"} });
    const provider = new RpcProvider({ nodeUrl: 'http://0.0.0.0:5050' } );
    const privateKey = "0x1800000000300000180000000000030000000000003006001800006600";
    const accountAddress = "0x517ececd29116499f4a1b64b094da79ba08dfd54a3edaa316134c41f8160973";


   
    const account = new Account(provider, accountAddress, privateKey);
    
    // // Connect the deployed Test contract in Tesnet
    // const testAddress = "0x07c514688d6d86e0af22565b57849791d2870f1b4c67dc3921c93f2b7d34c7a3";

    // // read abi of Test contract
    // const { abi: testAbi } = await provider.getClassAt(testAddress);
    // if (testAbi === undefined) { throw new Error("no abi.") };
    // const myTestContract = new Contract(testAbi, testAddress, provider);

    const compiledTestSierra = json.parse(fs.readFileSync( "/hdd/work/cairo-ws/alexandria-mangata/src/lean-beefy-test/target/dev/contracts_MangataStateFinality.sierra.json").toString( "ascii"));
    const compiledTestCasm = json.parse(fs.readFileSync( "/hdd/work/cairo-ws/alexandria-mangata/src/lean-beefy-test/target/dev/contracts_MangataStateFinality.casm.json").toString( "ascii"));
    
    const contractCallData = new CallData(compiledTestSierra.abi);
    const contractConstructor = contractCallData.compile("constructor", {
            contract_owner: "0x517ececd29116499f4a1b64b094da79ba08dfd54a3edaa316134c41f8160973"
        });

    const deployResponse = await account.declareAndDeploy({ contract: compiledTestSierra, casm: compiledTestCasm, constructorCalldata: contractConstructor });
    const { abi: testAbi } = await provider.getClassAt(deployResponse.deploy.contract_address);
    if (testAbi === undefined) { throw new Error("no abi.") };
    // Connect the new contract instance:
    const myTestContract = new Contract(testAbi, deployResponse.deploy.contract_address, provider);

    // Interaction with the contract with call
    const ad = await myTestContract.get_contract_owner();
    console.log("Contract Owner =", ad.toString());
    const vsi = await myTestContract.get_validator_set_info(4);
    console.log("vsi =", vsi.isNone());

    // Connect account with the contract
    myTestContract.connect(account);


    // Check if current block number is stale
    // and check if validator_set_id and the next one has been populated or not
    // populate accordingly

    let contract_last_block_number = await myTestContract.get_last_beefy_proof_info();

    // console.log("contract_last_block_number =", contract_last_block_number);
    // console.log("block_number =", block_number);

    if (contract_last_block_number.isSome()){
      if (contract_last_block_number.unwrap()>=block_number){
        { throw new Error("stale proof.") };      
      }
    }

    let next_validator_set_id = validator_set_id + 1n;
    let contract_validator_set_id_info = await myTestContract.get_validator_set_info(validator_set_id);
    let contract_next_validator_set_id_info = await myTestContract.get_validator_set_info(next_validator_set_id);

    if (contract_validator_set_id_info.isNone()){
      const set_validator_set_call = myTestContract.populate("set_validator_set_info_u8_array", [validator_set_id, beefy_authorities_addresses_vec_flat]);
      console.log(set_validator_set_call);
      const res = await myTestContract.set_validator_set_info_u8_array(set_validator_set_call.calldata);
      await provider.waitForTransaction(res.transaction_hash);
      const vsi_1 = await myTestContract.get_validator_set_info( validator_set_id);
      console.log("vsi_1 =", json.stringify( vsi_1.unwrap(), undefined, 2));

      const param = CallData.compile({
        validator_set_id : validator_set_id
      });
      console.log(param);
      const calculate_merkle_hash_for_validator_set_call = myTestContract.populate("calculate_merkle_hash_for_validator_set", param);
      console.log(calculate_merkle_hash_for_validator_set_call);
      const calculate_merkle_hash_for_validator_set_call_res = await myTestContract.calculate_merkle_hash_for_validator_set(calculate_merkle_hash_for_validator_set_call.calldata);
      await provider.waitForTransaction(calculate_merkle_hash_for_validator_set_call_res.transaction_hash);
      const vsi_1_1 = await myTestContract.get_validator_set_info( validator_set_id);
      console.log("vsi_1_1 =", json.stringify( vsi_1_1.unwrap(), undefined, 2));
    }

    if (contract_next_validator_set_id_info.isNone()){
      const set_next_validator_set_call = myTestContract.populate("set_validator_set_info_u8_array", [next_validator_set_id, beefy_next_authorities_addresses_vec_flat]);
      const res = await myTestContract.set_validator_set_info_u8_array(set_next_validator_set_call.calldata);
      await provider.waitForTransaction(res.transaction_hash);
      const vsi_1 = await myTestContract.get_validator_set_info( next_validator_set_id);
      console.log("vsi_1 =", json.stringify( vsi_1.unwrap(), undefined, 2));

      const param = CallData.compile({
        validator_set_id : next_validator_set_id
      });
      console.log(param);
      const calculate_merkle_hash_for_validator_set_call = myTestContract.populate("calculate_merkle_hash_for_validator_set", param);
      const calculate_merkle_hash_for_validator_set_call_res = await myTestContract.calculate_merkle_hash_for_validator_set(calculate_merkle_hash_for_validator_set_call.calldata);
      await provider.waitForTransaction(calculate_merkle_hash_for_validator_set_call_res.transaction_hash);
      const vsi_1_1 = await myTestContract.get_validator_set_info( next_validator_set_id);
      console.log("vsi_1_1 =", json.stringify( vsi_1_1.unwrap(), undefined, 2));
    }

    



    // const myCall = myTestContract.populate("set_validator_set_info_u8_array", [0, beefy_authorities_addresses_vec_flat]);
    // const res = await myTestContract.set_validator_set_info_u8_array(myCall.calldata);
    // await provider.waitForTransaction(res.transaction_hash);
    // const vsi_1 = await myTestContract.get_validator_set_info( 0);
    // console.log("vsi_1 =", json.stringify( vsi_1.unwrap(), undefined, 2));

    // const param = CallData.compile({
    //   lean_beefy_proof : beefyjustification.toU8a(),
    //   // sig_ver_limit: [0]
    // });
    // console.log(param);
    // console.log(beefyjustification);
    // console.log(beefyjustification.toString());
    // console.log(typeof beefyjustification.toString());


    // console.log(typeof beefyjustification);
    //     console.log(`${Object.prototype.toString.call(beefyjustification)}`);


    // let beefyjustification_U8a = beefyjustification.toU8a();

    // console.log(typeof beefyjustification_U8a);
    // console.log(`${Object.prototype.toString.call(beefyjustification_U8a)}`);
    // console.log(beefyjustification_U8a);
    // const param = CallData.compile({
    //   lean_beefy_proof : Array.from(beefyjustification_U8a),
    //   // sig_ver_limit: [0]
    // });

    // console.log(typeof beefyjustification);
    //     console.log(`${Object.prototype.toString.call(beefyjustification)}`);


    // let beefyjustification_U8a = beefyjustification.toU8a();

    // console.log(typeof beefyjustification_U8a);
    // console.log(`${Object.prototype.toString.call(beefyjustification_U8a)}`);
    // console.log(beefyjustification_U8a);
    // let buffer = Uint8Array.from(Buffer.from(buffer_string, 'hex'));

    let beefyjustification_array = Array.from(Uint8Array.from(Buffer.from(beefyjustification.toString().substring(2), 'hex')));
    console.log(Buffer.from(beefyjustification.toString(), 'hex'));
    console.log(Uint8Array.from(Buffer.from(beefyjustification.toString(), 'hex')));
    console.log(beefyjustification_array);
    const param = CallData.compile({
      lean_beefy_proof : beefyjustification_array,
      sig_ver_limit: 1,
      // sig_ver_limit_1: 1,
    });

    console.log(param);
    console.log(typeof param);
    console.log(`${Object.prototype.toString.call(param)}`);
    const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", beefyjustification_U8a);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", [beefyjustification.toString(), 0]);
    console.log(verify_lean_beefy_proof_call);
    const verify_lean_beefy_proof_call_res = await myTestContract.verify_lean_beefy_proof(verify_lean_beefy_proof_call.calldata);
    await provider.waitForTransaction(verify_lean_beefy_proof_call_res.transaction_hash);
    const get_current_mmr_root_res = await myTestContract.get_current_mmr_root();
    console.log("get_current_mmr_root_res =", json.stringify( get_current_mmr_root_res, undefined, 2));
    console.log(cairo.uint256(get_current_mmr_root_res.unwrap()));
    console.log(cairo.uint256(get_current_mmr_root_res.unwrap()).toString());
    const current_beefy_proof_info_res = await myTestContract.get_current_beefy_proof_info();
    console.log("current_beefy_proof_info_res =", json.stringify( current_beefy_proof_info_res, undefined, 2));


    console.log(`${mmr_proof_leaves}`);
    console.log(`${mmr_proof_proof}`);

    let mmr_proof_leaves_as_array = Array.from(Uint8Array.from(Buffer.from(mmr_proof_leaves.toHex().substring(2), 'hex')));
    let mmr_proof_proof_as_array = Array.from(Uint8Array.from(Buffer.from(mmr_proof_proof.toHex().substring(2), 'hex')));

    const mmr_param = CallData.compile({
      leaves : mmr_proof_leaves_as_array,
      proof: mmr_proof_proof_as_array
    });

    // console.log(param);
    // console.log(typeof param);
    // console.log(`${Object.prototype.toString.call(param)}`);
    const verify_beefy_mmr_leaves_proof_call = myTestContract.populate("verify_beefy_mmr_leaves_proof", mmr_param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", beefyjustification_U8a);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", [beefyjustification.toString(), 0]);
    console.log(verify_beefy_mmr_leaves_proof_call);
    const verify_beefy_mmr_leaves_proof_call_res = await myTestContract.verify_beefy_mmr_leaves_proof(verify_beefy_mmr_leaves_proof_call.calldata);
    await provider.waitForTransaction(verify_beefy_mmr_leaves_proof_call_res.transaction_hash);
    const current_beefy_data = await myTestContract.get_current_beefy_data();
    console.log("verify_beefy_mmr_leaves_proof_call_res =", json.stringify( current_beefy_data, undefined, 2));


    let mangata_parachain_leaf_as_array = Array.from(mangata_parachain_leaf);

    const verify_beefy_para_data_by_merklization_param = CallData.compile({
      leaf_index: BigInt(mangata_parachain_leaf_index),
      leaf: mangata_parachain_leaf_as_array,
      leaves_hashes: leaves_hashes,
    });

    // console.log(param);
    // console.log(typeof param);
    // console.log(`${Object.prototype.toString.call(param)}`);
    const verify_beefy_para_data_by_merklization_call = myTestContract.populate("verify_beefy_para_data_by_merklization", verify_beefy_para_data_by_merklization_param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", beefyjustification_U8a);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", param);
    // const verify_lean_beefy_proof_call = myTestContract.populate("verify_lean_beefy_proof", [beefyjustification.toString(), 0]);
    console.log(verify_beefy_para_data_by_merklization_call);
    const verify_beefy_para_data_by_merklization_call_res = await myTestContract.verify_beefy_para_data_by_merklization(verify_beefy_para_data_by_merklization_call.calldata);
    await provider.waitForTransaction(verify_beefy_para_data_by_merklization_call_res.transaction_hash);
    const current_para_data = await myTestContract.get_current_para_data();
    console.log("verify_beefy_para_data_by_merklization_call_res =", json.stringify( current_para_data, undefined, 2));
    
    // TODO - debug
    // Merkle root misatch with para data probably due to para data encoding/sorting 

    });
    
}

main().catch(console.error);


