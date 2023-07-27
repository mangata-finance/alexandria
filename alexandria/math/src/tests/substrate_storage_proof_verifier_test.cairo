use array::{ArrayTrait, SpanTrait};
use alexandria_math::blake2b::{convert_u8_array_to_felt252_array};
use alexandria_math::substrate_storage_proof_verifier::{verify_substrate_storage_proof,convert_u8_subarray_to_felt252_array};
use debug::PrintTrait;
use result::ResultTrait;


#[test]
#[available_gas(20000000000)]
fn test_fail() {
    let (buffer, buffer_index) = get_storage_proof_data();
    // let res = verify_substrate_storage_proof(buffer.span(), buffer_index.span(), get_key().span(), get_root().span()).unwrap();
    let res = verify_substrate_storage_proof(buffer.span(), buffer_index.span(), get_key().span(), get_root().span()).unwrap();
    // assert(msg.len() == 6400, 'Incorrect hash length');
    // assert(true==false, 'fail');
    panic(convert_u8_subarray_to_felt252_array(res.span, res.range.start, res.range.end - res.range.start));

}

#[test]
#[available_gas(20000000000)]
fn test_fail_2() {
    let (buffer, buffer_index) = get_storage_proof_data();
    // let res = verify_substrate_storage_proof(buffer.span(), buffer_index.span(), get_key().span(), get_root().span()).unwrap();
    let res = verify_substrate_storage_proof(buffer.span(), buffer_index.span(), get_key().span(), get_root().span()).unwrap();
    // assert(msg.len() == 6400, 'Incorrect hash length');
    // assert(true==false, 'fail');
    panic(convert_u8_subarray_to_felt252_array(res.span, res.range.start, res.range.end - res.range.start));

}

// Block number: 2,841,215
// Hash: 0x87699766114a1269d3f097248becb5ac73b0d74383529e038b5b4b2ee641aec3
// Parent hash: 0x572ccde2a4d35335e595c45509a53ee7fe29739cebad1221d8383c02bf6d4fed
// Extrinsic root: 0x4a9188715f84f368553f144b94fdc21e139e6fe761ceb02b67f9e6d8671d8880

// State root: 0xfdc56bd3a6e78790edf011e2e7468db8e41cc6ad6a3523b4acc035fc2ff410a2
// Encoded storage key: 0xcbedab01919142839236b4c481d70adb4c72016d74b63ae83d79b02efdb5528ee96760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d

// {
//   at: 0x87699766114a1269d3f097248becb5ac73b0d74383529e038b5b4b2ee641aec3
//   proof: [
//     0x7e6760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d80dac0c78dd0d92a000000000000000000c6b0015d90be39b67359810100000000
//     0x800012804ee23d258ffd21f2056056550114ea9bd24b4d1e7d8e217146a0ff51ef35fb4080ee4f0ed91001b2376037cd4406f53a07b8da6d330e2edfb960ac3b3ceeb2aa47
//     0x80005080dcb65578717ed86634a8cea32044916248c297218ffb611f693a724381be982f4c5e7b9012096b41c4eb3aaf947f6ea429080000
//     0x80006880bd80210e32a5313635944b7fea4c10af4b6156143b85984aecaa64b217f4a40a800f0444421fb8ed91ede17ae6ed359b61d8d3a6a0a54f57234de976cc2dbede3180946203184c1bd895ea5d1f678b846ca95fb67bef9333a7ae5a9b9cc195ea1dce
//     root - 0xfdc56bd3a6e78790edf011e2e7468db8e41cc6ad6a3523b4acc035fc2ff410a2
//     0x80fff780989daec3c59a0cc7092e31c7dbdd42a59d84ac855a987788628a68490251cc1580a1863838b7334959dbb2342c79d2e179875ad90735f9a2fa8aa6d922ab7aef188080a618078d331c51c7099d3e095ee72fbd3c2679621e52517a8d819fdd2a86e680fc6e5de247e2dabf97738ba19224190ac42f7b0c004d7babee4f82e9543b7a3b80ea205e4629887c328fa30800cbefa54480b13bb44b24b3bddc8b84872bde3f8180625a245bb9127410d807a1088ed3c0c4d51849923e5fb96ef68ec3c21e340de680dc4bb00af8fbc7c23f2212bcbd07c5686a4a03cb795271e7151a0fe50b7ad3c080437fec2d7a61f021052b4ce9b62ef90f08bbb72abb8ec0b281e298b53fdd4a0280c8e7e9ec0401b44487b1f7204d9259e4ac2440a2bb6609c751b17aebd45a94cc800721022dce0d957153717a570451a8bb91c8b47fccdfa6949693b0caf698d2f880792ae864b2fd3712fb5c4ca36368a2092cea4eccd2d7cefba1906fccbe8fb395800962c9c6baab455860e6b80fd9f672e09b622438f3dfd65a294b4fb038e38c8e8097c0deffb6fbfcffa8c0a53a2f08516f2aa78c291ac97e49e59df8a7f4982eab80e760ab94cb4eeac545835fd9ff0bfb7024ba6b88b98261d1df3abef97196b4d280727d7813fcb36c9551f8428e64b97c29ec875281bb27ab43487e6e59e82d7609
//     0x9e72016d74b63ae83d79b02efdb5528e2b5580d3b9a4400b3bf8a20d3bd5f3a5fd8e0b26c13dfe36df0b4792f8189db4d143fc80e6ad67a1fcb100a47df4d0207aa524c24c751a44527d136b648ff2d52f99e0fc80d772e567020fc1d4ab0958d554a077bd6fd42e11dcd795b18783c9152cc1661980055e5c73abb0bfcf5d3473627b26f9904938a5d5f530b0b1e774152514a6ef3f806a33219a657a67a766c7960c2dabbf07a76c53f00fa48114e7ee8e40eee9b38780894d01db5af87f96459f9b515ef52e9c45d325b73a3ac744830f6db7a7b622bf8001126ccfe8ff087539414d151726e77b33768d8d321d68ead220489ed14564db80177e3df8301cb7013f7416cc6c0facdbeaddded65001adf6973f02d9b0bfad3a
//     0x9eedab01919142839236b4c481d70adbd00080b796fe3a1816368272dfa8570674b8977a0e1a07e5330bfc2398f8aa1293f49a80853351d1a8bd27430a5348468e3377a2ecbcf4c0df15da7f38e4360b27d8eace80c5477b7680b943c66fd61077bdff0eaaa39a3ce070f1318e46f89b4f30603730
//   ]
// }

// [211, 132, 66 , 72, 142, 205, 140, 67 , 246, 226, 29 , 93 , 254, 130, 28 , 166, 156, 237, 15 , 199, 5, 63, 171, 18, 200, 18, 150, 180, 175, 32, 205, 45 , ]
// 128,253,197,107,211,166,231,135,144,237,240,17,226,231,70,141,184,228,28,198,173,106,53,35,180,172,192,53,252,47,244,16,162
// 128,189,221,129,60,99,66,57,114,49,113,239,63,238,152,87,155,148,150,78,59,177,203,62,66,114,98,200,192,104,213,35,25
// [189, 221, 129, 60 ('<'), 99 ('c'), 66 ('B'), 57 ('9'), 114 ('r'), 49 ('1'), 113 ('q'), 239, 63 ('?'), 238, 152, 87 ('W'), 155, 148, 150, 78 ('N'), 59 (';'), 177, 203, 62 ('>'), 66 ('B'), 114 ('r'), 98 ('b'), 200, 192, 104 ('h'), 213, 35 ('#'), 25 (''), ]

fn get_key() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xcb);i.append(0xed);i.append(0xab);i.append(0x01);i.append(0x91);i.append(0x91);i.append(0x42);i.append(0x83);i.append(0x92);i.append(0x36);i.append(0xb4);i.append(0xc4);i.append(0x81);i.append(0xd7);i.append(0x0a);i.append(0xdb);i.append(0x4c);i.append(0x72);i.append(0x01);i.append(0x6d);i.append(0x74);i.append(0xb6);i.append(0x3a);i.append(0xe8);i.append(0x3d);i.append(0x79);i.append(0xb0);i.append(0x2e);i.append(0xfd);i.append(0xb5);i.append(0x52);i.append(0x8e);i.append(0xe9);i.append(0x67);i.append(0x60);i.append(0xd2);i.append(0x74);i.append(0x65);i.append(0x3a);i.append(0x39);i.append(0xb4);i.append(0x29);i.append(0xa8);i.append(0x7e);i.append(0xba);i.append(0xae);i.append(0x9d);i.append(0x3a);i.append(0xa4);i.append(0xfd);i.append(0xf5);i.append(0x8b);i.append(0x90);i.append(0x96);i.append(0xcf);i.append(0x0b);i.append(0xeb);i.append(0xc7);i.append(0xc4);i.append(0xe5);i.append(0xa4);i.append(0xc2);i.append(0xed);i.append(0x8d);
    i
}

fn get_root() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xfd);i.append(0xc5);i.append(0x6b);i.append(0xd3);i.append(0xa6);i.append(0xe7);i.append(0x87);i.append(0x90);i.append(0xed);i.append(0xf0);i.append(0x11);i.append(0xe2);i.append(0xe7);i.append(0x46);i.append(0x8d);i.append(0xb8);i.append(0xe4);i.append(0x1c);i.append(0xc6);i.append(0xad);i.append(0x6a);i.append(0x35);i.append(0x23);i.append(0xb4);i.append(0xac);i.append(0xc0);i.append(0x35);i.append(0xfc);i.append(0x2f);i.append(0xf4);i.append(0x10);i.append(0xa2);
    i
}

fn get_storage_proof_data() -> (Array<u8>, Array<usize>) {
//   proof: [
    //         0
    // 130 -> 65 bytes
    // 7e6760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d80dac0c78dd0d92a000000000000000000c6b0015d90be39b67359810100000000
    //         65
    // 138 -> 69 bytes
    // 800012804ee23d258ffd21f2056056550114ea9bd24b4d1e7d8e217146a0ff51ef35fb4080ee4f0ed91001b2376037cd4406f53a07b8da6d330e2edfb960ac3b3ceeb2aa47
    //         134
    // 112 -> 56 bytes
    // 80005080dcb65578717ed86634a8cea32044916248c297218ffb611f693a724381be982f4c5e7b9012096b41c4eb3aaf947f6ea429080000
    //         190
    // 204 -> 102 bytes
    // 80006880bd80210e32a5313635944b7fea4c10af4b6156143b85984aecaa64b217f4a40a800f0444421fb8ed91ede17ae6ed359b61d8d3a6a0a54f57234de976cc2dbede3180946203184c1bd895ea5d1f678b846ca95fb67bef9333a7ae5a9b9cc195ea1dce
    //         292
    // 996 -> 498 bytes
    // 80fff780989daec3c59a0cc7092e31c7dbdd42a59d84ac855a987788628a68490251cc1580a1863838b7334959dbb2342c79d2e179875ad90735f9a2fa8aa6d922ab7aef188080a618078d331c51c7099d3e095ee72fbd3c2679621e52517a8d819fdd2a86e680fc6e5de247e2dabf97738ba19224190ac42f7b0c004d7babee4f82e9543b7a3b80ea205e4629887c328fa30800cbefa54480b13bb44b24b3bddc8b84872bde3f8180625a245bb9127410d807a1088ed3c0c4d51849923e5fb96ef68ec3c21e340de680dc4bb00af8fbc7c23f2212bcbd07c5686a4a03cb795271e7151a0fe50b7ad3c080437fec2d7a61f021052b4ce9b62ef90f08bbb72abb8ec0b281e298b53fdd4a0280c8e7e9ec0401b44487b1f7204d9259e4ac2440a2bb6609c751b17aebd45a94cc800721022dce0d957153717a570451a8bb91c8b47fccdfa6949693b0caf698d2f880792ae864b2fd3712fb5c4ca36368a2092cea4eccd2d7cefba1906fccbe8fb395800962c9c6baab455860e6b80fd9f672e09b622438f3dfd65a294b4fb038e38c8e8097c0deffb6fbfcffa8c0a53a2f08516f2aa78c291ac97e49e59df8a7f4982eab80e760ab94cb4eeac545835fd9ff0bfb7024ba6b88b98261d1df3abef97196b4d280727d7813fcb36c9551f8428e64b97c29ec875281bb27ab43487e6e59e82d7609
    //         790
    // 564 -> 282 bytes
    // 9e72016d74b63ae83d79b02efdb5528e2b5580d3b9a4400b3bf8a20d3bd5f3a5fd8e0b26c13dfe36df0b4792f8189db4d143fc80e6ad67a1fcb100a47df4d0207aa524c24c751a44527d136b648ff2d52f99e0fc80d772e567020fc1d4ab0958d554a077bd6fd42e11dcd795b18783c9152cc1661980055e5c73abb0bfcf5d3473627b26f9904938a5d5f530b0b1e774152514a6ef3f806a33219a657a67a766c7960c2dabbf07a76c53f00fa48114e7ee8e40eee9b38780894d01db5af87f96459f9b515ef52e9c45d325b73a3ac744830f6db7a7b622bf8001126ccfe8ff087539414d151726e77b33768d8d321d68ead220489ed14564db80177e3df8301cb7013f7416cc6c0facdbeaddded65001adf6973f02d9b0bfad3a
    //         1072
    // 234 -> 117 bytes
    // 9eedab01919142839236b4c481d70adbd00080b796fe3a1816368272dfa8570674b8977a0e1a07e5330bfc2398f8aa1293f49a80853351d1a8bd27430a5348468e3377a2ecbcf4c0df15da7f38e4360b27d8eace80c5477b7680b943c66fd61077bdff0eaaa39a3ce070f1318e46f89b4f30603730
    //         1189
//   ]

    let mut index_array: Array<usize> = Default::default();
    index_array.append(0);
    index_array.append(65);
    index_array.append(134);
    index_array.append(190);
    index_array.append(292);
    index_array.append(790);
    index_array.append(1072);

    let mut i: Array<u8> = Default::default();
    i.append(0x7e);i.append(0x67);i.append(0x60);i.append(0xd2);i.append(0x74);i.append(0x65);i.append(0x3a);i.append(0x39);i.append(0xb4);i.append(0x29);i.append(0xa8);i.append(0x7e);i.append(0xba);i.append(0xae);i.append(0x9d);i.append(0x3a);i.append(0xa4);i.append(0xfd);i.append(0xf5);i.append(0x8b);i.append(0x90);i.append(0x96);i.append(0xcf);i.append(0x0b);i.append(0xeb);i.append(0xc7);i.append(0xc4);i.append(0xe5);i.append(0xa4);i.append(0xc2);i.append(0xed);i.append(0x8d);i.append(0x80);i.append(0xda);i.append(0xc0);i.append(0xc7);i.append(0x8d);i.append(0xd0);i.append(0xd9);i.append(0x2a);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xc6);i.append(0xb0);i.append(0x01);i.append(0x5d);i.append(0x90);i.append(0xbe);i.append(0x39);i.append(0xb6);i.append(0x73);i.append(0x59);i.append(0x81);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
    i.append(0x80);i.append(0x00);i.append(0x12);i.append(0x80);i.append(0x4e);i.append(0xe2);i.append(0x3d);i.append(0x25);i.append(0x8f);i.append(0xfd);i.append(0x21);i.append(0xf2);i.append(0x05);i.append(0x60);i.append(0x56);i.append(0x55);i.append(0x01);i.append(0x14);i.append(0xea);i.append(0x9b);i.append(0xd2);i.append(0x4b);i.append(0x4d);i.append(0x1e);i.append(0x7d);i.append(0x8e);i.append(0x21);i.append(0x71);i.append(0x46);i.append(0xa0);i.append(0xff);i.append(0x51);i.append(0xef);i.append(0x35);i.append(0xfb);i.append(0x40);i.append(0x80);i.append(0xee);i.append(0x4f);i.append(0x0e);i.append(0xd9);i.append(0x10);i.append(0x01);i.append(0xb2);i.append(0x37);i.append(0x60);i.append(0x37);i.append(0xcd);i.append(0x44);i.append(0x06);i.append(0xf5);i.append(0x3a);i.append(0x07);i.append(0xb8);i.append(0xda);i.append(0x6d);i.append(0x33);i.append(0x0e);i.append(0x2e);i.append(0xdf);i.append(0xb9);i.append(0x60);i.append(0xac);i.append(0x3b);i.append(0x3c);i.append(0xee);i.append(0xb2);i.append(0xaa);i.append(0x47);
    i.append(0x80);i.append(0x00);i.append(0x50);i.append(0x80);i.append(0xdc);i.append(0xb6);i.append(0x55);i.append(0x78);i.append(0x71);i.append(0x7e);i.append(0xd8);i.append(0x66);i.append(0x34);i.append(0xa8);i.append(0xce);i.append(0xa3);i.append(0x20);i.append(0x44);i.append(0x91);i.append(0x62);i.append(0x48);i.append(0xc2);i.append(0x97);i.append(0x21);i.append(0x8f);i.append(0xfb);i.append(0x61);i.append(0x1f);i.append(0x69);i.append(0x3a);i.append(0x72);i.append(0x43);i.append(0x81);i.append(0xbe);i.append(0x98);i.append(0x2f);i.append(0x4c);i.append(0x5e);i.append(0x7b);i.append(0x90);i.append(0x12);i.append(0x09);i.append(0x6b);i.append(0x41);i.append(0xc4);i.append(0xeb);i.append(0x3a);i.append(0xaf);i.append(0x94);i.append(0x7f);i.append(0x6e);i.append(0xa4);i.append(0x29);i.append(0x08);i.append(0x00);i.append(0x00);
    i.append(0x80);i.append(0x00);i.append(0x68);i.append(0x80);i.append(0xbd);i.append(0x80);i.append(0x21);i.append(0x0e);i.append(0x32);i.append(0xa5);i.append(0x31);i.append(0x36);i.append(0x35);i.append(0x94);i.append(0x4b);i.append(0x7f);i.append(0xea);i.append(0x4c);i.append(0x10);i.append(0xaf);i.append(0x4b);i.append(0x61);i.append(0x56);i.append(0x14);i.append(0x3b);i.append(0x85);i.append(0x98);i.append(0x4a);i.append(0xec);i.append(0xaa);i.append(0x64);i.append(0xb2);i.append(0x17);i.append(0xf4);i.append(0xa4);i.append(0x0a);i.append(0x80);i.append(0x0f);i.append(0x04);i.append(0x44);i.append(0x42);i.append(0x1f);i.append(0xb8);i.append(0xed);i.append(0x91);i.append(0xed);i.append(0xe1);i.append(0x7a);i.append(0xe6);i.append(0xed);i.append(0x35);i.append(0x9b);i.append(0x61);i.append(0xd8);i.append(0xd3);i.append(0xa6);i.append(0xa0);i.append(0xa5);i.append(0x4f);i.append(0x57);i.append(0x23);i.append(0x4d);i.append(0xe9);i.append(0x76);i.append(0xcc);i.append(0x2d);i.append(0xbe);i.append(0xde);i.append(0x31);i.append(0x80);i.append(0x94);i.append(0x62);i.append(0x03);i.append(0x18);i.append(0x4c);i.append(0x1b);i.append(0xd8);i.append(0x95);i.append(0xea);i.append(0x5d);i.append(0x1f);i.append(0x67);i.append(0x8b);i.append(0x84);i.append(0x6c);i.append(0xa9);i.append(0x5f);i.append(0xb6);i.append(0x7b);i.append(0xef);i.append(0x93);i.append(0x33);i.append(0xa7);i.append(0xae);i.append(0x5a);i.append(0x9b);i.append(0x9c);i.append(0xc1);i.append(0x95);i.append(0xea);i.append(0x1d);i.append(0xce);
    i.append(0x80);i.append(0xff);i.append(0xf7);i.append(0x80);i.append(0x98);i.append(0x9d);i.append(0xae);i.append(0xc3);i.append(0xc5);i.append(0x9a);i.append(0x0c);i.append(0xc7);i.append(0x09);i.append(0x2e);i.append(0x31);i.append(0xc7);i.append(0xdb);i.append(0xdd);i.append(0x42);i.append(0xa5);i.append(0x9d);i.append(0x84);i.append(0xac);i.append(0x85);i.append(0x5a);i.append(0x98);i.append(0x77);i.append(0x88);i.append(0x62);i.append(0x8a);i.append(0x68);i.append(0x49);i.append(0x02);i.append(0x51);i.append(0xcc);i.append(0x15);i.append(0x80);i.append(0xa1);i.append(0x86);i.append(0x38);i.append(0x38);i.append(0xb7);i.append(0x33);i.append(0x49);i.append(0x59);i.append(0xdb);i.append(0xb2);i.append(0x34);i.append(0x2c);i.append(0x79);i.append(0xd2);i.append(0xe1);i.append(0x79);i.append(0x87);i.append(0x5a);i.append(0xd9);i.append(0x07);i.append(0x35);i.append(0xf9);i.append(0xa2);i.append(0xfa);i.append(0x8a);i.append(0xa6);i.append(0xd9);i.append(0x22);i.append(0xab);i.append(0x7a);i.append(0xef);i.append(0x18);i.append(0x80);i.append(0x80);i.append(0xa6);i.append(0x18);i.append(0x07);i.append(0x8d);i.append(0x33);i.append(0x1c);i.append(0x51);i.append(0xc7);i.append(0x09);i.append(0x9d);i.append(0x3e);i.append(0x09);i.append(0x5e);i.append(0xe7);i.append(0x2f);i.append(0xbd);i.append(0x3c);i.append(0x26);i.append(0x79);i.append(0x62);i.append(0x1e);i.append(0x52);i.append(0x51);i.append(0x7a);i.append(0x8d);i.append(0x81);i.append(0x9f);i.append(0xdd);i.append(0x2a);i.append(0x86);i.append(0xe6);i.append(0x80);i.append(0xfc);i.append(0x6e);i.append(0x5d);i.append(0xe2);i.append(0x47);i.append(0xe2);i.append(0xda);i.append(0xbf);i.append(0x97);i.append(0x73);i.append(0x8b);i.append(0xa1);i.append(0x92);i.append(0x24);i.append(0x19);i.append(0x0a);i.append(0xc4);i.append(0x2f);i.append(0x7b);i.append(0x0c);i.append(0x00);i.append(0x4d);i.append(0x7b);i.append(0xab);i.append(0xee);i.append(0x4f);i.append(0x82);i.append(0xe9);i.append(0x54);i.append(0x3b);i.append(0x7a);i.append(0x3b);i.append(0x80);i.append(0xea);i.append(0x20);i.append(0x5e);i.append(0x46);i.append(0x29);i.append(0x88);i.append(0x7c);i.append(0x32);i.append(0x8f);i.append(0xa3);i.append(0x08);i.append(0x00);i.append(0xcb);i.append(0xef);i.append(0xa5);i.append(0x44);i.append(0x80);i.append(0xb1);i.append(0x3b);i.append(0xb4);i.append(0x4b);i.append(0x24);i.append(0xb3);i.append(0xbd);i.append(0xdc);i.append(0x8b);i.append(0x84);i.append(0x87);i.append(0x2b);i.append(0xde);i.append(0x3f);i.append(0x81);i.append(0x80);i.append(0x62);i.append(0x5a);i.append(0x24);i.append(0x5b);i.append(0xb9);i.append(0x12);i.append(0x74);i.append(0x10);i.append(0xd8);i.append(0x07);i.append(0xa1);i.append(0x08);i.append(0x8e);i.append(0xd3);i.append(0xc0);i.append(0xc4);i.append(0xd5);i.append(0x18);i.append(0x49);i.append(0x92);i.append(0x3e);i.append(0x5f);i.append(0xb9);i.append(0x6e);i.append(0xf6);i.append(0x8e);i.append(0xc3);i.append(0xc2);i.append(0x1e);i.append(0x34);i.append(0x0d);i.append(0xe6);i.append(0x80);i.append(0xdc);i.append(0x4b);i.append(0xb0);i.append(0x0a);i.append(0xf8);i.append(0xfb);i.append(0xc7);i.append(0xc2);i.append(0x3f);i.append(0x22);i.append(0x12);i.append(0xbc);i.append(0xbd);i.append(0x07);i.append(0xc5);i.append(0x68);i.append(0x6a);i.append(0x4a);i.append(0x03);i.append(0xcb);i.append(0x79);i.append(0x52);i.append(0x71);i.append(0xe7);i.append(0x15);i.append(0x1a);i.append(0x0f);i.append(0xe5);i.append(0x0b);i.append(0x7a);i.append(0xd3);i.append(0xc0);i.append(0x80);i.append(0x43);i.append(0x7f);i.append(0xec);i.append(0x2d);i.append(0x7a);i.append(0x61);i.append(0xf0);i.append(0x21);i.append(0x05);i.append(0x2b);i.append(0x4c);i.append(0xe9);i.append(0xb6);i.append(0x2e);i.append(0xf9);i.append(0x0f);i.append(0x08);i.append(0xbb);i.append(0xb7);i.append(0x2a);i.append(0xbb);i.append(0x8e);i.append(0xc0);i.append(0xb2);i.append(0x81);i.append(0xe2);i.append(0x98);i.append(0xb5);i.append(0x3f);i.append(0xdd);i.append(0x4a);i.append(0x02);i.append(0x80);i.append(0xc8);i.append(0xe7);i.append(0xe9);i.append(0xec);i.append(0x04);i.append(0x01);i.append(0xb4);i.append(0x44);i.append(0x87);i.append(0xb1);i.append(0xf7);i.append(0x20);i.append(0x4d);i.append(0x92);i.append(0x59);i.append(0xe4);i.append(0xac);i.append(0x24);i.append(0x40);i.append(0xa2);i.append(0xbb);i.append(0x66);i.append(0x09);i.append(0xc7);i.append(0x51);i.append(0xb1);i.append(0x7a);i.append(0xeb);i.append(0xd4);i.append(0x5a);i.append(0x94);i.append(0xcc);i.append(0x80);i.append(0x07);i.append(0x21);i.append(0x02);i.append(0x2d);i.append(0xce);i.append(0x0d);i.append(0x95);i.append(0x71);i.append(0x53);i.append(0x71);i.append(0x7a);i.append(0x57);i.append(0x04);i.append(0x51);i.append(0xa8);i.append(0xbb);i.append(0x91);i.append(0xc8);i.append(0xb4);i.append(0x7f);i.append(0xcc);i.append(0xdf);i.append(0xa6);i.append(0x94);i.append(0x96);i.append(0x93);i.append(0xb0);i.append(0xca);i.append(0xf6);i.append(0x98);i.append(0xd2);i.append(0xf8);i.append(0x80);i.append(0x79);i.append(0x2a);i.append(0xe8);i.append(0x64);i.append(0xb2);i.append(0xfd);i.append(0x37);i.append(0x12);i.append(0xfb);i.append(0x5c);i.append(0x4c);i.append(0xa3);i.append(0x63);i.append(0x68);i.append(0xa2);i.append(0x09);i.append(0x2c);i.append(0xea);i.append(0x4e);i.append(0xcc);i.append(0xd2);i.append(0xd7);i.append(0xce);i.append(0xfb);i.append(0xa1);i.append(0x90);i.append(0x6f);i.append(0xcc);i.append(0xbe);i.append(0x8f);i.append(0xb3);i.append(0x95);i.append(0x80);i.append(0x09);i.append(0x62);i.append(0xc9);i.append(0xc6);i.append(0xba);i.append(0xab);i.append(0x45);i.append(0x58);i.append(0x60);i.append(0xe6);i.append(0xb8);i.append(0x0f);i.append(0xd9);i.append(0xf6);i.append(0x72);i.append(0xe0);i.append(0x9b);i.append(0x62);i.append(0x24);i.append(0x38);i.append(0xf3);i.append(0xdf);i.append(0xd6);i.append(0x5a);i.append(0x29);i.append(0x4b);i.append(0x4f);i.append(0xb0);i.append(0x38);i.append(0xe3);i.append(0x8c);i.append(0x8e);i.append(0x80);i.append(0x97);i.append(0xc0);i.append(0xde);i.append(0xff);i.append(0xb6);i.append(0xfb);i.append(0xfc);i.append(0xff);i.append(0xa8);i.append(0xc0);i.append(0xa5);i.append(0x3a);i.append(0x2f);i.append(0x08);i.append(0x51);i.append(0x6f);i.append(0x2a);i.append(0xa7);i.append(0x8c);i.append(0x29);i.append(0x1a);i.append(0xc9);i.append(0x7e);i.append(0x49);i.append(0xe5);i.append(0x9d);i.append(0xf8);i.append(0xa7);i.append(0xf4);i.append(0x98);i.append(0x2e);i.append(0xab);i.append(0x80);i.append(0xe7);i.append(0x60);i.append(0xab);i.append(0x94);i.append(0xcb);i.append(0x4e);i.append(0xea);i.append(0xc5);i.append(0x45);i.append(0x83);i.append(0x5f);i.append(0xd9);i.append(0xff);i.append(0x0b);i.append(0xfb);i.append(0x70);i.append(0x24);i.append(0xba);i.append(0x6b);i.append(0x88);i.append(0xb9);i.append(0x82);i.append(0x61);i.append(0xd1);i.append(0xdf);i.append(0x3a);i.append(0xbe);i.append(0xf9);i.append(0x71);i.append(0x96);i.append(0xb4);i.append(0xd2);i.append(0x80);i.append(0x72);i.append(0x7d);i.append(0x78);i.append(0x13);i.append(0xfc);i.append(0xb3);i.append(0x6c);i.append(0x95);i.append(0x51);i.append(0xf8);i.append(0x42);i.append(0x8e);i.append(0x64);i.append(0xb9);i.append(0x7c);i.append(0x29);i.append(0xec);i.append(0x87);i.append(0x52);i.append(0x81);i.append(0xbb);i.append(0x27);i.append(0xab);i.append(0x43);i.append(0x48);i.append(0x7e);i.append(0x6e);i.append(0x59);i.append(0xe8);i.append(0x2d);i.append(0x76);i.append(0x09);
    i.append(0x9e);i.append(0x72);i.append(0x01);i.append(0x6d);i.append(0x74);i.append(0xb6);i.append(0x3a);i.append(0xe8);i.append(0x3d);i.append(0x79);i.append(0xb0);i.append(0x2e);i.append(0xfd);i.append(0xb5);i.append(0x52);i.append(0x8e);i.append(0x2b);i.append(0x55);i.append(0x80);i.append(0xd3);i.append(0xb9);i.append(0xa4);i.append(0x40);i.append(0x0b);i.append(0x3b);i.append(0xf8);i.append(0xa2);i.append(0x0d);i.append(0x3b);i.append(0xd5);i.append(0xf3);i.append(0xa5);i.append(0xfd);i.append(0x8e);i.append(0x0b);i.append(0x26);i.append(0xc1);i.append(0x3d);i.append(0xfe);i.append(0x36);i.append(0xdf);i.append(0x0b);i.append(0x47);i.append(0x92);i.append(0xf8);i.append(0x18);i.append(0x9d);i.append(0xb4);i.append(0xd1);i.append(0x43);i.append(0xfc);i.append(0x80);i.append(0xe6);i.append(0xad);i.append(0x67);i.append(0xa1);i.append(0xfc);i.append(0xb1);i.append(0x00);i.append(0xa4);i.append(0x7d);i.append(0xf4);i.append(0xd0);i.append(0x20);i.append(0x7a);i.append(0xa5);i.append(0x24);i.append(0xc2);i.append(0x4c);i.append(0x75);i.append(0x1a);i.append(0x44);i.append(0x52);i.append(0x7d);i.append(0x13);i.append(0x6b);i.append(0x64);i.append(0x8f);i.append(0xf2);i.append(0xd5);i.append(0x2f);i.append(0x99);i.append(0xe0);i.append(0xfc);i.append(0x80);i.append(0xd7);i.append(0x72);i.append(0xe5);i.append(0x67);i.append(0x02);i.append(0x0f);i.append(0xc1);i.append(0xd4);i.append(0xab);i.append(0x09);i.append(0x58);i.append(0xd5);i.append(0x54);i.append(0xa0);i.append(0x77);i.append(0xbd);i.append(0x6f);i.append(0xd4);i.append(0x2e);i.append(0x11);i.append(0xdc);i.append(0xd7);i.append(0x95);i.append(0xb1);i.append(0x87);i.append(0x83);i.append(0xc9);i.append(0x15);i.append(0x2c);i.append(0xc1);i.append(0x66);i.append(0x19);i.append(0x80);i.append(0x05);i.append(0x5e);i.append(0x5c);i.append(0x73);i.append(0xab);i.append(0xb0);i.append(0xbf);i.append(0xcf);i.append(0x5d);i.append(0x34);i.append(0x73);i.append(0x62);i.append(0x7b);i.append(0x26);i.append(0xf9);i.append(0x90);i.append(0x49);i.append(0x38);i.append(0xa5);i.append(0xd5);i.append(0xf5);i.append(0x30);i.append(0xb0);i.append(0xb1);i.append(0xe7);i.append(0x74);i.append(0x15);i.append(0x25);i.append(0x14);i.append(0xa6);i.append(0xef);i.append(0x3f);i.append(0x80);i.append(0x6a);i.append(0x33);i.append(0x21);i.append(0x9a);i.append(0x65);i.append(0x7a);i.append(0x67);i.append(0xa7);i.append(0x66);i.append(0xc7);i.append(0x96);i.append(0x0c);i.append(0x2d);i.append(0xab);i.append(0xbf);i.append(0x07);i.append(0xa7);i.append(0x6c);i.append(0x53);i.append(0xf0);i.append(0x0f);i.append(0xa4);i.append(0x81);i.append(0x14);i.append(0xe7);i.append(0xee);i.append(0x8e);i.append(0x40);i.append(0xee);i.append(0xe9);i.append(0xb3);i.append(0x87);i.append(0x80);i.append(0x89);i.append(0x4d);i.append(0x01);i.append(0xdb);i.append(0x5a);i.append(0xf8);i.append(0x7f);i.append(0x96);i.append(0x45);i.append(0x9f);i.append(0x9b);i.append(0x51);i.append(0x5e);i.append(0xf5);i.append(0x2e);i.append(0x9c);i.append(0x45);i.append(0xd3);i.append(0x25);i.append(0xb7);i.append(0x3a);i.append(0x3a);i.append(0xc7);i.append(0x44);i.append(0x83);i.append(0x0f);i.append(0x6d);i.append(0xb7);i.append(0xa7);i.append(0xb6);i.append(0x22);i.append(0xbf);i.append(0x80);i.append(0x01);i.append(0x12);i.append(0x6c);i.append(0xcf);i.append(0xe8);i.append(0xff);i.append(0x08);i.append(0x75);i.append(0x39);i.append(0x41);i.append(0x4d);i.append(0x15);i.append(0x17);i.append(0x26);i.append(0xe7);i.append(0x7b);i.append(0x33);i.append(0x76);i.append(0x8d);i.append(0x8d);i.append(0x32);i.append(0x1d);i.append(0x68);i.append(0xea);i.append(0xd2);i.append(0x20);i.append(0x48);i.append(0x9e);i.append(0xd1);i.append(0x45);i.append(0x64);i.append(0xdb);i.append(0x80);i.append(0x17);i.append(0x7e);i.append(0x3d);i.append(0xf8);i.append(0x30);i.append(0x1c);i.append(0xb7);i.append(0x01);i.append(0x3f);i.append(0x74);i.append(0x16);i.append(0xcc);i.append(0x6c);i.append(0x0f);i.append(0xac);i.append(0xdb);i.append(0xea);i.append(0xdd);i.append(0xde);i.append(0xd6);i.append(0x50);i.append(0x01);i.append(0xad);i.append(0xf6);i.append(0x97);i.append(0x3f);i.append(0x02);i.append(0xd9);i.append(0xb0);i.append(0xbf);i.append(0xad);i.append(0x3a);
    i.append(0x9e);i.append(0xed);i.append(0xab);i.append(0x01);i.append(0x91);i.append(0x91);i.append(0x42);i.append(0x83);i.append(0x92);i.append(0x36);i.append(0xb4);i.append(0xc4);i.append(0x81);i.append(0xd7);i.append(0x0a);i.append(0xdb);i.append(0xd0);i.append(0x00);i.append(0x80);i.append(0xb7);i.append(0x96);i.append(0xfe);i.append(0x3a);i.append(0x18);i.append(0x16);i.append(0x36);i.append(0x82);i.append(0x72);i.append(0xdf);i.append(0xa8);i.append(0x57);i.append(0x06);i.append(0x74);i.append(0xb8);i.append(0x97);i.append(0x7a);i.append(0x0e);i.append(0x1a);i.append(0x07);i.append(0xe5);i.append(0x33);i.append(0x0b);i.append(0xfc);i.append(0x23);i.append(0x98);i.append(0xf8);i.append(0xaa);i.append(0x12);i.append(0x93);i.append(0xf4);i.append(0x9a);i.append(0x80);i.append(0x85);i.append(0x33);i.append(0x51);i.append(0xd1);i.append(0xa8);i.append(0xbd);i.append(0x27);i.append(0x43);i.append(0x0a);i.append(0x53);i.append(0x48);i.append(0x46);i.append(0x8e);i.append(0x33);i.append(0x77);i.append(0xa2);i.append(0xec);i.append(0xbc);i.append(0xf4);i.append(0xc0);i.append(0xdf);i.append(0x15);i.append(0xda);i.append(0x7f);i.append(0x38);i.append(0xe4);i.append(0x36);i.append(0x0b);i.append(0x27);i.append(0xd8);i.append(0xea);i.append(0xce);i.append(0x80);i.append(0xc5);i.append(0x47);i.append(0x7b);i.append(0x76);i.append(0x80);i.append(0xb9);i.append(0x43);i.append(0xc6);i.append(0x6f);i.append(0xd6);i.append(0x10);i.append(0x77);i.append(0xbd);i.append(0xff);i.append(0x0e);i.append(0xaa);i.append(0xa3);i.append(0x9a);i.append(0x3c);i.append(0xe0);i.append(0x70);i.append(0xf1);i.append(0x31);i.append(0x8e);i.append(0x46);i.append(0xf8);i.append(0x9b);i.append(0x4f);i.append(0x30);i.append(0x60);i.append(0x37);i.append(0x30);

    (i, index_array)
}


// 	// Block number: 2,841,215
// 	// Hash: 0x87699766114a1269d3f097248becb5ac73b0d74383529e038b5b4b2ee641aec3
// 	// Parent hash: 0x572ccde2a4d35335e595c45509a53ee7fe29739cebad1221d8383c02bf6d4fed
// 	// Extrinsic root: 0x4a9188715f84f368553f144b94fdc21e139e6fe761ceb02b67f9e6d8671d8880

// 	// State root: 0xfdc56bd3a6e78790edf011e2e7468db8e41cc6ad6a3523b4acc035fc2ff410a2
// 	// Encoded storage key: 0xcbedab01919142839236b4c481d70adb4c72016d74b63ae83d79b02efdb5528ee96760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d

// 	// {
// 	//   at: 0x87699766114a1269d3f097248becb5ac73b0d74383529e038b5b4b2ee641aec3
// 	//   proof: [
// 	//     0x7e6760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d80dac0c78dd0d92a000000000000000000c6b0015d90be39b67359810100000000
// 	//     0x800012804ee23d258ffd21f2056056550114ea9bd24b4d1e7d8e217146a0ff51ef35fb4080ee4f0ed91001b2376037cd4406f53a07b8da6d330e2edfb960ac3b3ceeb2aa47
// 	//     0x80005080dcb65578717ed86634a8cea32044916248c297218ffb611f693a724381be982f4c5e7b9012096b41c4eb3aaf947f6ea429080000
// 	//     0x80006880bd80210e32a5313635944b7fea4c10af4b6156143b85984aecaa64b217f4a40a800f0444421fb8ed91ede17ae6ed359b61d8d3a6a0a54f57234de976cc2dbede3180946203184c1bd895ea5d1f678b846ca95fb67bef9333a7ae5a9b9cc195ea1dce
// 	//     root - 0xfdc56bd3a6e78790edf011e2e7468db8e41cc6ad6a3523b4acc035fc2ff410a2
// 	//     0x80fff780989daec3c59a0cc7092e31c7dbdd42a59d84ac855a987788628a68490251cc1580a1863838b7334959dbb2342c79d2e179875ad90735f9a2fa8aa6d922ab7aef188080a618078d331c51c7099d3e095ee72fbd3c2679621e52517a8d819fdd2a86e680fc6e5de247e2dabf97738ba19224190ac42f7b0c004d7babee4f82e9543b7a3b80ea205e4629887c328fa30800cbefa54480b13bb44b24b3bddc8b84872bde3f8180625a245bb9127410d807a1088ed3c0c4d51849923e5fb96ef68ec3c21e340de680dc4bb00af8fbc7c23f2212bcbd07c5686a4a03cb795271e7151a0fe50b7ad3c080437fec2d7a61f021052b4ce9b62ef90f08bbb72abb8ec0b281e298b53fdd4a0280c8e7e9ec0401b44487b1f7204d9259e4ac2440a2bb6609c751b17aebd45a94cc800721022dce0d957153717a570451a8bb91c8b47fccdfa6949693b0caf698d2f880792ae864b2fd3712fb5c4ca36368a2092cea4eccd2d7cefba1906fccbe8fb395800962c9c6baab455860e6b80fd9f672e09b622438f3dfd65a294b4fb038e38c8e8097c0deffb6fbfcffa8c0a53a2f08516f2aa78c291ac97e49e59df8a7f4982eab80e760ab94cb4eeac545835fd9ff0bfb7024ba6b88b98261d1df3abef97196b4d280727d7813fcb36c9551f8428e64b97c29ec875281bb27ab43487e6e59e82d7609
// 	//     0x9e72016d74b63ae83d79b02efdb5528e2b5580d3b9a4400b3bf8a20d3bd5f3a5fd8e0b26c13dfe36df0b4792f8189db4d143fc80e6ad67a1fcb100a47df4d0207aa524c24c751a44527d136b648ff2d52f99e0fc80d772e567020fc1d4ab0958d554a077bd6fd42e11dcd795b18783c9152cc1661980055e5c73abb0bfcf5d3473627b26f9904938a5d5f530b0b1e774152514a6ef3f806a33219a657a67a766c7960c2dabbf07a76c53f00fa48114e7ee8e40eee9b38780894d01db5af87f96459f9b515ef52e9c45d325b73a3ac744830f6db7a7b622bf8001126ccfe8ff087539414d151726e77b33768d8d321d68ead220489ed14564db80177e3df8301cb7013f7416cc6c0facdbeaddded65001adf6973f02d9b0bfad3a
// 	//     0x9eedab01919142839236b4c481d70adbd00080b796fe3a1816368272dfa8570674b8977a0e1a07e5330bfc2398f8aa1293f49a80853351d1a8bd27430a5348468e3377a2ecbcf4c0df15da7f38e4360b27d8eace80c5477b7680b943c66fd61077bdff0eaaa39a3ce070f1318e46f89b4f30603730
// 	//   ]
// 	// }

// 	fn get_custom_test_data() -> (StorageProof, [u8;32], Vec<u8>){
// 		(
// 			StorageProof::new(vec![
// 			hex_literal::hex!("7e6760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d80dac0c78dd0d92a000000000000000000c6b0015d90be39b67359810100000000"
// 			).to_vec(),
// 			hex_literal::hex!("800012804ee23d258ffd21f2056056550114ea9bd24b4d1e7d8e217146a0ff51ef35fb4080ee4f0ed91001b2376037cd4406f53a07b8da6d330e2edfb960ac3b3ceeb2aa47"
// 			).to_vec(),
// 			hex_literal::hex!("80005080dcb65578717ed86634a8cea32044916248c297218ffb611f693a724381be982f4c5e7b9012096b41c4eb3aaf947f6ea429080000"
// 			).to_vec(),
// 			hex_literal::hex!("80006880bd80210e32a5313635944b7fea4c10af4b6156143b85984aecaa64b217f4a40a800f0444421fb8ed91ede17ae6ed359b61d8d3a6a0a54f57234de976cc2dbede3180946203184c1bd895ea5d1f678b846ca95fb67bef9333a7ae5a9b9cc195ea1dce"
// 			).to_vec(),
// 			hex_literal::hex!("80fff780989daec3c59a0cc7092e31c7dbdd42a59d84ac855a987788628a68490251cc1580a1863838b7334959dbb2342c79d2e179875ad90735f9a2fa8aa6d922ab7aef188080a618078d331c51c7099d3e095ee72fbd3c2679621e52517a8d819fdd2a86e680fc6e5de247e2dabf97738ba19224190ac42f7b0c004d7babee4f82e9543b7a3b80ea205e4629887c328fa30800cbefa54480b13bb44b24b3bddc8b84872bde3f8180625a245bb9127410d807a1088ed3c0c4d51849923e5fb96ef68ec3c21e340de680dc4bb00af8fbc7c23f2212bcbd07c5686a4a03cb795271e7151a0fe50b7ad3c080437fec2d7a61f021052b4ce9b62ef90f08bbb72abb8ec0b281e298b53fdd4a0280c8e7e9ec0401b44487b1f7204d9259e4ac2440a2bb6609c751b17aebd45a94cc800721022dce0d957153717a570451a8bb91c8b47fccdfa6949693b0caf698d2f880792ae864b2fd3712fb5c4ca36368a2092cea4eccd2d7cefba1906fccbe8fb395800962c9c6baab455860e6b80fd9f672e09b622438f3dfd65a294b4fb038e38c8e8097c0deffb6fbfcffa8c0a53a2f08516f2aa78c291ac97e49e59df8a7f4982eab80e760ab94cb4eeac545835fd9ff0bfb7024ba6b88b98261d1df3abef97196b4d280727d7813fcb36c9551f8428e64b97c29ec875281bb27ab43487e6e59e82d7609"
// 			).to_vec(),
// 			hex_literal::hex!("9e72016d74b63ae83d79b02efdb5528e2b5580d3b9a4400b3bf8a20d3bd5f3a5fd8e0b26c13dfe36df0b4792f8189db4d143fc80e6ad67a1fcb100a47df4d0207aa524c24c751a44527d136b648ff2d52f99e0fc80d772e567020fc1d4ab0958d554a077bd6fd42e11dcd795b18783c9152cc1661980055e5c73abb0bfcf5d3473627b26f9904938a5d5f530b0b1e774152514a6ef3f806a33219a657a67a766c7960c2dabbf07a76c53f00fa48114e7ee8e40eee9b38780894d01db5af87f96459f9b515ef52e9c45d325b73a3ac744830f6db7a7b622bf8001126ccfe8ff087539414d151726e77b33768d8d321d68ead220489ed14564db80177e3df8301cb7013f7416cc6c0facdbeaddded65001adf6973f02d9b0bfad3a"
// 			).to_vec(),	    
// 			hex_literal::hex!("9eedab01919142839236b4c481d70adbd00080b796fe3a1816368272dfa8570674b8977a0e1a07e5330bfc2398f8aa1293f49a80853351d1a8bd27430a5348468e3377a2ecbcf4c0df15da7f38e4360b27d8eace80c5477b7680b943c66fd61077bdff0eaaa39a3ce070f1318e46f89b4f30603730"
// 			).to_vec(),
// 			].into_iter())
// 			,
// 			hex_literal::hex!("fdc56bd3a6e78790edf011e2e7468db8e41cc6ad6a3523b4acc035fc2ff410a2")
// 			,
// 			hex_literal::hex!("cbedab01919142839236b4c481d70adb4c72016d74b63ae83d79b02efdb5528ee96760d274653a39b429a87ebaae9d3aa4fdf58b9096cf0bebc7c4e5a4c2ed8d"
// 			).to_vec()
// 		)
// 	}

// 	// Ok((12061438776951002, 465858865674911823104684230))
// // 	[
// //   12061438776951002
// //   465858865674911823104684230
// // ]

// 	#[test]
// 	fn read_proof_check_works() {
// 		use codec::Decode;
// 		let (storage_proof, root, key) = get_custom_test_data();
// 		let local_result1 =
// 			read_proof_check::<BlakeTwo256, _>(sp_core::H256(root), storage_proof, &[key.clone()]);
// 		// println!("{:?}", local_result1);
// 		let val = local_result1.unwrap().get(&key).unwrap().clone().unwrap();
// 		println!("{:?}", val);
// 		println!("{:?}", serde_json::Value::String(format!("0x{}", hex::encode(val.clone()))));
// 		let x = <(u128, u128)>::decode(&mut &val[..]);
// 		println!("{:?}", x);
// 	}
