use array::{ArrayTrait, SpanTrait};
use alexandria_substrate::lean_beefy_verifier::{BeefyData, BeefyAuthoritySet, encoded_opaque_leaves_to_leaves, verify_merkle_proof, hashes_to_u256s, merkelize_for_merkle_root, get_hashes_from_items,verify_mmr_leaves_proof,encoded_opaque_leaves_to_hashes,get_mmr_root, verify_lean_beefy_proof_with_validator_set, u256_byte_reverse, keccak, Slice, Range, verify_eth_signature_pre_hashed};
use alexandria_substrate::substrate_storage_read_proof_verifier::{convert_u8_subarray_to_u8_array, u8_array_eq};
use alexandria_substrate::blake2b::convert_u8_array_to_felt252_array;
use debug::PrintTrait;
use result::ResultTrait;
use core::clone::Clone;



use starknet::secp256_trait::{
    Signature, recover_public_key, verify_eth_signature, Secp256PointTrait, signature_from_vrs
};
use starknet::{eth_address::U256IntoEthAddress, EthAddress};
use integer::u256;
use starknet::secp256k1::{Secp256k1Point, Secp256k1PointImpl};

#[test]
#[available_gas(20000000000)]
fn custom_test() {
    {
        let pre_hashed_message = u256{ low:0x5ad896dbb14e39c1fecaff6ae02bbb50 

        ,high: 0xcee2819ce46ce268649072040ce1b33e} ;

        let v:u32 = 0x1;

        let r_high = 0x755a50112e6b29bbcabffd3fce5d7f1 ;

        let r_low = 0x10bc0ac7193b081b1fe25b885136414f ;

        // let r = u256{high: r_high, low: r_low};

        let s_high = 0x184d3f82b94a53eb15f889253c7b685d ;

        let s_low = 0xab08356867af8d581689c8b4c1ac9b3c ;

        // let s = u256{high: s_high, low: s_low};

        let a_high = 0xe04cc55e ;

        let a_low = 0xbee1cbce552f250e85c57b70b2e2625b;

        // let a = u256{high: a_high, low: a_low};

        let eth_signature = signature_from_vrs(v, u256{high: r_high, low: r_low }, u256{high:s_high, low:s_low});

        verify_eth_signature::<Secp256k1Point>(pre_hashed_message, eth_signature, Into::<u256, EthAddress>::into(u256{high:a_high, low:a_low}));
    }

}

#[test]
#[available_gas(20000000000)]
fn test_lean_beefy_proof_verification() {
    let res = verify_lean_beefy_proof_with_validator_set(get_lean_beefy_proof().span(), get_current_validator_addresses().span(), ArrayTrait::<u8>::new().span(), 3, 39);
    let maybe_mmr_root: Result<Span<u8>, felt252> = match res{
        Result::Ok(beefy_res)=>{
            let (_,beefy_payloads) =beefy_res;
            get_mmr_root(beefy_payloads.span())},
        Result::Err(e)=>{e.print(); assert(false, 'beefy ver failed');Result::Err('Dummy return')},
    };
    // panic(convert_u8_array_to_felt252_array(maybe_mmr_root.unwrap()));
    match maybe_mmr_root{
        Result::Ok(mmr_root)=>{ assert(u8_array_eq(mmr_root, get_expected_mmr_root().span()), 'mmr_root mismatch');},
        Result::Err(e)=>e.print(),
    };

    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');

}

// [179, 10, 26, 159, 204, 101, 198, 159, 193, 248, 252, 202, 209, 86, 155, 24, 110, 223, 138, 34, 95, 114, 204, 31, 32, 122, 203, 1, 9, 158, 139, 81]
fn get_expected_mmr_root() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(179);i.append(10);i.append(26);i.append(159);i.append(204);i.append(101);i.append(198);i.append(159);i.append(193);i.append(248);i.append(252);i.append(202);i.append(209);i.append(86);i.append(155);i.append(24);i.append(110);i.append(223);i.append(138);i.append(34);i.append(95);i.append(114);i.append(204);i.append(31);i.append(32);i.append(122);i.append(203);i.append(1);i.append(9);i.append(158);i.append(139);i.append(81);
    i
}

// finality_proof: V1(SignedCommitment { commitment: Commitment { payload: Payload([([109, 104], [179, 10, 26, 159, 204, 101, 198, 159, 193, 248, 252, 202, 209, 86, 155, 24, 110, 223, 138, 34, 95, 114, 204, 31, 32, 122, 203, 1, 9, 158, 139, 81])]), block_number: 39, validator_set_id: 3 }, signatures: [Some(Signature(78163315cf79e7d63f48cbd76b6f104f647d070145cd5efdcb83ff48dd8bf85d3fa53daf5a5862d7605d5cfcafbecd58e3a63710bf22d675e378a78032bbb70b00))] }).    
// [1, 4, 109, 104, 128, 179, 10, 26, 159, 204, 101, 198, 159, 193, 248, 252, 202, 209, 86, 155, 24, 110, 223, 138, 34, 95, 114, 204, 31, 32, 122, 203, 1, 9, 158, 139, 81, 39, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 128, 1, 0, 0, 0, 4, 120, 22, 51, 21, 207, 121, 231, 214, 63, 72, 203, 215, 107, 111, 16, 79, 100, 125, 7, 1, 69, 205, 94, 253, 203, 131, 255, 72, 221, 139, 248, 93, 63, 165, 61, 175, 90, 88, 98, 215, 96, 93, 92, 252, 175, 190, 205, 88, 227, 166, 55, 16, 191, 34, 214, 117, 227, 120, 167, 128, 50, 187, 183, 11, 0]
fn get_lean_beefy_proof() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(1); i.append(4); i.append(109); i.append(104); i.append(128); i.append(179); i.append(10); i.append(26); i.append(159); i.append(204); i.append(101); i.append(198); i.append(159); i.append(193); i.append(248); i.append(252); i.append(202); i.append(209); i.append(86); i.append(155); i.append(24); i.append(110); i.append(223); i.append(138); i.append(34); i.append(95); i.append(114); i.append(204); i.append(31); i.append(32); i.append(122); i.append(203); i.append(1); i.append(9); i.append(158); i.append(139); i.append(81); i.append(39); i.append(0); i.append(0); i.append(0); i.append(3); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(4); i.append(128); i.append(1); i.append(0); i.append(0); i.append(0); i.append(4); i.append(120); i.append(22); i.append(51); i.append(21); i.append(207); i.append(121); i.append(231); i.append(214); i.append(63); i.append(72); i.append(203); i.append(215); i.append(107); i.append(111); i.append(16); i.append(79); i.append(100); i.append(125); i.append(7); i.append(1); i.append(69); i.append(205); i.append(94); i.append(253); i.append(203); i.append(131); i.append(255); i.append(72); i.append(221); i.append(139); i.append(248); i.append(93); i.append(63); i.append(165); i.append(61); i.append(175); i.append(90); i.append(88); i.append(98); i.append(215); i.append(96); i.append(93); i.append(92); i.append(252); i.append(175); i.append(190); i.append(205); i.append(88); i.append(227); i.append(166); i.append(55); i.append(16); i.append(191); i.append(34); i.append(214); i.append(117); i.append(227); i.append(120); i.append(167); i.append(128); i.append(50); i.append(187); i.append(183); i.append(11); i.append(0);
    i
}

// [224, 76, 197, 94, 190, 225, 203, 206, 85, 47, 37, 14, 133, 197, 123, 112, 178, 226, 98, 91]
fn get_current_validator_addresses() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
    i
}

// Eth Address - [224, 76, 197, 94, 190, 225, 203, 206, 85, 47, 37, 14, 133, 197, 123, 112, 178, 226, 98, 91]    
// Eth Address - [e0, 4c, c5, 5e, be, e1, cb, ce, 55, 2f, 25, e, 85, c5, 7b, 70, b2, e2, 62, 5b]
// Authority Public(020a1091341fe5664bfa1782d5e04779689068c916b04cb365ec3153755684d9a1 (1CoWvCok...)), Message: [4, 109, 104, 128, 9, 60, 135, 194, 44, 243, 27, 165, 135, 135, 229, 11, 224, 172, 76, 236, 61, 110, 240, 137, 146, 98, 184, 184, 64, 91, 232, 194, 81, 142, 207, 195, 79, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0], Signature: Signature(0755a50112e6b29bbcabffd3fce5d7f110bc0ac7193b081b1fe25b885136414f184d3f82b94a53eb15f889253c7b685dab08356867af8d581689c8b4c1ac9b3c01), Address: Ok([224, 76, 197, 94, 190, 225, 203, 206, 85, 47, 37, 14, 133, 197, 123, 112, 178, 226, 98, 91])    
// finality_proof: V1(SignedCommitment { commitment: Commitment { payload: Payload([([109, 104], [9, 60, 135, 194, 44, 243, 27, 165, 135, 135, 229, 11, 224, 172, 76, 236, 61, 110, 240, 137, 146, 98, 184, 184, 64, 91, 232, 194, 81, 142, 207, 195])]), block_number: 79, validator_set_id: 7 }, signatures: [Some(Signature(0755a50112e6b29bbcabffd3fce5d7f110bc0ac7193b081b1fe25b885136414f184d3f82b94a53eb15f889253c7b685dab08356867af8d581689c8b4c1ac9b3c01))] }).    
// versioned_finality_proof encoded: [1, 4, 109, 104, 128, 9, 60, 135, 194, 44, 243, 27, 165, 135, 135, 229, 11, 224, 172, 76, 236, 61, 110, 240, 137, 146, 98, 184, 184, 64, 91, 232, 194, 81, 142, 207, 195, 79, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 4, 128, 1, 0, 0, 0, 4, 7, 85, 165, 1, 18, 230, 178, 155, 188, 171, 255, 211, 252, 229, 215, 241, 16, 188, 10, 199, 25, 59, 8, 27, 31, 226, 91, 136, 81, 54, 65, 79, 24, 77, 63, 130, 185, 74, 83, 235, 21, 248, 137, 37, 60, 123, 104, 93, 171, 8, 53, 104, 103, 175, 141, 88, 22, 137, 200, 180, 193, 172, 155, 60, 1].    
#[test]
#[available_gas(20000000000)]
fn test_lean_beefy_proof_verification_2() {
    let res = verify_lean_beefy_proof_with_validator_set(get_lean_beefy_proof_2().span(), get_current_validator_addresses_2().span(), ArrayTrait::<u8>::new().span(), 7, 79);
    let maybe_mmr_root: Result<Span<u8>, felt252> = match res{
        Result::Ok(beefy_res)=>{
            let (_,beefy_payloads) =beefy_res;
            get_mmr_root(beefy_payloads.span())},
        Result::Err(e)=>{e.print(); assert(false, 'beefy ver failed'); Result::Err('Dummy return')},
    };

    match maybe_mmr_root{
        Result::Ok(mmr_root)=>{ assert(u8_array_eq(mmr_root, get_expected_mmr_root_2().span()), 'mmr_root mismatch');},
        Result::Err(e)=>e.print(),
    };
    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');

}

// [9, 60, 135, 194, 44, 243, 27, 165, 135, 135, 229, 11, 224, 172, 76, 236, 61, 110, 240, 137, 146, 98, 184, 184, 64, 91, 232, 194, 81, 142, 207, 195]
fn get_expected_mmr_root_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(9);i.append(60);i.append(135);i.append(194);i.append(44);i.append(243);i.append(27);i.append(165);i.append(135);i.append(135);i.append(229);i.append(11);i.append(224);i.append(172);i.append(76);i.append(236);i.append(61);i.append(110);i.append(240);i.append(137);i.append(146);i.append(98);i.append(184);i.append(184);i.append(64);i.append(91);i.append(232);i.append(194);i.append(81);i.append(142);i.append(207);i.append(195);
    i
}

fn get_lean_beefy_proof_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(1); i.append(4); i.append(109); i.append(104); i.append(128); i.append(9); i.append(60); i.append(135); i.append(194); i.append(44); i.append(243); i.append(27); i.append(165); i.append(135); i.append(135); i.append(229); i.append(11); i.append(224); i.append(172); i.append(76); i.append(236); i.append(61); i.append(110); i.append(240); i.append(137); i.append(146); i.append(98); i.append(184); i.append(184); i.append(64); i.append(91); i.append(232); i.append(194); i.append(81); i.append(142); i.append(207); i.append(195); i.append(79); i.append(0); i.append(0); i.append(0); i.append(7); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(4); i.append(128); i.append(1); i.append(0); i.append(0); i.append(0); i.append(4); i.append(7); i.append(85); i.append(165); i.append(1); i.append(18); i.append(230); i.append(178); i.append(155); i.append(188); i.append(171); i.append(255); i.append(211); i.append(252); i.append(229); i.append(215); i.append(241); i.append(16); i.append(188); i.append(10); i.append(199); i.append(25); i.append(59); i.append(8); i.append(27); i.append(31); i.append(226); i.append(91); i.append(136); i.append(81); i.append(54); i.append(65); i.append(79); i.append(24); i.append(77); i.append(63); i.append(130); i.append(185); i.append(74); i.append(83); i.append(235); i.append(21); i.append(248); i.append(137); i.append(37); i.append(60); i.append(123); i.append(104); i.append(93); i.append(171); i.append(8); i.append(53); i.append(104); i.append(103); i.append(175); i.append(141); i.append(88); i.append(22); i.append(137); i.append(200); i.append(180); i.append(193); i.append(172); i.append(155); i.append(60); i.append(1);    
    i
}

fn get_current_validator_addresses_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
    i
}

#[test]
#[available_gas(20000000000)]
fn test_verify_eth_signature_pre_hashed() {
    let msg = get_msg().span();
    let commitment_pre_hashed_le = keccak(Slice{span: msg, range: Range{start: 0, end: msg.len()}});
    let commitment_pre_hashed = u256_byte_reverse(commitment_pre_hashed_le);

    let add = get_add().span();
    let add_slice = Slice{span: add, range: Range{start:0,end:add.len()}};

    let sig = get_sig().span();
    let sig_slice = Slice{span: sig, range: Range{start:0,end:sig.len()}};

    let res = verify_eth_signature_pre_hashed(commitment_pre_hashed, sig_slice, add_slice);
    assert(res, 'Sig ver failed');
    // res.print();
    // match res{
    //     Result::Ok(_)=>{},
    //     Result::Err(e)=>e.print(),
    // };
    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');
}

fn get_msg() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(4); i.append(109); i.append(104); i.append(0); i.append(1); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0);
    i
}

fn get_add() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
    i
}

fn get_sig() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x0d);i.append(0x4a);i.append(0x65);i.append(0x86);i.append(0xf4);i.append(0x9e);i.append(0x66);i.append(0x4c);i.append(0x79);i.append(0xb7);i.append(0x7f);i.append(0x20);i.append(0x6b);i.append(0xde);i.append(0x18);i.append(0xa6);i.append(0xa7);i.append(0xc0);i.append(0x78);i.append(0x70);i.append(0xe1);i.append(0x2e);i.append(0x01);i.append(0x18);i.append(0x62);i.append(0xb6);i.append(0x4f);i.append(0x3b);i.append(0x10);i.append(0xee);i.append(0xb8);i.append(0xd3);i.append(0x6a);i.append(0x8d);i.append(0xd9);i.append(0xf4);i.append(0x5b);i.append(0x36);i.append(0x3b);i.append(0x68);i.append(0xf8);i.append(0x75);i.append(0x73);i.append(0x4d);i.append(0x33);i.append(0xf5);i.append(0x3b);i.append(0x8b);i.append(0x05);i.append(0x3a);i.append(0x04);i.append(0x02);i.append(0x86);i.append(0x84);i.append(0x36);i.append(0x7b);i.append(0xf4);i.append(0x26);i.append(0xe4);i.append(0x66);i.append(0xd9);i.append(0x44);i.append(0x94);i.append(0x38);i.append(0x01);
    i
}

#[test]
#[available_gas(20000000000)]
fn test_verify_eth_signature_pre_hashed_2() {
    let msg = get_msg_2().span();
    let commitment_pre_hashed_le = keccak(Slice{span: msg, range: Range{start: 0, end: msg.len()}});
    let commitment_pre_hashed = u256_byte_reverse(commitment_pre_hashed_le);

    let add = get_add_2().span();
    let add_slice = Slice{span: add, range: Range{start:0,end:add.len()}};

    let sig = get_sig_2().span();
    let sig_slice = Slice{span: sig, range: Range{start:0,end:sig.len()}};

    let res = verify_eth_signature_pre_hashed(commitment_pre_hashed, sig_slice, add_slice);
    assert(res, 'Sig ver failed');
    // res.print();
    // match res{
    //     Result::Ok(_)=>{},
    //     Result::Err(e)=>e.print(),
    // };
    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');
}

fn get_msg_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(4); i.append(109); i.append(104); i.append(128); i.append(9); i.append(60); i.append(135); i.append(194); i.append(44); i.append(243); i.append(27); i.append(165); i.append(135); i.append(135); i.append(229); i.append(11); i.append(224); i.append(172); i.append(76); i.append(236); i.append(61); i.append(110); i.append(240); i.append(137); i.append(146); i.append(98); i.append(184); i.append(184); i.append(64); i.append(91); i.append(232); i.append(194); i.append(81); i.append(142); i.append(207); i.append(195); i.append(79); i.append(0); i.append(0); i.append(0); i.append(7); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0);
    i
}

fn get_add_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
    i
}
// [7, 85, 165, 1, 18, 230, 178, 155, 188, 171, 255, 211, 252, 229, 215, 241, 16, 188, 10, 199, 25, 59, 8, 27, 31, 226, 91, 136, 81, 54, 65, 79, 24, 77, 63, 130, 185, 74, 83, 235, 21, 248, 137, 37, 60, 123, 104, 93, 171, 8, 53, 104, 103, 175, 141, 88, 22, 137, 200, 180, 193, 172, 155, 60, 1]
fn get_sig_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x07);i.append(0x55);i.append(0xa5);i.append(0x01);i.append(0x12);i.append(0xe6);i.append(0xb2);i.append(0x9b);i.append(0xbc);i.append(0xab);i.append(0xff);i.append(0xd3);i.append(0xfc);i.append(0xe5);i.append(0xd7);i.append(0xf1);i.append(0x10);i.append(0xbc);i.append(0x0a);i.append(0xc7);i.append(0x19);i.append(0x3b);i.append(0x08);i.append(0x1b);i.append(0x1f);i.append(0xe2);i.append(0x5b);i.append(0x88);i.append(0x51);i.append(0x36);i.append(0x41);i.append(0x4f);i.append(0x18);i.append(0x4d);i.append(0x3f);i.append(0x82);i.append(0xb9);i.append(0x4a);i.append(0x53);i.append(0xeb);i.append(0x15);i.append(0xf8);i.append(0x89);i.append(0x25);i.append(0x3c);i.append(0x7b);i.append(0x68);i.append(0x5d);i.append(0xab);i.append(0x08);i.append(0x35);i.append(0x68);i.append(0x67);i.append(0xaf);i.append(0x8d);i.append(0x58);i.append(0x16);i.append(0x89);i.append(0xc8);i.append(0xb4);i.append(0xc1);i.append(0xac);i.append(0x9b);i.append(0x3c);i.append(0x01);
    i
}


// #1
// {
//   blockHash: 0xd68689ad3b1e430c9c1bdd45250792c1849afde61b761a87bd327701a73939af
//   leaves: 0x04c50100040000002744cc3e4b2f9d1d92cea93b8c1cad27767e41e5214270e219d611e30d28d2cc010000000000000001000000aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d70000000000000000000000000000000000000000000000000000000000000000
//   proof: 0x0404000000000000000a00000000000000103bacf5ac3ff912ccd0b20268ad054aefd2de8d233aece8166cb158fca10f2bfda5e1cafcd950449665ff1886a31aba5a702c6ae644df4b36c2d41c3a27ed838c86917851802d6cf421f5687729ba4a4360e3f61a2e7640faef058511843bde81e299901d8688fb6ff7daff092c5badf2d111f1768b2a1f7486a8ce15746ad5db
// }
#[test]
#[available_gas(20000000000)]
fn verify_mmr_leaves_proof_test(){
    let leaves_hashes = encoded_opaque_leaves_to_hashes(get_leaves().span()).unwrap();
    let res = verify_mmr_leaves_proof(mmr_root().span(), get_proof().span(), leaves_hashes.span());

    match res{
        Result::Ok(_)=>{},
        Result::Err(e)=>{e.print();
    assert(false, 'Ver failed');},
    };
    // panic(convert_u8_array_to_felt252_array(maybe_mmr_root.unwrap()));
}

fn get_leaves() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x04);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x04);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x27);i.append(0x44);i.append(0xcc);i.append(0x3e);i.append(0x4b);i.append(0x2f);i.append(0x9d);i.append(0x1d);i.append(0x92);i.append(0xce);i.append(0xa9);i.append(0x3b);i.append(0x8c);i.append(0x1c);i.append(0xad);i.append(0x27);i.append(0x76);i.append(0x7e);i.append(0x41);i.append(0xe5);i.append(0x21);i.append(0x42);i.append(0x70);i.append(0xe2);i.append(0x19);i.append(0xd6);i.append(0x11);i.append(0xe3);i.append(0x0d);i.append(0x28);i.append(0xd2);i.append(0xcc);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
    i
}

fn get_proof() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x04);i.append(0x04);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x0a);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x10);i.append(0x3b);i.append(0xac);i.append(0xf5);i.append(0xac);i.append(0x3f);i.append(0xf9);i.append(0x12);i.append(0xcc);i.append(0xd0);i.append(0xb2);i.append(0x02);i.append(0x68);i.append(0xad);i.append(0x05);i.append(0x4a);i.append(0xef);i.append(0xd2);i.append(0xde);i.append(0x8d);i.append(0x23);i.append(0x3a);i.append(0xec);i.append(0xe8);i.append(0x16);i.append(0x6c);i.append(0xb1);i.append(0x58);i.append(0xfc);i.append(0xa1);i.append(0x0f);i.append(0x2b);i.append(0xfd);i.append(0xa5);i.append(0xe1);i.append(0xca);i.append(0xfc);i.append(0xd9);i.append(0x50);i.append(0x44);i.append(0x96);i.append(0x65);i.append(0xff);i.append(0x18);i.append(0x86);i.append(0xa3);i.append(0x1a);i.append(0xba);i.append(0x5a);i.append(0x70);i.append(0x2c);i.append(0x6a);i.append(0xe6);i.append(0x44);i.append(0xdf);i.append(0x4b);i.append(0x36);i.append(0xc2);i.append(0xd4);i.append(0x1c);i.append(0x3a);i.append(0x27);i.append(0xed);i.append(0x83);i.append(0x8c);i.append(0x86);i.append(0x91);i.append(0x78);i.append(0x51);i.append(0x80);i.append(0x2d);i.append(0x6c);i.append(0xf4);i.append(0x21);i.append(0xf5);i.append(0x68);i.append(0x77);i.append(0x29);i.append(0xba);i.append(0x4a);i.append(0x43);i.append(0x60);i.append(0xe3);i.append(0xf6);i.append(0x1a);i.append(0x2e);i.append(0x76);i.append(0x40);i.append(0xfa);i.append(0xef);i.append(0x05);i.append(0x85);i.append(0x11);i.append(0x84);i.append(0x3b);i.append(0xde);i.append(0x81);i.append(0xe2);i.append(0x99);i.append(0x90);i.append(0x1d);i.append(0x86);i.append(0x88);i.append(0xfb);i.append(0x6f);i.append(0xf7);i.append(0xda);i.append(0xff);i.append(0x09);i.append(0x2c);i.append(0x5b);i.append(0xad);i.append(0xf2);i.append(0xd1);i.append(0x11);i.append(0xf1);i.append(0x76);i.append(0x8b);i.append(0x2a);i.append(0x1f);i.append(0x74);i.append(0x86);i.append(0xa8);i.append(0xce);i.append(0x15);i.append(0x74);i.append(0x6a);i.append(0xd5);i.append(0xdb);
    i
}


// 0xebfa14a7554db04e6128dc6102bb51e44970825d4c2bfb4c4b237af4efe7a791
fn mmr_root() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xeb);i.append(0xfa);i.append(0x14);i.append(0xa7);i.append(0x55);i.append(0x4d);i.append(0xb0);i.append(0x4e);i.append(0x61);i.append(0x28);i.append(0xdc);i.append(0x61);i.append(0x02);i.append(0xbb);i.append(0x51);i.append(0xe4);i.append(0x49);i.append(0x70);i.append(0x82);i.append(0x5d);i.append(0x4c);i.append(0x2b);i.append(0xfb);i.append(0x4c);i.append(0x4b);i.append(0x23);i.append(0x7a);i.append(0xf4);i.append(0xef);i.append(0xe7);i.append(0xa7);i.append(0x91);
    i
}

// #2
// {
//   blockHash: 0xf4e7fd42605a1f1a1d62fc6e71a3ce3be716c253e2baee794298362e83f90a4a
//   leaves: 0x04c501008f486d000177bc87189c450ce54ab78ddc73a601dbdc2de2bf522ebac658c485721e2742f02f0000000000006f00000003aff613b52959e3045f7ccbdef689259ee659ed2907cc28eb24fcafa65e281c044f454c1319230bbfbea1f4a999a43304365af54945e36ea8f9548946d07c1d
//   proof: 0x04133d330000000000893e3300000000004840dc3a58d2acbceacb547040880fc7615e6754e2ee366d5f9a6ecd1fec3984f7006050bb6734ed9a77b40d03bc4b877b6ba82212cb64205ef119aaae94969dc19508c9e68a69073066f39c0dedf492410998c3c6ab37b930d698bf722efee82b6979d17be05374274cbec6d6b994062d99801c69665a68c0ec6a952a51c46970ea70b4e37e7b1e4e959cdef784e29ee0d7efc31e39d3c7b4c40aecf1ba4a0ba5b06eb968e8374c60cbfed25d961f7c902e54910364fd042e343faa236cc80a8a91d0571158306c2c60acc99830446fbb0d17ee339b7ba86fb45407d2040eaae7eb1c65468de50b7c9df1da898ee615792c223bf40fa476abd572feb8e69d1c6ad5b9f7b67e7da6bacd7d000b4f6ef444f6a04a62c3619b702b1247dc35fce66a26b8712501f8a5f120978020bd4cefd0b3c6daa8f8a2011d255ed2b4b88bb86a29ad5b9340c395425d2c73d79f67e40a1eca3e16c51d534a4241d3723cca001a218767a0a8c105c44a59a9d2507672b7b94a5b513a5ba6557528800495da9c355d2c15252ee2b687c4d52f6166be652c90c9934833f52e92f8dc227da4d9a05291353caa257d522820c5d14cc745a80377abdbb444fd9a62e1283eb684c71a982afa72ed327643f3672015aa0fbffae7f8b31427b658e636b3dce9a651a730eef695593a14e2f338a7457053913a0ec59fb86827b93b7944c57332473cf3773d222c61347c78f2268c9485293250e2af08bb3537d5bc620c74c135862e55eba3a52a52301445a1ee28a2d5ac1219a00bc90a4377e8cfa32320f84f046a6d83ba
// }
#[test]
#[available_gas(20000000000)]
fn verify_mmr_leaves_proof_test_2(){
    let leaves_hashes = encoded_opaque_leaves_to_hashes(get_leaves_2().span()).unwrap();
    let res = verify_mmr_leaves_proof(mmr_root_2().span(), get_proof_2().span(), leaves_hashes.span());

    match res{
        Result::Ok(_)=>{},
        Result::Err(e)=>{e.print();
    assert(false, 'Ver failed');},
    };
    // panic(convert_u8_array_to_felt252_array(maybe_mmr_root.unwrap()));
}

fn get_leaves_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x04);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x8f);i.append(0x48);i.append(0x6d);i.append(0x00);i.append(0x01);i.append(0x77);i.append(0xbc);i.append(0x87);i.append(0x18);i.append(0x9c);i.append(0x45);i.append(0x0c);i.append(0xe5);i.append(0x4a);i.append(0xb7);i.append(0x8d);i.append(0xdc);i.append(0x73);i.append(0xa6);i.append(0x01);i.append(0xdb);i.append(0xdc);i.append(0x2d);i.append(0xe2);i.append(0xbf);i.append(0x52);i.append(0x2e);i.append(0xba);i.append(0xc6);i.append(0x58);i.append(0xc4);i.append(0x85);i.append(0x72);i.append(0x1e);i.append(0x27);i.append(0x42);i.append(0xf0);i.append(0x2f);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x6f);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x03);i.append(0xaf);i.append(0xf6);i.append(0x13);i.append(0xb5);i.append(0x29);i.append(0x59);i.append(0xe3);i.append(0x04);i.append(0x5f);i.append(0x7c);i.append(0xcb);i.append(0xde);i.append(0xf6);i.append(0x89);i.append(0x25);i.append(0x9e);i.append(0xe6);i.append(0x59);i.append(0xed);i.append(0x29);i.append(0x07);i.append(0xcc);i.append(0x28);i.append(0xeb);i.append(0x24);i.append(0xfc);i.append(0xaf);i.append(0xa6);i.append(0x5e);i.append(0x28);i.append(0x1c);i.append(0x04);i.append(0x4f);i.append(0x45);i.append(0x4c);i.append(0x13);i.append(0x19);i.append(0x23);i.append(0x0b);i.append(0xbf);i.append(0xbe);i.append(0xa1);i.append(0xf4);i.append(0xa9);i.append(0x99);i.append(0xa4);i.append(0x33);i.append(0x04);i.append(0x36);i.append(0x5a);i.append(0xf5);i.append(0x49);i.append(0x45);i.append(0xe3);i.append(0x6e);i.append(0xa8);i.append(0xf9);i.append(0x54);i.append(0x89);i.append(0x46);i.append(0xd0);i.append(0x7c);i.append(0x1d);
    i
}

fn get_proof_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x04);i.append(0x13);i.append(0x3d);i.append(0x33);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x89);i.append(0x3e);i.append(0x33);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x48);i.append(0x40);i.append(0xdc);i.append(0x3a);i.append(0x58);i.append(0xd2);i.append(0xac);i.append(0xbc);i.append(0xea);i.append(0xcb);i.append(0x54);i.append(0x70);i.append(0x40);i.append(0x88);i.append(0x0f);i.append(0xc7);i.append(0x61);i.append(0x5e);i.append(0x67);i.append(0x54);i.append(0xe2);i.append(0xee);i.append(0x36);i.append(0x6d);i.append(0x5f);i.append(0x9a);i.append(0x6e);i.append(0xcd);i.append(0x1f);i.append(0xec);i.append(0x39);i.append(0x84);i.append(0xf7);i.append(0x00);i.append(0x60);i.append(0x50);i.append(0xbb);i.append(0x67);i.append(0x34);i.append(0xed);i.append(0x9a);i.append(0x77);i.append(0xb4);i.append(0x0d);i.append(0x03);i.append(0xbc);i.append(0x4b);i.append(0x87);i.append(0x7b);i.append(0x6b);i.append(0xa8);i.append(0x22);i.append(0x12);i.append(0xcb);i.append(0x64);i.append(0x20);i.append(0x5e);i.append(0xf1);i.append(0x19);i.append(0xaa);i.append(0xae);i.append(0x94);i.append(0x96);i.append(0x9d);i.append(0xc1);i.append(0x95);i.append(0x08);i.append(0xc9);i.append(0xe6);i.append(0x8a);i.append(0x69);i.append(0x07);i.append(0x30);i.append(0x66);i.append(0xf3);i.append(0x9c);i.append(0x0d);i.append(0xed);i.append(0xf4);i.append(0x92);i.append(0x41);i.append(0x09);i.append(0x98);i.append(0xc3);i.append(0xc6);i.append(0xab);i.append(0x37);i.append(0xb9);i.append(0x30);i.append(0xd6);i.append(0x98);i.append(0xbf);i.append(0x72);i.append(0x2e);i.append(0xfe);i.append(0xe8);i.append(0x2b);i.append(0x69);i.append(0x79);i.append(0xd1);i.append(0x7b);i.append(0xe0);i.append(0x53);i.append(0x74);i.append(0x27);i.append(0x4c);i.append(0xbe);i.append(0xc6);i.append(0xd6);i.append(0xb9);i.append(0x94);i.append(0x06);i.append(0x2d);i.append(0x99);i.append(0x80);i.append(0x1c);i.append(0x69);i.append(0x66);i.append(0x5a);i.append(0x68);i.append(0xc0);i.append(0xec);i.append(0x6a);i.append(0x95);i.append(0x2a);i.append(0x51);i.append(0xc4);i.append(0x69);i.append(0x70);i.append(0xea);i.append(0x70);i.append(0xb4);i.append(0xe3);i.append(0x7e);i.append(0x7b);i.append(0x1e);i.append(0x4e);i.append(0x95);i.append(0x9c);i.append(0xde);i.append(0xf7);i.append(0x84);i.append(0xe2);i.append(0x9e);i.append(0xe0);i.append(0xd7);i.append(0xef);i.append(0xc3);i.append(0x1e);i.append(0x39);i.append(0xd3);i.append(0xc7);i.append(0xb4);i.append(0xc4);i.append(0x0a);i.append(0xec);i.append(0xf1);i.append(0xba);i.append(0x4a);i.append(0x0b);i.append(0xa5);i.append(0xb0);i.append(0x6e);i.append(0xb9);i.append(0x68);i.append(0xe8);i.append(0x37);i.append(0x4c);i.append(0x60);i.append(0xcb);i.append(0xfe);i.append(0xd2);i.append(0x5d);i.append(0x96);i.append(0x1f);i.append(0x7c);i.append(0x90);i.append(0x2e);i.append(0x54);i.append(0x91);i.append(0x03);i.append(0x64);i.append(0xfd);i.append(0x04);i.append(0x2e);i.append(0x34);i.append(0x3f);i.append(0xaa);i.append(0x23);i.append(0x6c);i.append(0xc8);i.append(0x0a);i.append(0x8a);i.append(0x91);i.append(0xd0);i.append(0x57);i.append(0x11);i.append(0x58);i.append(0x30);i.append(0x6c);i.append(0x2c);i.append(0x60);i.append(0xac);i.append(0xc9);i.append(0x98);i.append(0x30);i.append(0x44);i.append(0x6f);i.append(0xbb);i.append(0x0d);i.append(0x17);i.append(0xee);i.append(0x33);i.append(0x9b);i.append(0x7b);i.append(0xa8);i.append(0x6f);i.append(0xb4);i.append(0x54);i.append(0x07);i.append(0xd2);i.append(0x04);i.append(0x0e);i.append(0xaa);i.append(0xe7);i.append(0xeb);i.append(0x1c);i.append(0x65);i.append(0x46);i.append(0x8d);i.append(0xe5);i.append(0x0b);i.append(0x7c);i.append(0x9d);i.append(0xf1);i.append(0xda);i.append(0x89);i.append(0x8e);i.append(0xe6);i.append(0x15);i.append(0x79);i.append(0x2c);i.append(0x22);i.append(0x3b);i.append(0xf4);i.append(0x0f);i.append(0xa4);i.append(0x76);i.append(0xab);i.append(0xd5);i.append(0x72);i.append(0xfe);i.append(0xb8);i.append(0xe6);i.append(0x9d);i.append(0x1c);i.append(0x6a);i.append(0xd5);i.append(0xb9);i.append(0xf7);i.append(0xb6);i.append(0x7e);i.append(0x7d);i.append(0xa6);i.append(0xba);i.append(0xcd);i.append(0x7d);i.append(0x00);i.append(0x0b);i.append(0x4f);i.append(0x6e);i.append(0xf4);i.append(0x44);i.append(0xf6);i.append(0xa0);i.append(0x4a);i.append(0x62);i.append(0xc3);i.append(0x61);i.append(0x9b);i.append(0x70);i.append(0x2b);i.append(0x12);i.append(0x47);i.append(0xdc);i.append(0x35);i.append(0xfc);i.append(0xe6);i.append(0x6a);i.append(0x26);i.append(0xb8);i.append(0x71);i.append(0x25);i.append(0x01);i.append(0xf8);i.append(0xa5);i.append(0xf1);i.append(0x20);i.append(0x97);i.append(0x80);i.append(0x20);i.append(0xbd);i.append(0x4c);i.append(0xef);i.append(0xd0);i.append(0xb3);i.append(0xc6);i.append(0xda);i.append(0xa8);i.append(0xf8);i.append(0xa2);i.append(0x01);i.append(0x1d);i.append(0x25);i.append(0x5e);i.append(0xd2);i.append(0xb4);i.append(0xb8);i.append(0x8b);i.append(0xb8);i.append(0x6a);i.append(0x29);i.append(0xad);i.append(0x5b);i.append(0x93);i.append(0x40);i.append(0xc3);i.append(0x95);i.append(0x42);i.append(0x5d);i.append(0x2c);i.append(0x73);i.append(0xd7);i.append(0x9f);i.append(0x67);i.append(0xe4);i.append(0x0a);i.append(0x1e);i.append(0xca);i.append(0x3e);i.append(0x16);i.append(0xc5);i.append(0x1d);i.append(0x53);i.append(0x4a);i.append(0x42);i.append(0x41);i.append(0xd3);i.append(0x72);i.append(0x3c);i.append(0xca);i.append(0x00);i.append(0x1a);i.append(0x21);i.append(0x87);i.append(0x67);i.append(0xa0);i.append(0xa8);i.append(0xc1);i.append(0x05);i.append(0xc4);i.append(0x4a);i.append(0x59);i.append(0xa9);i.append(0xd2);i.append(0x50);i.append(0x76);i.append(0x72);i.append(0xb7);i.append(0xb9);i.append(0x4a);i.append(0x5b);i.append(0x51);i.append(0x3a);i.append(0x5b);i.append(0xa6);i.append(0x55);i.append(0x75);i.append(0x28);i.append(0x80);i.append(0x04);i.append(0x95);i.append(0xda);i.append(0x9c);i.append(0x35);i.append(0x5d);i.append(0x2c);i.append(0x15);i.append(0x25);i.append(0x2e);i.append(0xe2);i.append(0xb6);i.append(0x87);i.append(0xc4);i.append(0xd5);i.append(0x2f);i.append(0x61);i.append(0x66);i.append(0xbe);i.append(0x65);i.append(0x2c);i.append(0x90);i.append(0xc9);i.append(0x93);i.append(0x48);i.append(0x33);i.append(0xf5);i.append(0x2e);i.append(0x92);i.append(0xf8);i.append(0xdc);i.append(0x22);i.append(0x7d);i.append(0xa4);i.append(0xd9);i.append(0xa0);i.append(0x52);i.append(0x91);i.append(0x35);i.append(0x3c);i.append(0xaa);i.append(0x25);i.append(0x7d);i.append(0x52);i.append(0x28);i.append(0x20);i.append(0xc5);i.append(0xd1);i.append(0x4c);i.append(0xc7);i.append(0x45);i.append(0xa8);i.append(0x03);i.append(0x77);i.append(0xab);i.append(0xdb);i.append(0xb4);i.append(0x44);i.append(0xfd);i.append(0x9a);i.append(0x62);i.append(0xe1);i.append(0x28);i.append(0x3e);i.append(0xb6);i.append(0x84);i.append(0xc7);i.append(0x1a);i.append(0x98);i.append(0x2a);i.append(0xfa);i.append(0x72);i.append(0xed);i.append(0x32);i.append(0x76);i.append(0x43);i.append(0xf3);i.append(0x67);i.append(0x20);i.append(0x15);i.append(0xaa);i.append(0x0f);i.append(0xbf);i.append(0xfa);i.append(0xe7);i.append(0xf8);i.append(0xb3);i.append(0x14);i.append(0x27);i.append(0xb6);i.append(0x58);i.append(0xe6);i.append(0x36);i.append(0xb3);i.append(0xdc);i.append(0xe9);i.append(0xa6);i.append(0x51);i.append(0xa7);i.append(0x30);i.append(0xee);i.append(0xf6);i.append(0x95);i.append(0x59);i.append(0x3a);i.append(0x14);i.append(0xe2);i.append(0xf3);i.append(0x38);i.append(0xa7);i.append(0x45);i.append(0x70);i.append(0x53);i.append(0x91);i.append(0x3a);i.append(0x0e);i.append(0xc5);i.append(0x9f);i.append(0xb8);i.append(0x68);i.append(0x27);i.append(0xb9);i.append(0x3b);i.append(0x79);i.append(0x44);i.append(0xc5);i.append(0x73);i.append(0x32);i.append(0x47);i.append(0x3c);i.append(0xf3);i.append(0x77);i.append(0x3d);i.append(0x22);i.append(0x2c);i.append(0x61);i.append(0x34);i.append(0x7c);i.append(0x78);i.append(0xf2);i.append(0x26);i.append(0x8c);i.append(0x94);i.append(0x85);i.append(0x29);i.append(0x32);i.append(0x50);i.append(0xe2);i.append(0xaf);i.append(0x08);i.append(0xbb);i.append(0x35);i.append(0x37);i.append(0xd5);i.append(0xbc);i.append(0x62);i.append(0x0c);i.append(0x74);i.append(0xc1);i.append(0x35);i.append(0x86);i.append(0x2e);i.append(0x55);i.append(0xeb);i.append(0xa3);i.append(0xa5);i.append(0x2a);i.append(0x52);i.append(0x30);i.append(0x14);i.append(0x45);i.append(0xa1);i.append(0xee);i.append(0x28);i.append(0xa2);i.append(0xd5);i.append(0xac);i.append(0x12);i.append(0x19);i.append(0xa0);i.append(0x0b);i.append(0xc9);i.append(0x0a);i.append(0x43);i.append(0x77);i.append(0xe8);i.append(0xcf);i.append(0xa3);i.append(0x23);i.append(0x20);i.append(0xf8);i.append(0x4f);i.append(0x04);i.append(0x6a);i.append(0x6d);i.append(0x83);i.append(0xba);
    i
}

// 0xac4b38b0dd9d7562b44102f26ef2292d076a533cbed89f531f6a63f939fdb475
fn mmr_root_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xac);i.append(0x4b);i.append(0x38);i.append(0xb0);i.append(0xdd);i.append(0x9d);i.append(0x75);i.append(0x62);i.append(0xb4);i.append(0x41);i.append(0x02);i.append(0xf2);i.append(0x6e);i.append(0xf2);i.append(0x29);i.append(0x2d);i.append(0x07);i.append(0x6a);i.append(0x53);i.append(0x3c);i.append(0xbe);i.append(0xd8);i.append(0x9f);i.append(0x53);i.append(0x1f);i.append(0x6a);i.append(0x63);i.append(0xf9);i.append(0x39);i.append(0xfd);i.append(0xb4);i.append(0x75);
    i
}

#[test]
#[available_gas(20000000000)]
fn binary_merkle_tree_test(){
    let (leaves, leaves_lengths) = get_merkle_leaves_1(); 
    let leaves_hashes = get_hashes_from_items(leaves.span(), leaves_lengths.span());
    let merkle_root = match leaves_hashes{
                    Result::Ok(leaves_hashes)=>{merkelize_for_merkle_root(leaves_hashes.span())},
                    Result::Err(e)=>{e.print();
                assert(false, 'Hashing failed');
                0_u256 // dummy return
                },
                };
    assert(merkle_root == *hashes_to_u256s(get_expected_merkle_root_1().span()).unwrap().at(0), 'Merkle root mismatch');

    let (leaf_index, leaf) = get_leaf_data_1_1();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_1_1().span()).unwrap().span(), get_number_of_leaves_1(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');

    let (leaf_index, leaf) = get_leaf_data_1_2();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_1_2().span()).unwrap().span(), get_number_of_leaves_1(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');

    let (leaf_index, leaf) = get_leaf_data_1_3();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_1_3().span()).unwrap().span(), get_number_of_leaves_1(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');
}

// ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j","k"]
fn get_merkle_leaves_1() -> (Array<u8>, Array<usize>) {

    let mut l: Array<usize> = Default::default();
    l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);l.append(1);

    let mut i: Array<u8> = Default::default();
    i.append('a');i.append('b');i.append('c');i.append('d');i.append('e');i.append('f');i.append('g');i.append('h');i.append('i');i.append('j');i.append('k');

    (i, l)
}

// 0x2921423f37513bc6bb5d8630430e3511ebbc1283abe2792a23195a4d9b0e2291,
fn get_expected_merkle_root_1() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x29);i.append(0x21);i.append(0x42);i.append(0x3f);i.append(0x37);i.append(0x51);i.append(0x3b);i.append(0xc6);i.append(0xbb);i.append(0x5d);i.append(0x86);i.append(0x30);i.append(0x43);i.append(0x0e);i.append(0x35);i.append(0x11);i.append(0xeb);i.append(0xbc);i.append(0x12);i.append(0x83);i.append(0xab);i.append(0xe2);i.append(0x79);i.append(0x2a);i.append(0x23);i.append(0x19);i.append(0x5a);i.append(0x4d);i.append(0x9b);i.append(0x0e);i.append(0x22);i.append(0x91);
    i
}


// ["00f1ab17c0a22cac8888dcacf2506f283715df19c6155fecd32865fa76fe0b4c", "cd07272f4955ddcfdac38ff36dff9d3e4353498923679ab548ba87e34648e4a3"]
fn get_merkle_proof_1_1() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x00);i.append(0xf1);i.append(0xab);i.append(0x17);i.append(0xc0);i.append(0xa2);i.append(0x2c);i.append(0xac);i.append(0x88);i.append(0x88);i.append(0xdc);i.append(0xac);i.append(0xf2);i.append(0x50);i.append(0x6f);i.append(0x28);i.append(0x37);i.append(0x15);i.append(0xdf);i.append(0x19);i.append(0xc6);i.append(0x15);i.append(0x5f);i.append(0xec);i.append(0xd3);i.append(0x28);i.append(0x65);i.append(0xfa);i.append(0x76);i.append(0xfe);i.append(0x0b);i.append(0x4c);i.append(0xcd);i.append(0x07);i.append(0x27);i.append(0x2f);i.append(0x49);i.append(0x55);i.append(0xdd);i.append(0xcf);i.append(0xda);i.append(0xc3);i.append(0x8f);i.append(0xf3);i.append(0x6d);i.append(0xff);i.append(0x9d);i.append(0x3e);i.append(0x43);i.append(0x53);i.append(0x49);i.append(0x89);i.append(0x23);i.append(0x67);i.append(0x9a);i.append(0xb5);i.append(0x48);i.append(0xba);i.append(0x87);i.append(0xe3);i.append(0x46);i.append(0x48);i.append(0xe4);i.append(0xa3);
    i
}

fn get_number_of_leaves_1() -> usize {
    11
}

fn get_leaf_data_1_1() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append('k');
    (10, i)
}

// ["a766932420cc6e9072394bef2c036ad8972c44696fee29397bd5e2c06001f615", "f0b49bb4b0d9396e0315755ceafaa280707b32e75e6c9053f5cdf2679dcd5c6a", "68203f90e9d07dc5859259d7536e87a6ba9d345f2552b5b9de2999ddce9ce1bf", "57c67b74c8b10f8e13b84735c3de55c9a27ca84d613a6501601c13163b88783a"]
fn get_merkle_proof_1_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xa7);i.append(0x66);i.append(0x93);i.append(0x24);i.append(0x20);i.append(0xcc);i.append(0x6e);i.append(0x90);i.append(0x72);i.append(0x39);i.append(0x4b);i.append(0xef);i.append(0x2c);i.append(0x03);i.append(0x6a);i.append(0xd8);i.append(0x97);i.append(0x2c);i.append(0x44);i.append(0x69);i.append(0x6f);i.append(0xee);i.append(0x29);i.append(0x39);i.append(0x7b);i.append(0xd5);i.append(0xe2);i.append(0xc0);i.append(0x60);i.append(0x01);i.append(0xf6);i.append(0x15);i.append(0xf0);i.append(0xb4);i.append(0x9b);i.append(0xb4);i.append(0xb0);i.append(0xd9);i.append(0x39);i.append(0x6e);i.append(0x03);i.append(0x15);i.append(0x75);i.append(0x5c);i.append(0xea);i.append(0xfa);i.append(0xa2);i.append(0x80);i.append(0x70);i.append(0x7b);i.append(0x32);i.append(0xe7);i.append(0x5e);i.append(0x6c);i.append(0x90);i.append(0x53);i.append(0xf5);i.append(0xcd);i.append(0xf2);i.append(0x67);i.append(0x9d);i.append(0xcd);i.append(0x5c);i.append(0x6a);i.append(0x68);i.append(0x20);i.append(0x3f);i.append(0x90);i.append(0xe9);i.append(0xd0);i.append(0x7d);i.append(0xc5);i.append(0x85);i.append(0x92);i.append(0x59);i.append(0xd7);i.append(0x53);i.append(0x6e);i.append(0x87);i.append(0xa6);i.append(0xba);i.append(0x9d);i.append(0x34);i.append(0x5f);i.append(0x25);i.append(0x52);i.append(0xb5);i.append(0xb9);i.append(0xde);i.append(0x29);i.append(0x99);i.append(0xdd);i.append(0xce);i.append(0x9c);i.append(0xe1);i.append(0xbf);i.append(0x57);i.append(0xc6);i.append(0x7b);i.append(0x74);i.append(0xc8);i.append(0xb1);i.append(0x0f);i.append(0x8e);i.append(0x13);i.append(0xb8);i.append(0x47);i.append(0x35);i.append(0xc3);i.append(0xde);i.append(0x55);i.append(0xc9);i.append(0xa2);i.append(0x7c);i.append(0xa8);i.append(0x4d);i.append(0x61);i.append(0x3a);i.append(0x65);i.append(0x01);i.append(0x60);i.append(0x1c);i.append(0x13);i.append(0x16);i.append(0x3b);i.append(0x88);i.append(0x78);i.append(0x3a);
    i
}

fn get_leaf_data_1_2() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append('g');
    (6, i)
}

// ["ea00237ef11bd9615a3b6d2629f2c6259d67b19bb94947a1bd739bae3415141c", "f3d0adcb6a1c70832365e9da0a6b2f5199422f6a53c67cfad171114e3442aa0f", "cd07272f4955ddcfdac38ff36dff9d3e4353498923679ab548ba87e34648e4a3"]
fn get_merkle_proof_1_3() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xea);i.append(0x00);i.append(0x23);i.append(0x7e);i.append(0xf1);i.append(0x1b);i.append(0xd9);i.append(0x61);i.append(0x5a);i.append(0x3b);i.append(0x6d);i.append(0x26);i.append(0x29);i.append(0xf2);i.append(0xc6);i.append(0x25);i.append(0x9d);i.append(0x67);i.append(0xb1);i.append(0x9b);i.append(0xb9);i.append(0x49);i.append(0x47);i.append(0xa1);i.append(0xbd);i.append(0x73);i.append(0x9b);i.append(0xae);i.append(0x34);i.append(0x15);i.append(0x14);i.append(0x1c);i.append(0xf3);i.append(0xd0);i.append(0xad);i.append(0xcb);i.append(0x6a);i.append(0x1c);i.append(0x70);i.append(0x83);i.append(0x23);i.append(0x65);i.append(0xe9);i.append(0xda);i.append(0x0a);i.append(0x6b);i.append(0x2f);i.append(0x51);i.append(0x99);i.append(0x42);i.append(0x2f);i.append(0x6a);i.append(0x53);i.append(0xc6);i.append(0x7c);i.append(0xfa);i.append(0xd1);i.append(0x71);i.append(0x11);i.append(0x4e);i.append(0x34);i.append(0x42);i.append(0xaa);i.append(0x0f);i.append(0xcd);i.append(0x07);i.append(0x27);i.append(0x2f);i.append(0x49);i.append(0x55);i.append(0xdd);i.append(0xcf);i.append(0xda);i.append(0xc3);i.append(0x8f);i.append(0xf3);i.append(0x6d);i.append(0xff);i.append(0x9d);i.append(0x3e);i.append(0x43);i.append(0x53);i.append(0x49);i.append(0x89);i.append(0x23);i.append(0x67);i.append(0x9a);i.append(0xb5);i.append(0x48);i.append(0xba);i.append(0x87);i.append(0xe3);i.append(0x46);i.append(0x48);i.append(0xe4);i.append(0xa3);
    i
}

fn get_leaf_data_1_3() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append('j');
    (9, i)
}

#[test]
#[available_gas(20000000000)]
fn binary_merkle_tree_test_2(){
    let (leaves, leaves_lengths) = get_merkle_leaves_2(); 
    let leaves_hashes = get_hashes_from_items(leaves.span(), leaves_lengths.span());
    let merkle_root = match leaves_hashes{
                    Result::Ok(leaves_hashes)=>{merkelize_for_merkle_root(leaves_hashes.span())},
                    Result::Err(e)=>{e.print();
                assert(false, 'Hashing failed');
                0_u256 // dummy return
                },
                };
    assert(merkle_root == *hashes_to_u256s(get_expected_merkle_root_2().span()).unwrap().at(0), 'Merkle root mismatch');

    let (leaf_index, leaf) = get_leaf_data_2_1();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_2_1().span()).unwrap().span(), get_number_of_leaves_2(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');

    let (leaf_index, leaf) = get_leaf_data_2_2();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_2_2().span()).unwrap().span(), get_number_of_leaves_2(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');

    let (leaf_index, leaf) = get_leaf_data_2_3();
    let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
    let res = verify_merkle_proof(merkle_root, hashes_to_u256s(get_merkle_proof_2_3().span()).unwrap().span(), get_number_of_leaves_2(), leaf_index, leaf_hash);
    assert(res, 'merkle proof ver failed');
}

// "0x9aF1Ca5941148eB6A3e9b9C741b69738292C533f",
// "0xDD6ca953fddA25c496165D9040F7F77f75B75002",
// "0x60e9C47B64Bc1C7C906E891255EaEC19123E7F42",
// "0xfa4859480Aa6D899858DE54334d2911E01C070df",
// "0x19B9b128470584F7209eEf65B69F3624549Abe6d",
// "0xC436aC1f261802C4494504A11fc2926C726cB83b",
// "0xc304C8C2c12522F78aD1E28dD86b9947D7744bd0",
// "0xDa0C2Cba6e832E55dE89cF4033affc90CC147352",
// "0xf850Fd22c96e3501Aad4CDCBf38E4AEC95622411",
// "0x684918D4387CEb5E7eda969042f036E226E50642",
// "0x963F0A1bFbb6813C0AC88FcDe6ceB96EA634A595",
// "0x39B38ad74b8bCc5CE564f7a27Ac19037A95B6099",
// "0xC2Dec7Fdd1fef3ee95aD88EC8F3Cd5bd4065f3C7",
// "0x9E311f05c2b6A43C2CCF16fB2209491BaBc2ec01",
// "0x927607C30eCE4Ef274e250d0bf414d4a210b16f0",
// "0x98882bcf85E1E2DFF780D0eB360678C1cf443266",
// "0xFBb50191cd0662049E7C4EE32830a4Cc9B353047",
// "0x963854fc2C358c48C3F9F0A598B9572c581B8DEF",
// "0xF9D7Bc222cF6e3e07bF66711e6f409E51aB75292",
// "0xF2E3fd32D063F8bBAcB9e6Ea8101C2edd899AFe6",
// "0x407a5b9047B76E8668570120A96d580589fd1325",
// "0xEAD9726FAFB900A07dAd24a43AE941d2eFDD6E97",
fn get_merkle_leaves_2() -> (Array<u8>, Array<usize>) {

    let mut l: Array<usize> = Default::default();
    let mut itr: usize =0;
    loop{
        if itr==22{break;}
        l.append(20);
        itr=itr+1;
    };

    let mut i: Array<u8> = Default::default();
            i.append(0x9a);i.append(0xF1);i.append(0xCa);i.append(0x59);i.append(0x41);i.append(0x14);i.append(0x8e);i.append(0xB6);i.append(0xA3);i.append(0xe9);i.append(0xb9);i.append(0xC7);i.append(0x41);i.append(0xb6);i.append(0x97);i.append(0x38);i.append(0x29);i.append(0x2C);i.append(0x53);i.append(0x3f);
			i.append(0xDD);i.append(0x6c);i.append(0xa9);i.append(0x53);i.append(0xfd);i.append(0xdA);i.append(0x25);i.append(0xc4);i.append(0x96);i.append(0x16);i.append(0x5D);i.append(0x90);i.append(0x40);i.append(0xF7);i.append(0xF7);i.append(0x7f);i.append(0x75);i.append(0xB7);i.append(0x50);i.append(0x02);
			i.append(0x60);i.append(0xe9);i.append(0xC4);i.append(0x7B);i.append(0x64);i.append(0xBc);i.append(0x1C);i.append(0x7C);i.append(0x90);i.append(0x6E);i.append(0x89);i.append(0x12);i.append(0x55);i.append(0xEa);i.append(0xEC);i.append(0x19);i.append(0x12);i.append(0x3E);i.append(0x7F);i.append(0x42);
			i.append(0xfa);i.append(0x48);i.append(0x59);i.append(0x48);i.append(0x0A);i.append(0xa6);i.append(0xD8);i.append(0x99);i.append(0x85);i.append(0x8D);i.append(0xE5);i.append(0x43);i.append(0x34);i.append(0xd2);i.append(0x91);i.append(0x1E);i.append(0x01);i.append(0xC0);i.append(0x70);i.append(0xdf);
			i.append(0x19);i.append(0xB9);i.append(0xb1);i.append(0x28);i.append(0x47);i.append(0x05);i.append(0x84);i.append(0xF7);i.append(0x20);i.append(0x9e);i.append(0xEf);i.append(0x65);i.append(0xB6);i.append(0x9F);i.append(0x36);i.append(0x24);i.append(0x54);i.append(0x9A);i.append(0xbe);i.append(0x6d);
			i.append(0xC4);i.append(0x36);i.append(0xaC);i.append(0x1f);i.append(0x26);i.append(0x18);i.append(0x02);i.append(0xC4);i.append(0x49);i.append(0x45);i.append(0x04);i.append(0xA1);i.append(0x1f);i.append(0xc2);i.append(0x92);i.append(0x6C);i.append(0x72);i.append(0x6c);i.append(0xB8);i.append(0x3b);
			i.append(0xc3);i.append(0x04);i.append(0xC8);i.append(0xC2);i.append(0xc1);i.append(0x25);i.append(0x22);i.append(0xF7);i.append(0x8a);i.append(0xD1);i.append(0xE2);i.append(0x8d);i.append(0xD8);i.append(0x6b);i.append(0x99);i.append(0x47);i.append(0xD7);i.append(0x74);i.append(0x4b);i.append(0xd0);
			i.append(0xDa);i.append(0x0C);i.append(0x2C);i.append(0xba);i.append(0x6e);i.append(0x83);i.append(0x2E);i.append(0x55);i.append(0xdE);i.append(0x89);i.append(0xcF);i.append(0x40);i.append(0x33);i.append(0xaf);i.append(0xfc);i.append(0x90);i.append(0xCC);i.append(0x14);i.append(0x73);i.append(0x52);
			i.append(0xf8);i.append(0x50);i.append(0xFd);i.append(0x22);i.append(0xc9);i.append(0x6e);i.append(0x35);i.append(0x01);i.append(0xAa);i.append(0xd4);i.append(0xCD);i.append(0xCB);i.append(0xf3);i.append(0x8E);i.append(0x4A);i.append(0xEC);i.append(0x95);i.append(0x62);i.append(0x24);i.append(0x11);
			i.append(0x68);i.append(0x49);i.append(0x18);i.append(0xD4);i.append(0x38);i.append(0x7C);i.append(0xEb);i.append(0x5E);i.append(0x7e);i.append(0xda);i.append(0x96);i.append(0x90);i.append(0x42);i.append(0xf0);i.append(0x36);i.append(0xE2);i.append(0x26);i.append(0xE5);i.append(0x06);i.append(0x42);
			i.append(0x96);i.append(0x3F);i.append(0x0A);i.append(0x1b);i.append(0xFb);i.append(0xb6);i.append(0x81);i.append(0x3C);i.append(0x0A);i.append(0xC8);i.append(0x8F);i.append(0xcD);i.append(0xe6);i.append(0xce);i.append(0xB9);i.append(0x6E);i.append(0xA6);i.append(0x34);i.append(0xA5);i.append(0x95);
			i.append(0x39);i.append(0xB3);i.append(0x8a);i.append(0xd7);i.append(0x4b);i.append(0x8b);i.append(0xCc);i.append(0x5C);i.append(0xE5);i.append(0x64);i.append(0xf7);i.append(0xa2);i.append(0x7A);i.append(0xc1);i.append(0x90);i.append(0x37);i.append(0xA9);i.append(0x5B);i.append(0x60);i.append(0x99);
			i.append(0xC2);i.append(0xDe);i.append(0xc7);i.append(0xFd);i.append(0xd1);i.append(0xfe);i.append(0xf3);i.append(0xee);i.append(0x95);i.append(0xaD);i.append(0x88);i.append(0xEC);i.append(0x8F);i.append(0x3C);i.append(0xd5);i.append(0xbd);i.append(0x40);i.append(0x65);i.append(0xf3);i.append(0xC7);
			i.append(0x9E);i.append(0x31);i.append(0x1f);i.append(0x05);i.append(0xc2);i.append(0xb6);i.append(0xA4);i.append(0x3C);i.append(0x2C);i.append(0xCF);i.append(0x16);i.append(0xfB);i.append(0x22);i.append(0x09);i.append(0x49);i.append(0x1B);i.append(0xaB);i.append(0xc2);i.append(0xec);i.append(0x01);
			i.append(0x92);i.append(0x76);i.append(0x07);i.append(0xC3);i.append(0x0e);i.append(0xCE);i.append(0x4E);i.append(0xf2);i.append(0x74);i.append(0xe2);i.append(0x50);i.append(0xd0);i.append(0xbf);i.append(0x41);i.append(0x4d);i.append(0x4a);i.append(0x21);i.append(0x0b);i.append(0x16);i.append(0xf0);
			i.append(0x98);i.append(0x88);i.append(0x2b);i.append(0xcf);i.append(0x85);i.append(0xE1);i.append(0xE2);i.append(0xDF);i.append(0xF7);i.append(0x80);i.append(0xD0);i.append(0xeB);i.append(0x36);i.append(0x06);i.append(0x78);i.append(0xC1);i.append(0xcf);i.append(0x44);i.append(0x32);i.append(0x66);
			i.append(0xFB);i.append(0xb5);i.append(0x01);i.append(0x91);i.append(0xcd);i.append(0x06);i.append(0x62);i.append(0x04);i.append(0x9E);i.append(0x7C);i.append(0x4E);i.append(0xE3);i.append(0x28);i.append(0x30);i.append(0xa4);i.append(0xCc);i.append(0x9B);i.append(0x35);i.append(0x30);i.append(0x47);
			i.append(0x96);i.append(0x38);i.append(0x54);i.append(0xfc);i.append(0x2C);i.append(0x35);i.append(0x8c);i.append(0x48);i.append(0xC3);i.append(0xF9);i.append(0xF0);i.append(0xA5);i.append(0x98);i.append(0xB9);i.append(0x57);i.append(0x2c);i.append(0x58);i.append(0x1B);i.append(0x8D);i.append(0xEF);
			i.append(0xF9);i.append(0xD7);i.append(0xBc);i.append(0x22);i.append(0x2c);i.append(0xF6);i.append(0xe3);i.append(0xe0);i.append(0x7b);i.append(0xF6);i.append(0x67);i.append(0x11);i.append(0xe6);i.append(0xf4);i.append(0x09);i.append(0xE5);i.append(0x1a);i.append(0xB7);i.append(0x52);i.append(0x92);
			i.append(0xF2);i.append(0xE3);i.append(0xfd);i.append(0x32);i.append(0xD0);i.append(0x63);i.append(0xF8);i.append(0xbB);i.append(0xAc);i.append(0xB9);i.append(0xe6);i.append(0xEa);i.append(0x81);i.append(0x01);i.append(0xC2);i.append(0xed);i.append(0xd8);i.append(0x99);i.append(0xAF);i.append(0xe6);
			i.append(0x40);i.append(0x7a);i.append(0x5b);i.append(0x90);i.append(0x47);i.append(0xB7);i.append(0x6E);i.append(0x86);i.append(0x68);i.append(0x57);i.append(0x01);i.append(0x20);i.append(0xA9);i.append(0x6d);i.append(0x58);i.append(0x05);i.append(0x89);i.append(0xfd);i.append(0x13);i.append(0x25);
			i.append(0xEA);i.append(0xD9);i.append(0x72);i.append(0x6F);i.append(0xAF);i.append(0xB9);i.append(0x00);i.append(0xA0);i.append(0x7d);i.append(0xAd);i.append(0x24);i.append(0xa4);i.append(0x3A);i.append(0xE9);i.append(0x41);i.append(0xd2);i.append(0xeF);i.append(0xDD);i.append(0x6E);i.append(0x97);
			
    (i, l)
}

// 0x1d815257ae6a560d93f3820fa65d0fd77aebb77220f45837605bc7f48a6e3ef9,,
fn get_expected_merkle_root_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x1d);i.append(0x81);i.append(0x52);i.append(0x57);i.append(0xae);i.append(0x6a);i.append(0x56);i.append(0x0d);i.append(0x93);i.append(0xf3);i.append(0x82);i.append(0x0f);i.append(0xa6);i.append(0x5d);i.append(0x0f);i.append(0xd7);i.append(0x7a);i.append(0xeb);i.append(0xb7);i.append(0x72);i.append(0x20);i.append(0xf4);i.append(0x58);i.append(0x37);i.append(0x60);i.append(0x5b);i.append(0xc7);i.append(0xf4);i.append(0x8a);i.append(0x6e);i.append(0x3e);i.append(0xf9);
    i
}


// ["3ac05b0ccfde7f55ab70cab0f51be5fadfccbb6932ebb44a9c75e956be04778d", "c61b19f58326bdcff9322bcdcffacefacc67e3a3a5264f6106bd5970fa349f3d", "62f3ed9d0b006fae872c2fe620202be7e16b741232c9b7641a134915a79fa64e", "89dc78c3c641d0bb2eb1b6d6c11f07eac8d48e7c816f82c3c5214227fc2c2de6", "13508560eda7c52399e532275deab0dcff0111f92044b74d3e4a7d956f427a52"]
fn get_merkle_proof_2_1() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x3a);i.append(0xc0);i.append(0x5b);i.append(0x0c);i.append(0xcf);i.append(0xde);i.append(0x7f);i.append(0x55);i.append(0xab);i.append(0x70);i.append(0xca);i.append(0xb0);i.append(0xf5);i.append(0x1b);i.append(0xe5);i.append(0xfa);i.append(0xdf);i.append(0xcc);i.append(0xbb);i.append(0x69);i.append(0x32);i.append(0xeb);i.append(0xb4);i.append(0x4a);i.append(0x9c);i.append(0x75);i.append(0xe9);i.append(0x56);i.append(0xbe);i.append(0x04);i.append(0x77);i.append(0x8d);i.append(0xc6);i.append(0x1b);i.append(0x19);i.append(0xf5);i.append(0x83);i.append(0x26);i.append(0xbd);i.append(0xcf);i.append(0xf9);i.append(0x32);i.append(0x2b);i.append(0xcd);i.append(0xcf);i.append(0xfa);i.append(0xce);i.append(0xfa);i.append(0xcc);i.append(0x67);i.append(0xe3);i.append(0xa3);i.append(0xa5);i.append(0x26);i.append(0x4f);i.append(0x61);i.append(0x06);i.append(0xbd);i.append(0x59);i.append(0x70);i.append(0xfa);i.append(0x34);i.append(0x9f);i.append(0x3d);i.append(0x62);i.append(0xf3);i.append(0xed);i.append(0x9d);i.append(0x0b);i.append(0x00);i.append(0x6f);i.append(0xae);i.append(0x87);i.append(0x2c);i.append(0x2f);i.append(0xe6);i.append(0x20);i.append(0x20);i.append(0x2b);i.append(0xe7);i.append(0xe1);i.append(0x6b);i.append(0x74);i.append(0x12);i.append(0x32);i.append(0xc9);i.append(0xb7);i.append(0x64);i.append(0x1a);i.append(0x13);i.append(0x49);i.append(0x15);i.append(0xa7);i.append(0x9f);i.append(0xa6);i.append(0x4e);i.append(0x89);i.append(0xdc);i.append(0x78);i.append(0xc3);i.append(0xc6);i.append(0x41);i.append(0xd0);i.append(0xbb);i.append(0x2e);i.append(0xb1);i.append(0xb6);i.append(0xd6);i.append(0xc1);i.append(0x1f);i.append(0x07);i.append(0xea);i.append(0xc8);i.append(0xd4);i.append(0x8e);i.append(0x7c);i.append(0x81);i.append(0x6f);i.append(0x82);i.append(0xc3);i.append(0xc5);i.append(0x21);i.append(0x42);i.append(0x27);i.append(0xfc);i.append(0x2c);i.append(0x2d);i.append(0xe6);i.append(0x13);i.append(0x50);i.append(0x85);i.append(0x60);i.append(0xed);i.append(0xa7);i.append(0xc5);i.append(0x23);i.append(0x99);i.append(0xe5);i.append(0x32);i.append(0x27);i.append(0x5d);i.append(0xea);i.append(0xb0);i.append(0xdc);i.append(0xff);i.append(0x01);i.append(0x11);i.append(0xf9);i.append(0x20);i.append(0x44);i.append(0xb7);i.append(0x4d);i.append(0x3e);i.append(0x4a);i.append(0x7d);i.append(0x95);i.append(0x6f);i.append(0x42);i.append(0x7a);i.append(0x52);
    i
}

fn get_number_of_leaves_2() -> usize {
    22
}

fn get_leaf_data_2_1() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append(0x39);i.append(0xB3);i.append(0x8a);i.append(0xd7);i.append(0x4b);i.append(0x8b);i.append(0xCc);i.append(0x5C);i.append(0xE5);i.append(0x64);i.append(0xf7);i.append(0xa2);i.append(0x7A);i.append(0xc1);i.append(0x90);i.append(0x37);i.append(0xA9);i.append(0x5B);i.append(0x60);i.append(0x99);
    (11, i)
}

// ["7af146e5230a48c56040d55f5d29917ed4196c3eb99bfa7244ed7b21dd35b2c2", "f79a89c44c33059ed431f93a439dfcda5e10e002d0052d2f6fa49cdba698b0be", "78c059e20132dfeaf26388820ff1af60cec06cfb54e91b616e8883eb3ca4342f"]
fn get_merkle_proof_2_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x7a);i.append(0xf1);i.append(0x46);i.append(0xe5);i.append(0x23);i.append(0x0a);i.append(0x48);i.append(0xc5);i.append(0x60);i.append(0x40);i.append(0xd5);i.append(0x5f);i.append(0x5d);i.append(0x29);i.append(0x91);i.append(0x7e);i.append(0xd4);i.append(0x19);i.append(0x6c);i.append(0x3e);i.append(0xb9);i.append(0x9b);i.append(0xfa);i.append(0x72);i.append(0x44);i.append(0xed);i.append(0x7b);i.append(0x21);i.append(0xdd);i.append(0x35);i.append(0xb2);i.append(0xc2);i.append(0xf7);i.append(0x9a);i.append(0x89);i.append(0xc4);i.append(0x4c);i.append(0x33);i.append(0x05);i.append(0x9e);i.append(0xd4);i.append(0x31);i.append(0xf9);i.append(0x3a);i.append(0x43);i.append(0x9d);i.append(0xfc);i.append(0xda);i.append(0x5e);i.append(0x10);i.append(0xe0);i.append(0x02);i.append(0xd0);i.append(0x05);i.append(0x2d);i.append(0x2f);i.append(0x6f);i.append(0xa4);i.append(0x9c);i.append(0xdb);i.append(0xa6);i.append(0x98);i.append(0xb0);i.append(0xbe);i.append(0x78);i.append(0xc0);i.append(0x59);i.append(0xe2);i.append(0x01);i.append(0x32);i.append(0xdf);i.append(0xea);i.append(0xf2);i.append(0x63);i.append(0x88);i.append(0x82);i.append(0x0f);i.append(0xf1);i.append(0xaf);i.append(0x60);i.append(0xce);i.append(0xc0);i.append(0x6c);i.append(0xfb);i.append(0x54);i.append(0xe9);i.append(0x1b);i.append(0x61);i.append(0x6e);i.append(0x88);i.append(0x83);i.append(0xeb);i.append(0x3c);i.append(0xa4);i.append(0x34);i.append(0x2f);
    i
}

fn get_leaf_data_2_2() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append(0xEA);i.append(0xD9);i.append(0x72);i.append(0x6F);i.append(0xAF);i.append(0xB9);i.append(0x00);i.append(0xA0);i.append(0x7d);i.append(0xAd);i.append(0x24);i.append(0xa4);i.append(0x3A);i.append(0xE9);i.append(0x41);i.append(0xd2);i.append(0xeF);i.append(0xDD);i.append(0x6E);i.append(0x97);
	(21, i)
}

// ["eabb03c592af442325d97bf94bd10f1054895a02b741086eab60b02037e67bd7", "171bd426be717039f08cfbe678973414f0a8568fc1b32288d087ba4352204df9", "c47b488bd85d4578790fb853ca85fabc4c46aa91e77112c1303e38b05a7c6d47", "a16b2347e31bf776eff90cff7e14b5b4b851fff730a644969edd9b53cfa6610a", "13508560eda7c52399e532275deab0dcff0111f92044b74d3e4a7d956f427a52"]
fn get_merkle_proof_2_3() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0xea);i.append(0xbb);i.append(0x03);i.append(0xc5);i.append(0x92);i.append(0xaf);i.append(0x44);i.append(0x23);i.append(0x25);i.append(0xd9);i.append(0x7b);i.append(0xf9);i.append(0x4b);i.append(0xd1);i.append(0x0f);i.append(0x10);i.append(0x54);i.append(0x89);i.append(0x5a);i.append(0x02);i.append(0xb7);i.append(0x41);i.append(0x08);i.append(0x6e);i.append(0xab);i.append(0x60);i.append(0xb0);i.append(0x20);i.append(0x37);i.append(0xe6);i.append(0x7b);i.append(0xd7);i.append(0x17);i.append(0x1b);i.append(0xd4);i.append(0x26);i.append(0xbe);i.append(0x71);i.append(0x70);i.append(0x39);i.append(0xf0);i.append(0x8c);i.append(0xfb);i.append(0xe6);i.append(0x78);i.append(0x97);i.append(0x34);i.append(0x14);i.append(0xf0);i.append(0xa8);i.append(0x56);i.append(0x8f);i.append(0xc1);i.append(0xb3);i.append(0x22);i.append(0x88);i.append(0xd0);i.append(0x87);i.append(0xba);i.append(0x43);i.append(0x52);i.append(0x20);i.append(0x4d);i.append(0xf9);i.append(0xc4);i.append(0x7b);i.append(0x48);i.append(0x8b);i.append(0xd8);i.append(0x5d);i.append(0x45);i.append(0x78);i.append(0x79);i.append(0x0f);i.append(0xb8);i.append(0x53);i.append(0xca);i.append(0x85);i.append(0xfa);i.append(0xbc);i.append(0x4c);i.append(0x46);i.append(0xaa);i.append(0x91);i.append(0xe7);i.append(0x71);i.append(0x12);i.append(0xc1);i.append(0x30);i.append(0x3e);i.append(0x38);i.append(0xb0);i.append(0x5a);i.append(0x7c);i.append(0x6d);i.append(0x47);i.append(0xa1);i.append(0x6b);i.append(0x23);i.append(0x47);i.append(0xe3);i.append(0x1b);i.append(0xf7);i.append(0x76);i.append(0xef);i.append(0xf9);i.append(0x0c);i.append(0xff);i.append(0x7e);i.append(0x14);i.append(0xb5);i.append(0xb4);i.append(0xb8);i.append(0x51);i.append(0xff);i.append(0xf7);i.append(0x30);i.append(0xa6);i.append(0x44);i.append(0x96);i.append(0x9e);i.append(0xdd);i.append(0x9b);i.append(0x53);i.append(0xcf);i.append(0xa6);i.append(0x61);i.append(0x0a);i.append(0x13);i.append(0x50);i.append(0x85);i.append(0x60);i.append(0xed);i.append(0xa7);i.append(0xc5);i.append(0x23);i.append(0x99);i.append(0xe5);i.append(0x32);i.append(0x27);i.append(0x5d);i.append(0xea);i.append(0xb0);i.append(0xdc);i.append(0xff);i.append(0x01);i.append(0x11);i.append(0xf9);i.append(0x20);i.append(0x44);i.append(0xb7);i.append(0x4d);i.append(0x3e);i.append(0x4a);i.append(0x7d);i.append(0x95);i.append(0x6f);i.append(0x42);i.append(0x7a);i.append(0x52);
    i
}

fn get_leaf_data_2_3() -> (usize, Array<u8>) {
    let mut i: Array<u8> = Default::default();
    i.append(0xfa);i.append(0x48);i.append(0x59);i.append(0x48);i.append(0x0A);i.append(0xa6);i.append(0xD8);i.append(0x99);i.append(0x85);i.append(0x8D);i.append(0xE5);i.append(0x43);i.append(0x34);i.append(0xd2);i.append(0x91);i.append(0x1E);i.append(0x01);i.append(0xC0);i.append(0x70);i.append(0xdf);
	(3, i)
}

// {
//   blockHash: 0x7a0dc39ae0a595b270a92b9d5e6152577da9db421733b17194171185c67816e2
//   leaves: 0x04c501000300000025211058d6728753fb8a1e69d8a8d52255c6d2edb20e4249329f3e7f069ac0f2010000000000000001000000aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d70000000000000000000000000000000000000000000000000000000000000000
//   proof: 0x04030000000000000006000000000000000c73c160021302c2be54cc56799ae9e8641d398e0280f130d40403eed791eb61e4ba58faa1397a113b79824d3b88b4937ac001b8ab33bb52ec74aee893a2c8e73f653974eb7fbf18818db682e2b53f9339806b98f124f48ad861cecdfff6c114e5
// }
// [MmrLeaf { version: MmrLeafVersion(0), parent_number_and_hash: (3, 0x25211058d6728753fb8a1e69d8a8d52255c6d2edb20e4249329f3e7f069ac0f2), beefy_next_authority_set: BeefyAuthoritySet { id: 1, len: 1, keyset_commitment: 0xaeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7 }, leaf_extra: 0x0000000000000000000000000000000000000000000000000000000000000000 }]
#[test]
#[available_gas(20000000000)]
fn encoded_opaque_leaves_to_leaves_test(){
    let leaves = encoded_opaque_leaves_to_leaves(get_encoded_opaque_leaves_1().span());
    match leaves {
		Result::Ok(leaves) => {
        let expected_leaves: Array<BeefyData> = get_expected_leaves_1();
        assert(leaves.len()==1, 'Wrong leaves len');
        assert(*leaves.at(0)==*expected_leaves.at(0), 'leaf 0 mismatch');

        },
		Result::Err(e) => {e.print(); assert(false, 'Decoding failed');}
	};
    
}

fn get_encoded_opaque_leaves_1() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x04);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x03);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x25);i.append(0x21);i.append(0x10);i.append(0x58);i.append(0xd6);i.append(0x72);i.append(0x87);i.append(0x53);i.append(0xfb);i.append(0x8a);i.append(0x1e);i.append(0x69);i.append(0xd8);i.append(0xa8);i.append(0xd5);i.append(0x22);i.append(0x55);i.append(0xc6);i.append(0xd2);i.append(0xed);i.append(0xb2);i.append(0x0e);i.append(0x42);i.append(0x49);i.append(0x32);i.append(0x9f);i.append(0x3e);i.append(0x7f);i.append(0x06);i.append(0x9a);i.append(0xc0);i.append(0xf2);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
    i
}

fn get_expected_leaves_1() -> Array<BeefyData> {
    let mut i: Array<BeefyData> = array![];
    let next_beefy_authority_set = BeefyAuthoritySet{
        id: 1,
        len: 1,
        keyset_commitment: u256{high: 0xaeb47a269393297f4b0a3c9c9cfd00c7, low:0xa4195255274cf39d83dabc2fcc9ff3d7}
    };
    let beefy_data = BeefyData{
        version: 0,
        block_number: 3,
        hash: u256{high: 0x25211058d6728753fb8a1e69d8a8d522, low:0x55c6d2edb20e4249329f3e7f069ac0f2},
        leaf_extra: u256{high: 0x00000000000000000000000000000000, low:0x00000000000000000000000000000000},
        beefy_next_authority_set: next_beefy_authority_set,
    };
    i.append(beefy_data);
    i
}


// {
//   blockHash: 0x03306c9397b723677339843cc9f6241235a3f563a148e1e61a85b855f02ab1fc
//   leaves: 0x0cc5010002000000ba66eb36773ac13806017817f9735db74f3ae0a8994af1bb1931c5709290a9f3010000000000000001000000aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d70000000000000000000000000000000000000000000000000000000000000000c501002e00000063cde375567f691a22a0bdd98c78f85274775e5bf391ec9e6ed41e61221b9a7f050000000000000001000000aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d70000000000000000000000000000000000000000000000000000000000000000c501007a000000cbd3a1098384dd8b7d02f533edfd5bfc7b7597b48dd1f7ab49776d8b1425e9fa0d0000000000000001000000aeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d70000000000000000000000000000000000000000000000000000000000000000
//   proof: 0x0c02000000000000002e000000000000007a000000000000008200000000000000441d48d6ab538fe8788bc927400c13f50fd6113019e1f5b731ea2a0be73f5a9a5232bfd8fc24e3a83f68f0b13f920dcdb5c7fe17b246c21e589464977b2933497ceefcb4543d8c35fa84dd8f02a988005e8a41c20dfa77546d198e738fb4346d09cea7049276fe3bafafca0df4028efb2ec1ef66192ed29538d0156a8f88dc5f99a1ea5afb4e422b0bf9f0d395259a456e9569fc800f32493916fde590635e3912757609f025e6fcecf9b87bdcd20d6cb4a3226a93c12c7d2b1811a56ce4a71df4021ce4d7ecedc2c28bd1c8ce2dbf2a62ad4c724f38c915083978c31814affb495b0a0877450de977561a156d1e81f0ba0a107654a6e33ac1e8a549cba7f795bc867c07a6a0cf4ba3d8eccbed6a0195880810aff0019a804cc4f308b935b4e3a6d14267c08b0a316b33d88e1b7c08d01ac97a71129aca4b5675e3982b6c2921d1b4c2450d2c18477622ec2562c98b2435ff6b36fd56970fd02440b3b8d305ba213dfe40e239b8d6e440ab03e64164709d8022d1c5a648b1c28eb3511f4cf9f2f9ec2ecd4dd6a9760b5c3670fdbd592af96020386eca92ca1e5a98a7b779cf20b76f5162339ca423e48d1169e383931822adceb8b2d8aaf2da857fdddeaf0a9f7fc05038f795df9a0181933e05c2784fb513620d58b2d7afd8f21f34bb2ed3c63e1dfede004f7325295fbb037126bc2b827510cb5d9c8253093de91d4c8104de0a77e47d63c99467e89e7414d86692044a3e114d227c9fcc7c7df7c3960d853dd6
// }
// [MmrLeaf { version: MmrLeafVersion(0), parent_number_and_hash: (2, 0xba66eb36773ac13806017817f9735db74f3ae0a8994af1bb1931c5709290a9f3), beefy_next_authority_set: BeefyAuthoritySet { id: 1, len: 1, keyset_commitment: 0xaeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7 }, leaf_extra: 0x0000000000000000000000000000000000000000000000000000000000000000 }, MmrLeaf { version: MmrLeafVersion(0), parent_number_and_hash: (46, 0x63cde375567f691a22a0bdd98c78f85274775e5bf391ec9e6ed41e61221b9a7f), beefy_next_authority_set: BeefyAuthoritySet { id: 5, len: 1, keyset_commitment: 0xaeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7 }, leaf_extra: 0x0000000000000000000000000000000000000000000000000000000000000000 }, MmrLeaf { version: MmrLeafVersion(0), parent_number_and_hash: (122, 0xcbd3a1098384dd8b7d02f533edfd5bfc7b7597b48dd1f7ab49776d8b1425e9fa), beefy_next_authority_set: BeefyAuthoritySet { id: 13, len: 1, keyset_commitment: 0xaeb47a269393297f4b0a3c9c9cfd00c7a4195255274cf39d83dabc2fcc9ff3d7 }, leaf_extra: 0x0000000000000000000000000000000000000000000000000000000000000000 }]
#[test]
#[available_gas(20000000000)]
fn encoded_opaque_leaves_to_leaves_test_2(){
    let leaves = encoded_opaque_leaves_to_leaves(get_encoded_opaque_leaves_2().span());
    match leaves {
		Result::Ok(leaves) => {
        let expected_leaves: Array<BeefyData> = get_expected_leaves_2();
        assert(leaves.len()==3, 'Wrong leaves len');
        assert(*leaves.at(0)==*expected_leaves.at(0), 'leaf 0 mismatch');
        assert(*leaves.at(1)==*expected_leaves.at(1), 'leaf 0 mismatch');
        assert(*leaves.at(2)==*expected_leaves.at(2), 'leaf 0 mismatch');

        },
		Result::Err(e) => {e.print(); assert(false, 'Decoding failed');}
	};
    
}

fn get_encoded_opaque_leaves_2() -> Array<u8> {
    let mut i: Array<u8> = Default::default();
    i.append(0x0c);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x02);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xba);i.append(0x66);i.append(0xeb);i.append(0x36);i.append(0x77);i.append(0x3a);i.append(0xc1);i.append(0x38);i.append(0x06);i.append(0x01);i.append(0x78);i.append(0x17);i.append(0xf9);i.append(0x73);i.append(0x5d);i.append(0xb7);i.append(0x4f);i.append(0x3a);i.append(0xe0);i.append(0xa8);i.append(0x99);i.append(0x4a);i.append(0xf1);i.append(0xbb);i.append(0x19);i.append(0x31);i.append(0xc5);i.append(0x70);i.append(0x92);i.append(0x90);i.append(0xa9);i.append(0xf3);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x2e);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x63);i.append(0xcd);i.append(0xe3);i.append(0x75);i.append(0x56);i.append(0x7f);i.append(0x69);i.append(0x1a);i.append(0x22);i.append(0xa0);i.append(0xbd);i.append(0xd9);i.append(0x8c);i.append(0x78);i.append(0xf8);i.append(0x52);i.append(0x74);i.append(0x77);i.append(0x5e);i.append(0x5b);i.append(0xf3);i.append(0x91);i.append(0xec);i.append(0x9e);i.append(0x6e);i.append(0xd4);i.append(0x1e);i.append(0x61);i.append(0x22);i.append(0x1b);i.append(0x9a);i.append(0x7f);i.append(0x05);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x7a);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xcb);i.append(0xd3);i.append(0xa1);i.append(0x09);i.append(0x83);i.append(0x84);i.append(0xdd);i.append(0x8b);i.append(0x7d);i.append(0x02);i.append(0xf5);i.append(0x33);i.append(0xed);i.append(0xfd);i.append(0x5b);i.append(0xfc);i.append(0x7b);i.append(0x75);i.append(0x97);i.append(0xb4);i.append(0x8d);i.append(0xd1);i.append(0xf7);i.append(0xab);i.append(0x49);i.append(0x77);i.append(0x6d);i.append(0x8b);i.append(0x14);i.append(0x25);i.append(0xe9);i.append(0xfa);i.append(0x0d);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
    i
}

fn get_expected_leaves_2() -> Array<BeefyData> {
    let mut i: Array<BeefyData> = array![];

    let next_beefy_authority_set = BeefyAuthoritySet{
        id: 1,
        len: 1,
        keyset_commitment: u256{high: 0xaeb47a269393297f4b0a3c9c9cfd00c7, low:0xa4195255274cf39d83dabc2fcc9ff3d7}
    };
    let beefy_data = BeefyData{
        version: 0,
        block_number: 2,
        hash: u256{high: 0xba66eb36773ac13806017817f9735db7, low:0x4f3ae0a8994af1bb1931c5709290a9f3},
        leaf_extra: u256{high: 0x00000000000000000000000000000000, low:0x00000000000000000000000000000000},
        beefy_next_authority_set: next_beefy_authority_set,
    };
    i.append(beefy_data);

    let next_beefy_authority_set = BeefyAuthoritySet{
        id: 5,
        len: 1,
        keyset_commitment: u256{high: 0xaeb47a269393297f4b0a3c9c9cfd00c7, low:0xa4195255274cf39d83dabc2fcc9ff3d7}
    };
    let beefy_data = BeefyData{
        version: 0,
        block_number: 46,
        hash: u256{high: 0x63cde375567f691a22a0bdd98c78f852, low:0x74775e5bf391ec9e6ed41e61221b9a7f},
        leaf_extra: u256{high: 0x00000000000000000000000000000000, low:0x00000000000000000000000000000000},
        beefy_next_authority_set: next_beefy_authority_set,
    };
    i.append(beefy_data);

    let next_beefy_authority_set = BeefyAuthoritySet{
        id: 13,
        len: 1,
        keyset_commitment: u256{high: 0xaeb47a269393297f4b0a3c9c9cfd00c7, low:0xa4195255274cf39d83dabc2fcc9ff3d7}
    };
    let beefy_data = BeefyData{
        version: 0,
        block_number: 122,
        hash: u256{high: 0xcbd3a1098384dd8b7d02f533edfd5bfc, low:0x7b7597b48dd1f7ab49776d8b1425e9fa},
        leaf_extra: u256{high: 0x00000000000000000000000000000000, low:0x00000000000000000000000000000000},
        beefy_next_authority_set: next_beefy_authority_set,
    };
    i.append(beefy_data);

    i
}