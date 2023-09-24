use array::{ArrayTrait, SpanTrait};
use alexandria_substrate::lean_beefy_verifier::{verify_mmr_leaves_proof,encoded_opaque_leaves_to_hashes,get_mmr_root, verify_lean_beefy_proof_with_validator_set, u256_byte_reverse, keccak, Slice, Range, verify_eth_signature_pre_hashed};
use alexandria_substrate::substrate_storage_read_proof_verifier::{convert_u8_subarray_to_u8_array, u8_array_eq};
use alexandria_substrate::blake2b::convert_u8_array_to_felt252_array;
use debug::PrintTrait;
use result::ResultTrait;
use core::clone::Clone;

#[test]
#[available_gas(20000000000)]
fn test_lean_beefy_proof_verification() {
    let res = verify_lean_beefy_proof_with_validator_set(get_lean_beefy_proof().span(), get_current_validator_addresses().span(), ArrayTrait::<u8>::new().span(), 3, 39);
    let maybe_mmr_root: Result<Span<u8>, felt252> = match res{
        Result::Ok(beefy_payloads)=>{
            get_mmr_root(beefy_payloads.span())},
        Result::Err(e)=>{e.print(); Result::Err('Dummy return')},
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
        Result::Ok(beefy_payloads)=>{
            get_mmr_root(beefy_payloads.span())},
        Result::Err(e)=>{e.print(); Result::Err('Dummy return')},
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