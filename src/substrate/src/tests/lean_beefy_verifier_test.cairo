use array::{ArrayTrait, SpanTrait};
use alexandria_substrate::lean_beefy_verifier::{verify_lean_beefy_proof_with_validator_set, u256_le_to_be, keccak, Slice, Range, verify_eth_signature_pre_hashed};
use alexandria_substrate::substrate_storage_read_proof_verifier::{convert_u8_subarray_to_u8_array};
use debug::PrintTrait;
use result::ResultTrait;

#[test]
#[available_gas(20000000000)]
fn test_lean_beefy_proof_verification() {
    let res = verify_lean_beefy_proof_with_validator_set(get_lean_beefy_proof().span(), get_current_validator_addresses().span(), ArrayTrait::<u8>::new().span(), 3, 39);
    match res{
        Result::Ok(_)=>{},
        Result::Err(e)=>e.print(),
    };
    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');

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
    match res{
        Result::Ok(_)=>{},
        Result::Err(e)=>e.print(),
    };
    // let rs = convert_u8_subarray_to_u8_array(res.span, res.range.start, res.range.end - res.range.start);
    // assert(u8_array_eq(rs.span(), ers.span()), 'Raw storage must be as expected');

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
    let commitment_pre_hashed = u256_le_to_be(commitment_pre_hashed_le);

    let add = get_add().span();
    let add_slice = Slice{span: add, range: Range{start:0,end:add.len()}};

    let sig = get_sig().span();
    let sig_slice = Slice{span: sig, range: Range{start:0,end:sig.len()}};

    let res = verify_eth_signature_pre_hashed(commitment_pre_hashed, sig_slice, add_slice);
    res.print();
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
    let commitment_pre_hashed = u256_le_to_be(commitment_pre_hashed_le);

    let add = get_add_2().span();
    let add_slice = Slice{span: add, range: Range{start:0,end:add.len()}};

    let sig = get_sig_2().span();
    let sig_slice = Slice{span: sig, range: Range{start:0,end:sig.len()}};

    let res = verify_eth_signature_pre_hashed(commitment_pre_hashed, sig_slice, add_slice);
    res.print();
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

