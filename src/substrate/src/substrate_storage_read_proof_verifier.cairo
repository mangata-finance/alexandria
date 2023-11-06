use alexandria_math::BitShift;
use integer::{u64_wrapping_add, BoundedInt};
use traits::{Into, TryInto};
use option::OptionTrait;
use result::ResultTrait;
use array::{ArrayTrait, SpanTrait};
use core::clone::Clone;
use alexandria_substrate::blake2b::{blake2b};
use core::traits::Default;
use debug::PrintTrait;


const FIRST_PREFIX: u8 = 0x00;
const LEAF_PREFIX_MASK: u8 = 0x40;
const BRANCH_WITHOUT_MASK: u8 = 0x80;
const BRANCH_WITH_MASK: u8 = 0xC0;
const EMPTY_TRIE: u8 = 0x00; //BitOr::<u8>::bitor(FIRST_PREFIX, 0x00); // 0x00000000
const ALT_HASHING_LEAF_PREFIX_MASK: u8 = 0x20; //bitor(FIRST_PREFIX, 0x20);
const ALT_HASHING_BRANCH_WITH_MASK: u8 = 0x10; //bitor(FIRST_PREFIX, 0x10);
const ESCAPE_COMPACT_HEADER: u8 = 0x01; //bitor(EMPTY_TRIE, 0x01);

const NIBBLE_PER_BYTE: usize = 2;
const NIBBLE_BITMASK_LEFT: u8 = 0xF0;
const NIBBLE_BITMASK_RIGHT: u8 = 0x0F;
const BITMAP_LENGTH: usize = 2;
/// Number of child for a branch (trie radix).
const NIBBLE_LENGTH: usize = 16;

const HASH_LENGTH: usize = 32; // 256/8


// Possibly unsafe and insecure substrate storage proof verifier
// DO NOT use in production - yet :)

#[derive(Copy, Drop)]
enum NodeHeader {
    Null: (),
    // contains wether there is a value and nibble count
    Branch: (bool, usize),
    // contains nibble count
    Leaf: usize,
    // contains nibble count.
    HashedValueBranch: usize,
    // contains nibble count.
    HashedValueLeaf: usize,
}

#[derive(Copy, Drop)]
enum NodePlan {
    /// Null trie node; could be an empty root or an empty branch entry.
    Empty: (),
    /// Leaf node; has a partial key plan and value.
    Leaf: (NibbleSlicePlan, ValuePlan),
    /// Branch node with support for a nibble (when extension nodes are not used).
    NibbledBranch: (NibbleSlicePlan, Option<ValuePlan>, Span<Option<NodeHandlePlan>>, ),
}

#[derive(Copy, Drop, PartialEq)]
enum NodeHandlePlan {
    Hash: Range,
    Inline: Range,
}

#[derive(Copy, Drop, PartialEq)]
enum ValuePlan {
    /// Range for byte representation in encoded node.
    Inline: Range,
    /// Range for hash in encoded node and original
    /// value size.
    Node: Range,
}

/// A `NibbleSlicePlan` is a blueprint for decoding a nibble slice from a byte slice. The
/// `NibbleSlicePlan` is created by parsing a byte slice and can be reused multiple times.
#[derive(Drop, Copy, PartialEq)]
struct NibbleSlicePlan {
    range: Range,
    padding: bool
}

fn nibble_len(nibble_slice_plan: NibbleSlicePlan) -> usize {
    if nibble_slice_plan.range.end == nibble_slice_plan.range.start {
        return 0;
    };
    if nibble_slice_plan.padding {
        ((nibble_slice_plan.range.end - nibble_slice_plan.range.start) * 2) - 1
    } else {
        ((nibble_slice_plan.range.end - nibble_slice_plan.range.start) * 2)
    }
}

#[derive(Drop, Copy, PartialEq)]
struct Range {
    start: usize,
    end: usize
}

#[derive(Drop, Copy)]
struct Slice<T> {
    span: Span<T>,
    range: Range,
}

fn verify_substrate_storage_read_proof_given_hashes(
    buffer: Span<u8>,
    buffer_node_index: Span<usize>,
    key: Span<u8>,
    root: Span<u8>,
    hashes: Span<u256>
) -> Result<Slice<u8>, felt252> {
    if hashes.len() != buffer_node_index.len() {
        return Result::Err('Bad Hashes Array');
    };

    lookup_value(buffer, buffer_node_index, key, hashes, root)
}

// fn verify_substrate_storage_read_proof_given_hashes_clone_test(buffer: Span<u8>, buffer_node_index: Span<usize>, key: Span<u8>, root: Span<u8>, hashes: Span<u8>) -> Result<Slice<u8>,felt252>{
// 	if hashes.len() != (HASH_LENGTH*buffer_node_index.len()){
// 			return Result::Err('Bad Hashes Array');
// 		};

// 	let mut hashesx = ArrayTrait::<u8>::new();
// 	let mut hash = ArrayTrait::<u8>::new().span();
// 	let mut encoded_node = ArrayTrait::<u8>::new();
// 	let mut itr: usize = 0;
// 	let maybe_err = loop{
// 		if itr== buffer_node_index.len(){
// 			break Result::Ok(());
// 		};

// 		let mut encoded_node = ArrayTrait::<u8>::new();

// 		if itr == (buffer_node_index.len() -1) {
// 			encoded_node = get_array_from_span(buffer, Range{start:*buffer_node_index.at(itr), end:buffer.len()});
// 		} else {
// 			encoded_node = get_array_from_span(buffer, Range{start:*buffer_node_index.at(itr), end:*buffer_node_index.at(itr+1)});
// 		};
// 		let xyz = *encoded_node.at(0);
// 		// hash = blake2b(encoded_node).span();
// 		// if hash.len() != HASH_LENGTH{
// 		// 	break Result::Err('Bad Hasher Output');
// 		// }

// 		let mut itr2 =0;
// 		loop{
// 			if itr2==HASH_LENGTH{
// 				break;
// 			};
// 			hashesx.append(*hashes.at(itr2));
// 			itr2 = itr2 + 1;
// 		};
// 		itr = itr +1;
// 	};

// 	match maybe_err {
// 		Result::Ok(_) => {},
// 		Result::Err(e) => {return Result::Err(e);}
// 	};

// 	lookup_value(buffer, buffer_node_index, key, hashes, root)
// }

fn verify_substrate_storage_read_proof(
    buffer: Span<u8>, buffer_node_index: Span<usize>, key: Span<u8>, root: Span<u8>
) -> Result<Slice<u8>, felt252> {
    let mut hashes = ArrayTrait::<u8>::new();
    let mut hash = ArrayTrait::<u8>::new().span();
    let mut encoded_node = ArrayTrait::<u8>::new();
    let mut itr: usize = 0;
    let maybe_err = loop {
        if itr == buffer_node_index.len() {
            break Result::Ok(());
        };

        let mut encoded_node = ArrayTrait::<u8>::new();

        if itr == (buffer_node_index.len() - 1) {
            encoded_node =
                get_array_from_span(
                    buffer, Range { start: *buffer_node_index.at(itr), end: buffer.len() }
                );
        } else {
            encoded_node =
                get_array_from_span(
                    buffer,
                    Range { start: *buffer_node_index.at(itr), end: *buffer_node_index.at(itr + 1) }
                );
        };
        hash = blake2b(encoded_node).span();
        if hash.len() != HASH_LENGTH {
            break Result::Err('Bad Hasher Output');
        }

        let mut itr2 = 0;
        loop {
            if itr2 == HASH_LENGTH {
                break;
            };
            hashes.append(*hash.at(itr2));
            itr2 = itr2 + 1;
        };
        itr = itr + 1;
    };

    match maybe_err {
        Result::Ok(_) => {},
        Result::Err(e) => {
            return Result::Err(e);
        }
    };

    if hashes.len() != (HASH_LENGTH * buffer_node_index.len()) {
        return Result::Err('Bad Hashes Array');
    };

    let hashes_u256 = hashes_to_u256s(hashes.span()).expect('len checked above');

    lookup_value(buffer, buffer_node_index, key, hashes_u256.span(), root)
}

fn hashes_to_u256s(hashes: Span<u8>) -> Result<Array<u256>, felt252> {
    let hashes_len: usize = hashes.len() / HASH_LENGTH;
    if (hashes_len * HASH_LENGTH) != hashes.len() {
        return Result::Err('Bad hashes len');
    }

    let mut itr: usize = 0;
    let mut val_u256: u256 = 0;
    let mut be_u256s: Array<u256> = array![];
    let mut citr: usize = 0;

    loop {
        if itr == hashes_len {
            break;
        }
        val_u256 = 0;
        citr = 0;

        loop {
            if citr == HASH_LENGTH {
                break;
            }
            val_u256 = Into::<u8, u256>::into(*hashes.at(itr * HASH_LENGTH + citr))
                + val_u256 * 256_u256;
            citr = citr + 1;
        };

        be_u256s.append(val_u256);
        itr = itr + 1;
    };
    Result::Ok(be_u256s)
}

fn u256_to_u8_a(x: u256) -> Array<u8>{
    let mut arr: Array<u8> = array![];

    arr.append(((x.high / 0x01000000000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00010000000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000100000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000001000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000010000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000100000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000001000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000010000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000100000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000001000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000000010000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000000000100000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000000000001000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000000000000010000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high / 0x00000000000000000000000000000100_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.high                                          ) & BoundedInt::<u8>::max().into()).try_into().unwrap());

    arr.append(((x.low / 0x01000000000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00010000000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000100000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000001000000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000010000000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000100000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000001000000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000010000000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000100000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000001000000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000000010000000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000000000100000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000000000001000000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000000000000010000_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low / 0x00000000000000000000000000000100_u128) & BoundedInt::<u8>::max().into()).try_into().unwrap());
    arr.append(((x.low                                          ) & BoundedInt::<u8>::max().into()).try_into().unwrap());

    arr
}

fn get_array_from_span(buffer: Span<u8>, range: Range) -> Array<u8> {
    let mut itr = range.start;
    let mut array_op = ArrayTrait::<u8>::new();
    loop {
        if itr == range.end {
            break;
        }
        array_op.append(*buffer.at(itr));
        itr = itr + 1;
    };
    array_op
}

fn u8_array_eq(x: Span<u8>, y: Span<u8>) -> bool {
    if x.len() != y.len() {
        return false;
    }

    let mut itr = 0;
    let mut eq = true;
    loop {
        if itr == x.len() {
            break;
        };

        if *x.at(itr) != *y.at(itr) {
            eq = false;
            break;
        };

        itr = itr + 1;
    };
    eq
}

fn convert_u8_subarray_to_u8_array(a: Span<u8>, start: usize, length: usize) -> Array<u8> {
    let mut x = ArrayTrait::<u8>::new();
    let mut i: usize = 0;
    loop {
        if i == length {
            break;
        }
        x.append(*a.at(i + start));
        i = i + 1;
    };
    x
}

fn convert_u8_subarray_to_felt252_array(
    a: Span<u8>, start: usize, length: usize
) -> Array<felt252> {
    let mut x = ArrayTrait::<felt252>::new();
    let mut i: usize = 0;
    loop {
        if i == length {
            break;
        }
        x.append((*a.at(i + start)).into());
        i = i + 1;
    };
    x
}

fn lookup_value(
    buffer: Span<u8>, buffer_index: Span<usize>, key: Span<u8>, hashes: Span<u256>, root: Span<u8>
) -> Result<Slice<u8>, felt252> {
    let mut key_nibble_offset: usize = 0;
    let mut hash = Slice { span: root, range: Range { start: 0, end: root.len() } };

    let mut depth: usize = 0;
    let mut inner_depth: usize = 0;
    let res2 = loop {
        let mut node_data = get_node(hash, hashes, buffer, buffer_index).unwrap();
        let (is_continue, res0) = loop {
            let decoded_node = parse_encoded_node(node_data).unwrap();
            let mut next_node: Option<NodeHandlePlan> = Option::None(());
            match decoded_node {
                NodePlan::Empty(()) => {
                    break (false, Result::Err('Empty Node'));
                },
                NodePlan::Leaf((
                    nibble_slice_plan, value_plan
                )) => {
                    if nibble_partial_eq(buffer, nibble_slice_plan, key, key_nibble_offset) {
                        break (
                            false, Result::Ok(load_value(buffer, value_plan, hashes, buffer_index))
                        );
                    } else {
                        break (false, Result::Err('No value at leaf'));
                    };
                },
                NodePlan::NibbledBranch((
                    nibble_slice_plan, maybe_value_plan, children
                )) => {
                    if !nibble_partial_starts_with(
                        buffer, nibble_slice_plan, key, key_nibble_offset
                    ) {
                        break (false, Result::Err('No value at NibbledBranch'));
                    };

                    if nibble_partial_len_eq(buffer, nibble_slice_plan, key, key_nibble_offset) {
                        if maybe_value_plan.is_some() {
                            let val = load_value(
                                buffer, maybe_value_plan.unwrap(), hashes, buffer_index
                            );
                            break (false, Result::Ok(val));
                        } else {
                            break (false, Result::Err('No value at NibbledBranch'));
                        }
                    } else {
                        if children
                            .at(
                                nibble_at(
                                    key, key_nibble_offset + nibble_len(nibble_slice_plan), false
                                )
                                    .into()
                            )
                            .is_some() {
                            next_node = *children
                                .at(
                                    nibble_at(
                                        key,
                                        key_nibble_offset + nibble_len(nibble_slice_plan),
                                        false
                                    )
                                        .into()
                                );
                            key_nibble_offset = key_nibble_offset
                                + nibble_len(nibble_slice_plan)
                                + 1;
                        } else {
                            break (false, Result::Err('No NibbledBranch child'));
                        }
                    }
                },
            };

            assert(next_node.is_some(), 'next_node is none');

            inner_depth = inner_depth + 1;

            match next_node.unwrap() {
                NodeHandlePlan::Hash(range) => {
                    hash = Slice { span: buffer, range: range };
                    break (true, Result::Err('Dummy'));
                },
                NodeHandlePlan::Inline(range) => {
                    node_data = Slice { span: buffer, range: range };
                },
            };
        };
        depth = depth + 1;
        if !is_continue {
            break res0;
        };
    };
    res2
}

fn nibble_at(nibble_byte_span: Span<u8>, nibble_index: usize, padding: bool) -> u8 {
    let byte: u8 = if padding {
        *nibble_byte_span.at((nibble_index + 1) / NIBBLE_PER_BYTE)
    } else {
        *nibble_byte_span.at(nibble_index / NIBBLE_PER_BYTE)
    };

    if (nibble_index % NIBBLE_PER_BYTE == 0) ^ padding {
        byte / 16
    } else {
        (byte & NIBBLE_BITMASK_RIGHT)
    }
}

fn nibble_at_slice(nibble_byte_slice: Slice<u8>, nibble_index: usize, padding: bool) -> u8 {
    let byte: u8 = if padding {
        *nibble_byte_slice
            .span
            .at(nibble_byte_slice.range.start + ((nibble_index + 1) / NIBBLE_PER_BYTE))
    } else {
        *nibble_byte_slice.span.at(nibble_byte_slice.range.start + (nibble_index / NIBBLE_PER_BYTE))
    };

    if (nibble_index % NIBBLE_PER_BYTE == 0) ^ padding {
        byte / 16
    } else {
        (byte & NIBBLE_BITMASK_RIGHT)
    }
}

fn nibble_partial_eq(
    buffer: Span<u8>, nibble_slice_plan: NibbleSlicePlan, key: Span<u8>, key_nibble_offset: usize
) -> bool {
    if !nibble_partial_len_eq(buffer, nibble_slice_plan, key, key_nibble_offset) {
        return false;
    }

    let nibble_length: usize = if nibble_slice_plan.padding {
        ((nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE) - 1
    } else {
        (nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
    };

    let mut eq = true;
    let mut itr = 0;
    loop {
        if itr == nibble_length {
            break;
        }

        if !(nibble_at_slice(
            Slice { span: buffer, range: nibble_slice_plan.range }, itr, nibble_slice_plan.padding
        ) == nibble_at(key, itr + key_nibble_offset, false)) {
            eq == false;
            break;
        };
        itr = itr + 1;
    };
    eq
}
fn nibble_partial_starts_with(
    buffer: Span<u8>, nibble_slice_plan: NibbleSlicePlan, key: Span<u8>, key_nibble_offset: usize
) -> bool {
    // remaining key nibble length should be greater than the nibble slice length
    if (nibble_slice_plan.range.end == nibble_slice_plan.range.start) {
        return true;
    }

    // if key length is 0 and it reaches here then lens are diff
    if key.len() == 0 {
        return false;
    }

    let nibble_length = if nibble_slice_plan.padding {
        ((nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE) - 1
    } else {
        (nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
    };

    let key_length = (key.len() * NIBBLE_PER_BYTE) - key_nibble_offset;
    if nibble_length > key_length {
        return false;
    }

    let mut eq = true;
    let mut itr = 0;
    loop {
        if itr == nibble_length {
            break;
        }

        if !(nibble_at_slice(
            Slice { span: buffer, range: nibble_slice_plan.range }, itr, nibble_slice_plan.padding
        ) == nibble_at(key, itr + key_nibble_offset, false)) {
            eq == false;
            break;
        };
        itr = itr + 1;
    };
    eq
}


fn nibble_partial_len_eq(
    buffer: Span<u8>, nibble_slice_plan: NibbleSlicePlan, key: Span<u8>, key_nibble_offset: usize
) -> bool {
    if (nibble_slice_plan.range.end == nibble_slice_plan.range.start) {
        return key.len() == key_nibble_offset;
    }

    // if key length is 0 and it reaches here then lens are diff
    if key.len() == 0 {
        return false;
    }

    let nibble_length = if nibble_slice_plan.padding {
        (nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE - 1
    } else {
        (nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
    };

    let key_length = (key.len() * NIBBLE_PER_BYTE) - key_nibble_offset;
    nibble_length == key_length
}

fn load_value(
    buffer: Span<u8>, v: ValuePlan, hashes: Span<u256>, buffer_index: Span<usize>
) -> Slice<u8> {
    match v {
        ValuePlan::Inline(value_plan) => Slice { span: buffer, range: value_plan },
        ValuePlan::Node(hash_range) => {
            get_node(Slice { span: buffer, range: hash_range }, hashes, buffer, buffer_index)
                .unwrap()
        },
    }
}

fn get_node(
    hash: Slice<u8>, hashes: Span<u256>, buffer: Span<u8>, buffer_index: Span<usize>
) -> Option<Slice<u8>> {
    let mut res: Option<Slice<u8>> = Option::None(());
    let mut itr = 0;
    let number_of_hashes = hashes.len();

    assert((hash.range.end-hash.range.start) == HASH_LENGTH, 'Bad hash length');

    let hash_u256 = *hashes_to_u256s(hash.span.slice(hash.range.start, HASH_LENGTH)).expect('len checked above').at(0);

    if number_of_hashes != buffer_index.len() {
        return Option::None(());
    }
    let mut eq = true;
    let mut itr2 = 0;
    loop {
        if itr == number_of_hashes {
            break;
        }

        itr2 = 0;

        if hash_u256 != *hashes.at(itr){
            eq = false;
        }

        if eq {
            if itr == (number_of_hashes - 1) {
                res =
                    Option::Some(
                        Slice {
                            span: buffer, range: Range {
                                start: *buffer_index.at(itr), end: buffer.len()
                            }
                        }
                    );
            } else {
                res =
                    Option::Some(
                        Slice {
                            span: buffer, range: Range {
                                start: *buffer_index.at(itr), end: *buffer_index.at(itr + 1)
                            }
                        }
                    );
            }
            break;
        } else {
            eq = true;
        }

        itr = itr + 1;
    };

    res
}

fn parse_encoded_node(buffer: Slice<u8>) -> Result<NodePlan, felt252> {
    let mut offset: usize = buffer.range.start;

    let header = decode_header(buffer, ref offset).unwrap();

    assert(offset < buffer.range.end, 'offset beyond node range');

    let contains_hash = match header {
        NodeHeader::Null(_) => {
            false
        },
        NodeHeader::Branch(_) => {
            false
        },
        NodeHeader::Leaf(_) => {
            false
        },
        NodeHeader::HashedValueBranch(_) => {
            true
        },
        NodeHeader::HashedValueLeaf(_) => {
            true
        },
    };

    let branch_has_value = match header {
        NodeHeader::Null(_) => {
            true
        },
        NodeHeader::Branch((has_value, _)) => has_value,
        NodeHeader::Leaf(_) => {
            true
        },
        NodeHeader::HashedValueBranch(_) => {
            true
        },
        NodeHeader::HashedValueLeaf(_) => {
            true
        },
    };

    match header {
        NodeHeader::Null(()) => Result::Ok(NodePlan::Empty(())),
        NodeHeader::Branch((
            _, nibble_count
        )) => {
            let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
            // check that the padding is valid (if any)
            if padding && ((*buffer.span.at(offset) & NIBBLE_BITMASK_LEFT) != 0) {
                return Result::Err('Bad Format');
            }
            let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
            let partial = Range { start: offset, end: offset + partial_bytes_length };
            offset = offset + partial_bytes_length;
            let partial_padding = (nibble_count % NIBBLE_PER_BYTE) != 0;
            let bitmap = bitmap_decode(
                Slice {
                    span: buffer.span, range: Range { start: offset, end: offset + BITMAP_LENGTH }
                }
            );
            offset = offset + BITMAP_LENGTH;
            let value = if branch_has_value {
                Option::Some(
                    if contains_hash {
                        let vp = ValuePlan::Node(
                            Range { start: offset, end: offset + HASH_LENGTH }
                        );
                        offset = offset + HASH_LENGTH;
                        vp
                    } else {
                        let count = compact_u32_decode(buffer, ref offset).unwrap();
                        let vp = ValuePlan::Inline(Range { start: offset, end: offset + count });
                        offset = offset + count;
                        vp
                    }
                )
            } else {
                Option::None(())
            };

            let mut children = ArrayTrait::<Option<NodeHandlePlan>>::new();
            let mut itr: usize = 0;
            loop {
                if itr == NIBBLE_LENGTH {
                    break;
                }
                if bitmap_value_at(bitmap, itr.try_into().expect('itr < 16')) {
                    let count = compact_u32_decode(buffer, ref offset).unwrap();
                    let range = Range { start: offset, end: offset + count };
                    offset = offset + count;
                    children
                        .append(
                            Option::Some(
                                if count == HASH_LENGTH {
                                    NodeHandlePlan::Hash(range)
                                } else {
                                    NodeHandlePlan::Inline(range)
                                }
                            )
                        );
                } else {
                    children.append(Option::None(()));
                }
                itr = itr + 1;
            };

            assert(offset == buffer.range.end, 'offset not at node range end');

            Result::Ok(
                NodePlan::NibbledBranch(
                    (
                        NibbleSlicePlan {
                            range: partial, padding: partial_padding
                        }, value, children.span(),
                    )
                )
            )
        },
        NodeHeader::Leaf(nibble_count) => {
            let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
            // check that the padding is valid (if any)
            if padding && ((*buffer.span.at(offset) & NIBBLE_BITMASK_LEFT) != 0) {
                return Result::Err('Bad Format');
            }
            let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
            let partial = Range { start: offset, end: offset + partial_bytes_length };
            offset = offset + partial_bytes_length;
            let partial_padding = (nibble_count % NIBBLE_PER_BYTE) != 0;
            let value = if contains_hash {
                let vp = ValuePlan::Node(Range { start: offset, end: offset + HASH_LENGTH });
                offset = offset + HASH_LENGTH;
                vp
            } else {
                let count = compact_u32_decode(buffer, ref offset).unwrap();
                let vp = ValuePlan::Inline(Range { start: offset, end: offset + count });
                offset = offset + count;
                vp
            };
            assert(offset == buffer.range.end, 'offset not at node range end');

            Result::Ok(
                NodePlan::Leaf(
                    (NibbleSlicePlan { range: partial, padding: partial_padding }, value, )
                )
            )
        },
        NodeHeader::HashedValueBranch(nibble_count) => {
            let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
            // check that the padding is valid (if any)
            if padding && ((*buffer.span.at(offset) & NIBBLE_BITMASK_LEFT) != 0) {
                return Result::Err('Bad Format');
            }
            let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
            let partial = Range { start: offset, end: offset + partial_bytes_length };
            offset = offset + partial_bytes_length;
            let partial_padding = (nibble_count % NIBBLE_PER_BYTE) != 0;
            let bitmap = bitmap_decode(
                Slice {
                    span: buffer.span, range: Range { start: offset, end: offset + BITMAP_LENGTH }
                }
            );
            offset = offset + BITMAP_LENGTH;
            let value = if branch_has_value {
                Option::Some(
                    if contains_hash {
                        let vp = ValuePlan::Node(
                            Range { start: offset, end: offset + HASH_LENGTH }
                        );
                        offset = offset + HASH_LENGTH;
                        vp
                    } else {
                        let count = compact_u32_decode(buffer, ref offset).unwrap();
                        let vp = ValuePlan::Inline(Range { start: offset, end: offset + count });
                        offset = offset + count;
                        vp
                    }
                )
            } else {
                Option::None(())
            };

            let mut children = ArrayTrait::<Option<NodeHandlePlan>>::new();
            let mut itr: usize = 0;
            loop {
                if itr == NIBBLE_LENGTH {
                    break;
                }
                if bitmap_value_at(bitmap, itr.try_into().expect('itr < 16')) {
                    let count = compact_u32_decode(buffer, ref offset).unwrap();
                    let range = Range { start: offset, end: offset + count };
                    offset = offset + count;
                    children
                        .append(
                            Option::Some(
                                if count == HASH_LENGTH {
                                    NodeHandlePlan::Hash(range)
                                } else {
                                    NodeHandlePlan::Inline(range)
                                }
                            )
                        );
                } else {
                    children.append(Option::None(()));
                }
                itr = itr + 1;
            };
            assert(offset == buffer.range.end, 'offset not at node range end');
            Result::Ok(
                NodePlan::NibbledBranch(
                    (
                        NibbleSlicePlan {
                            range: partial, padding: partial_padding
                        }, value, children.span(),
                    )
                )
            )
        },
        NodeHeader::HashedValueLeaf(nibble_count) => {
            let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
            // check that the padding is valid (if any)
            if padding && ((*buffer.span.at(offset) & NIBBLE_BITMASK_LEFT) != 0) {
                return Result::Err('Bad Format');
            }
            let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
            let partial = Range { start: offset, end: offset + partial_bytes_length };
            offset = offset + partial_bytes_length;
            let partial_padding = (nibble_count % NIBBLE_PER_BYTE) != 0;
            let value = if contains_hash {
                let vp = ValuePlan::Node(Range { start: offset, end: offset + HASH_LENGTH });
                offset = offset + HASH_LENGTH;
                vp
            } else {
                let count = compact_u32_decode(buffer, ref offset)?;
                let vp = ValuePlan::Inline(Range { start: offset, end: offset + count });
                offset = offset + count;
                vp
            };
            assert(offset == buffer.range.end, 'offset not at node range end');

            Result::Ok(
                NodePlan::Leaf(
                    (NibbleSlicePlan { range: partial, padding: partial_padding }, value, )
                )
            )
        },
    }
}

fn bitmap_decode(buffer: Slice<u8>) -> u16 {
    assert((buffer.range.end - buffer.range.start) == 2, 'wrong bitmap len');
    let value = u16_decode(buffer);
    assert(value != 0, 'Bitmap without a child');
    value
}

fn u16_decode(slice: Slice<u8>) -> u16 {
    assert((slice.range.end - slice.range.start) == 2, 'wrong u16 len');

    // Little endian encoding
    // first byte is low
    let first: u16 = Into::<u8, u16>::into(*slice.span.at(slice.range.start));
    // second byte is high
    let second: u16 = Into::<u8, u16>::into(*slice.span.at(slice.range.start + 1));

    let res: u16 = first + (second * 256);
    res
}

fn u32_decode(slice: Slice<u8>) -> u32 {
    assert((slice.range.end - slice.range.start) == 4, 'wrong u32 len');

    // Little endian encoding
    let first: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start));
    let second: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 1));
    let third: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 2));
    let fourth: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 3));

    let res: u32 = first + ((second + ((third + (fourth * 256)) * 256)) * 256);
    res
}

fn bitmap_value_at(bitmap: u16, itr: u8) -> bool {
    (bitmap & BitShift::<u16>::shl(1_u16, itr.into())) != 0
}

fn compact_u32_decode(buffer: Slice<u8>, ref offset: usize) -> Result<u32, felt252> {
    let prefix: u8 = *buffer.span.at(offset);
    offset = offset + 1;

    let selector: u8 = prefix % 4;

    if selector == 0 {
        return Result::Ok(Into::<u8, u32>::into(prefix) / 4);
    } else if selector == 1 {
        // Little endian encoding
        // first byte is low - prefix
        let first: u32 = Into::<u8, u32>::into(prefix);
        // second byte is high - the following byte
        let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
        offset = offset + 1;

        let x: u32 = (first + (second * 256)) / 4;

        if x > 0x3F && x <= 0x3FFF {
            return Result::Ok(x);
        } else {
            return Result::Err('Bad compact u32 enc');
        }
    } else if selector == 2 {
        // Little endian encoding
        let first: u32 = Into::<u8, u32>::into(prefix);
        let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
        offset = offset + 1;
        let third: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
        offset = offset + 1;
        let fourth: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
        offset = offset + 1;

        let x: u32 = (first + ((second + ((third + (fourth * 256)) * 256)) * 256)) / 4;

        if x > 0x3FFF && x <= (BoundedInt::<u32>::max() / 4) {
            return Result::Ok(x);
        } else {
            return Result::Err('Bad compact u32 enc');
        }
    } else if selector == 3 {
        if (prefix / 4) == 0 {
            // Little endian encoding
            let first: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
            offset = offset + 1;
            let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
            offset = offset + 1;
            let third: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
            offset = offset + 1;
            let fourth: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
            offset = offset + 1;

            let x: u32 = first + ((second + ((third + (fourth * 256)) * 256)) * 256);

            if x > (BoundedInt::<u32>::max() / 4) {
                return Result::Ok(x);
            } else {
                return Result::Err('Bad compact u32 enc');
            }
        } else {
            return Result::Err('Bad compact u32 enc');
        }
    }
    return Result::Err('Bad compact u32 enc');
}

fn decode_header(b: Slice<u8>, ref offset: usize) -> Result<NodeHeader, felt252> {
    let i = *b.span.at(offset);

    offset = offset + 1;

    if i == EMPTY_TRIE {
        return Result::Ok(NodeHeader::Null(()));
    }

    let masked_i = (i & 0xC0);

    if masked_i == LEAF_PREFIX_MASK {
        Result::Ok(NodeHeader::Leaf(decode_size(i, b, ref offset, 2).unwrap()))
    } else if masked_i == BRANCH_WITH_MASK {
        Result::Ok(NodeHeader::Branch((true, decode_size(i, b, ref offset, 2).unwrap())))
    } else if masked_i == BRANCH_WITHOUT_MASK {
        Result::Ok(NodeHeader::Branch((false, decode_size(i, b, ref offset, 2).unwrap())))
    } else if masked_i == EMPTY_TRIE {
        if (i & 0xE0) == ALT_HASHING_LEAF_PREFIX_MASK {
            Result::Ok(NodeHeader::HashedValueLeaf((decode_size(i, b, ref offset, 3).unwrap())))
        } else if (i & 0xF0) == ALT_HASHING_BRANCH_WITH_MASK {
            Result::Ok(NodeHeader::HashedValueBranch((decode_size(i, b, ref offset, 4).unwrap())))
        } else {
            // do not allow any special encoding
            Result::Err('Unallowed encoding')
        }
    } else {
        Result::Err('Unallowed encoding')
    }
}

fn decode_size(
    first: u8, b: Slice<u8>, ref offset: usize, prefix_mask: usize
) -> Result<usize, felt252> {
    let max_value = BitShift::<u8>::shr(0xff, prefix_mask.try_into().unwrap());

    let mut result: usize = (first & max_value).into();

    if result < max_value.into() {
        return Result::Ok(result);
    }

    result -= 1;
    let res = loop {
        let n = Into::<u8, usize>::into(*b.span.at(offset));
        offset = offset + 1;
        if n < 255 {
            break Result::Ok(result + n + 1);
        }
        result += 255;
    };
    res
}
