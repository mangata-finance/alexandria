use alexandria_math::math::{shr, shl};
use alexandria_math::sha512::{math_shr_u64, math_shl_u64};
use integer::{u64_wrapping_add, bitwise, downcast, upcast, BoundedInt, U128BitXor};
use traits::{Into, TryInto, BitXor};
use option::OptionTrait;
use result::ResultTrait;
use array::{ArrayTrait, SpanTrait};
use core::clone::Clone;
use blake2b::blake2b;


const FIRST_PREFIX: u8 = 0x00;
const LEAF_PREFIX_MASK: u8 = 0x40;
const BRANCH_WITHOUT_MASK: u8 = 0x80;
const BRANCH_WITH_MASK: u8 = 0xC0;
const EMPTY_TRIE: u8 = bitor(FIRST_PREFIX, 0x00); // 0x00000000
const ALT_HASHING_LEAF_PREFIX_MASK: u8 = bitor(FIRST_PREFIX, 0x20);
const ALT_HASHING_BRANCH_WITH_MASK: u8 = bitor(FIRST_PREFIX, 0x10);
const ESCAPE_COMPACT_HEADER: u8 = bitor(EMPTY_TRIE, 0x01);

const NIBBLE_PER_BYTE: usize = 2;
const NIBBLE_BITMASK_LEFT: u8 = 0xF0;
const NIBBLE_BITMASK_RIGHT: u8 = 0x0F;
const BITMAP_LENGTH: usize = 2;
/// Number of child for a branch (trie radix).
const NIBBLE_LENGTH: usize = 16;

const HASH_LENGTH: usize = 32; // 256/8

// TODO
// Write traversal loop
// write scale decoders for u16 and compact u32
// Write buffer management stuff
// Write hasher stuff
// Maybe setup substrate code for debugging
// Debug 


// Use number_padding
// Use slices everywhere, use actuals and not plans
// Impl ops on slices...

#[derive(Copy, Drop, PartialEq)]
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

#[derive(Copy, Drop, PartialEq)]
enum NodePlan {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty: (),
	/// Leaf node; has a partial key plan and value.
	Leaf: (NibbleSlicePlan, ValuePlan),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch: (
		NibbleSlicePlan,
		Option<ValuePlan>,
		Span<Option<NodeHandlePlan>>,
    ),
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

impl NibbleSlicePlan{
	fn nibble_len() -> usize{
		if self.range.end == self.range.start {return 0;}
		if self.padding {
			((self.range.end - self.range.start) * 2) - 1 }
		else{
			((self.range.end - self.range.start) * 2)
		}

	}
}

#[derive(Drop, Copy, PartialEq)]
struct Range{
    start: usize,
    end: usize
}

#[derive(Drop, Copy, PartialEq)]
struct Slice<T>{
    span: Span<T>,
    range: Range,
}

fn verify_substrate_storage_proof(buffer: Span<u8>, buffer_node_index: Span<usize>, key: Span<u8>, root: Span<u8>) -> Result<Array<u8>, felt252>{
	let hashes = compute_node_hashes(buffer: Span<u8>, buffer_index: Span<usize>);
	let mut hashes = ArrayTrait::<u8>::new();
	let mut hash = ArrayTrait::<u8>::new();
	let mut encoded_node = ArrayTrait::<u8>::new();
	let mut itr = 0;
	loop{
		if itr== buffer_node_index.len(){
			break;
		}

		encoded_node = if itr == buffer_node_index.len() -1 {
			get_array_from_span(buffer, *buffer_node_index.at(itr), *buffer.len())
		} else {
			get_array_from_span(buffer, *buffer_node_index.at(itr), *buffer_node_index.at(itr+1))
		}
		hash = blake2b(encoded_node);
		if hash.len() != HASH_LENGTH{
			return Err('Bad Hasher Output');
		}

		let mut itr2 =0;
		loop{
			if itr2==HASH_LENGTH{
				break;
			}
			hashes.append(*hash.at(itr2))
			itr2 = itr2 + 1;
		}
		itr = itr +1;
	}
	if hashes.len() != (HASH_LENGTH*buffer_node_index.len()){
			return Err('Bad Hashes Array');
		}
	let value = lookup_value();
	value
}

fn get_array_from_span(buffer, start, end) -> Array<u8>{
	let mut itr = start;
	let mut array_op = ArrayTrait::<u8>::new();
	loop{
		if itr == end{
			break;
		}
		array_op.append(*buffer.at(itr));
		itr = itr +1;
	}
	array_op
}

fn lookup_value(buffer: Span<u8>, buffer_index: Span<usize>, key: Span<u8>, hashes: Span<u8>, root: Span<u8>) -> Result<Option<Slice<u8>>,felt252>{
	let mut key_nibble_offset: usize = 0;
	let mut hash = Slice{span: root, range: Range{start: 0, end: root.len()}};

	// let mut depth:usize =0;
	loop{
		let node_data = get_node(hash, hashes, buffer, buffer_index);
		loop{
			let decoded_node = parse_encoded_node(node_data);
			let next_node = match decoded_node{
				NodePlan::Empty(()) => {
					return Ok(None)
				},
				NodePlan::Leaf((nibble_slice_plan, value_plan)) =>{
						if nibble_partial_eq(buffer, nibble_slice_plan, key, key_nibble_offset) {
							return load_value(
								buffer
								value_plan,
							)
						} else {
							return Ok(None)
						},
				},
				NodePlan::NibbledBranch((nibble_slice_plan, children, maybe_value_plan)) => {
						if nibble_partial_starts_with(buffer, nibble_slice_plan, key, key_nibble_offset) {
							return Ok(None)
						};

						if nibble_partial_len_eq(buffer, nibble_slice_plan, key, key_nibble_offset) {
							match maybe_value_plan{
								Some(value_plan)=>{return load_value(
								buffer
								value_plan,
							)},
								None => {return Ok(None)},
							};
							
						} else {
							match *children.at(nibble_at(key, key_nibble_offset+nibble_slice_plan.nibble_len(), false)) {
								Some(x) => {
									key_nibble_offset = key_nibble_offset + nibble_slice_plan.nibble_len() + 1;
									x
								},
								None => {

									return Ok(None)
								},
							}
						}
					},
			}

			match next_node {
					NodeHandlePlan::Hash(range) => {
						hash = Slice{span: buffer, range: range};
						break
					},
					NodeHandlePlan::Inline(range) => {
						node_data = Slice{span: buffer, range: range};
					},
				}
		}
	}
}

fn nibble_at(nibble_byte_span: Span<u8>, nibble_index: usize, padding: bool) -> u8 {
	let byte:u8 = if padding {
		*nibble_byte_span.at((nibble_index+1)/NIBBLE_PER_BYTE)
	} else {
		*nibble_byte_span.at(nibble_index/NIBBLE_PER_BYTE)
	}

	if (nibble_index % NIBBLE_PER_BYTE == 0) ^ padding {
		u8_shr(byte, 4)
	} else {
		bitand(byte, NIBBLE_BITMASK_RIGHT)
	}
}

fn nibble_at_slice(nibble_byte_slice: Slice<u8>, nibble_index: usize, padding: bool) -> u8 {
	let byte:u8 = if padding {
		*nibble_byte_slice.span.at( nibble_byte_slice.range.start + ((nibble_index+1)/NIBBLE_PER_BYTE) )
	} else {
		*nibble_byte_slice.span.at( nibble_byte_slice.range.start + (nibble_index/NIBBLE_PER_BYTE))
	}

	if (nibble_index % NIBBLE_PER_BYTE == 0) ^ padding {
		u8_shr(byte, 4)
	} else {
		bitand(byte, NIBBLE_BITMASK_RIGHT)
	}
}

fn nibble_partial_eq(buffer, nibble_slice_plan, key, key_nibble_offset) -> bool {

	if (nibble_slice_plan.range.end == nibble_slice_plan.range.start){
		return true
	}

	if !nibble_partial_len_eq(buffer, nibble_slice_plan, key, key_nibble_offset){
		return false
	}

	let nibble_length:usize = if nibble_slice_plan.padding {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE - 1
	} else {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
	}

	let mut eq = true;
	let mut itr = 0;
	loop{
		if itr == nibble_length{
			break;
		}

		if !(
				nibble_at_slice(Slice{span: buffer, range: nibble_slice_plan.range}, itr, nibble_slice_plan.padding)
				==
				nibble_at(key, itr + key_nibble_offset, false)
			)
			{
			eq == false;
			break;
		}
	}
	eq

}
fn nibble_partial_starts_with(buffer, nibble_slice_plan, key, key_nibble_offset) -> bool {
	// remaining key nibble length should be greater than the nibble slice length
	if (nibble_slice_plan.range.end == nibble_slice_plan.range.start){
		return key.len() == key_nibble_offset
	}

	// if key length is 0 and it reaches here then lens are diff
	if key.len() == 0 {
		return false
	}

	let nibble_length = if nibble_slice_plan.padding {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE - 1
	} else {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
	}

	let key_length = (key.len() * NIBBLE_PER_BYTE) - key_nibble_offset;
	if nibble_length > key_length{
		return false
	}

	let mut eq = true;
	let mut itr = 0;
	loop{
		if itr == nibble_length{
			break;
		}

		if !(
				nibble_at_slice(Slice{span: buffer, range: nibble_slice_plan.range}, itr, nibble_slice_plan.padding)
				==
				nibble_at(key, itr + key_nibble_offset, false)
			)
			{
			eq == false;
			break;
		}
	}
	eq

}



fn nibble_partial_len_eq(buffer, nibble_slice_plan, key, key_nibble_offset) -> bool {
	if (nibble_slice_plan.range.end == nibble_slice_plan.range.start){
		return key.len() == key_nibble_offset
	}

	// if key length is 0 and it reaches here then lens are diff
	if key.len() == 0 {
		return false
	}

	let nibble_length = if nibble_slice_plan.padding {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE - 1
	} else {
		(nibble_slice_plan.range.end - nibble_slice_plan.range.start) * NIBBLE_PER_BYTE
	}

	let key_length = (key.len() * NIBBLE_PER_BYTE) - key_nibble_offset;
	nibble_length == key_length

}

fn load_value(
	buffer: Span<u8>
	v: ValuePlan,
) -> Result<Slice<u8>, felt252> {
	match v {
		ValuePlan::Inline(value_plan) => Ok(Slice{span: buffer, range: value_plan}),
		ValuePlan::Node(hash) => { Ok(get_node(hash))
			} else {
				Err('Incomplete Database')
			},
	}
}

fn get_node(hash, hashes, buffer, buffer_index)-> Option<Slice<u8>, felt252>{
	let mut res: Option<Slice<u8>> = None;
	let mut itr = 0;
	let number_of_hashes = hashes.len()/HASH_LENGTH;
	if hashes.len() != buffer_index.len(){
		return None
	}
	let mut eq = true;
	let mut itr2=0;
	loop{
		if itr == number_of_hashes{
			break;
		}

		itr2 = 0;

		loop{
			if itr2 == HASH_LENGTH{
				break;
			}

			if !(*hash.at(itr2) == *hashes.at(itr*HASH_LENGTH + itr2)){
				eq = false;
				break;
			}

			itr2=itr2+1;
		}

		if eq {
			if itr == (number_of_hashes - 1) {
				res = Some(Slice{span: buffer, range: Range{start: *buffer_index.at(itr),end: buffer.len()}});
			} else {
				res = Some(Slice{span: buffer, range: Range{start: *buffer_index.at(itr),end: *buffer_index.at(itr+1)}});
			}
			break;
		} else {
			eq = true;
		}

		itr= itr+1;
	}
	res
}

fn parse_encoded_node(buffer: Slice<u8>) -> Result<, felt252>{

    // let encoded_node: Slice<u8> = buffer;
    let mut offset: usize = buffer.range.start;
	// TODO
	// At the end of parsing the node maybe we could check if it is at the end of the slice
    let header = decode_header(buffer, ref offset)?;

    let contains_hash = match header {
        NodeHeader::HashedValueBranch(_) | NodeHeader::HashedValueLeaf(_) => {true},
        _ => false,
    };

    let branch_has_value = match header{
        NodeHeader::Branch(has_value, _) => has_value,
        _ => true,
    }

    match header {
			NodeHeader::Null(()) => Ok(NodePlan::Empty(())),
			NodeHeader::HashedValueBranch(nibble_count) => {
				let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
				// check that the padding is valid (if any)
				if padding && (bitand(*buffer.at(offset), NIBBLE_BITMASK_LEFT) != 0) {
					return Err('Bad Format');
				}
                let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
				let partial = Range {start: offset, end: offset + partial_bytes_length};
                offset = offset + partial_bytes_length;
				let partial_padding = nibble_count%NIBBLE_PER_BYTE;
				let bitmap_range = Range {start: offset, end: offset + BITMAP_LENGTH};
                offset = offset + BITMAP_LENGTH;
				let bitmap = bitmap_decode(buffer, bitmap_range)?;
				let value = if branch_has_value {
					Some(if contains_hash {
						let vp = ValuePlan::Node(Range {start: offset, end: offset + HASH_LENGTH})
                        offset = offset + HASH_LENGTH;
                        vp
					} else {
						let count = compact_u32_decode(buffer, ref offset)?;
						let vp = ValuePlan::Inline(Range {start: offset, end: offset + count});
                        offset = offset + count;
                        vp
					})
				} else {
					None
				};
				
                let mut children = ArrayTrait::<Option<NodeHandlePlan>>::new();
                let mut itr: usize = 0
				loop {
                    if itr == NIBBLE_LENGTH{
                        break;
                    }
					if bitmap_value_at(bitmap, itr) {
						let count = compact_u32_decode(buffer, ref offset)?;
						let range = Range {start: offset, end: offset + count};
                        offset = offset + count;
						children.append(Some(if count == HASH_LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						}));
					} else {
                        children.append(None);
                    }
                    itr = itr + 1;
				}
				Ok(NodePlan::NibbledBranch {
					partial: NibbleSlicePlan{range: partial, padding: partial_padding},
					value: value,
					children: children,
				})
			},
            NodeHeader::Branch((_, nibble_count)) => {
				let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
				// check that the padding is valid (if any)
				if padding && (bitand(*buffer.at(offset), NIBBLE_BITMASK_LEFT) != 0) {
					return Err('Bad Format');
				}
                let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
				let partial = Range {start: offset, end: offset + partial_bytes_length};
                offset = offset + partial_bytes_length;
				let partial_padding = nibble_count%NIBBLE_PER_BYTE;
				let bitmap_range = Range {start: offset, end: offset + BITMAP_LENGTH};
                offset = offset + BITMAP_LENGTH;
				let bitmap = bitmap_decode(buffer, bitmap_range)?;
				let value = if branch_has_value {
					Some(if contains_hash {
						let vp = ValuePlan::Node(Range {start: offset, end: offset + HASH_LENGTH})
                        offset = offset + HASH_LENGTH;
                        vp
					} else {
						let count = compact_u32_decode(buffer, ref offset)?;
						let vp = ValuePlan::Inline(Range {start: offset, end: offset + count});
                        offset = offset + count;
                        vp
					})
				} else {
					None
				};
				
                let mut children = ArrayTrait::<Option<NodeHandlePlan>>::new();
                let mut itr: usize = 0
				loop {
                    if itr == NIBBLE_LENGTH{
                        break;
                    }
					if bitmap_value_at(bitmap, itr) {
						let count = compact_u32_decode(buffer, ref offset)?;
						let range = Range {start: offset, end: offset + count};
                        offset = offset + count;
						children.append(Some(if count == HASH_LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						}));
					} else {
                        children.append(None);
                    }
                    itr = itr + 1;
				}
				Ok(NodePlan::NibbledBranch {
					partial: NibbleSlicePlan{range: partial, padding: partial_padding},
					value: value,
					children: children.span(),
				})
			},
			NodeHeader::HashedValueLeaf(nibble_count) => {
				let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
				// check that the padding is valid (if any)
				if padding && (bitand(*buffer.at(offset), NIBBLE_BITMASK_LEFT) != 0) {
					return Err('Bad Format');
				}
                let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
				let partial = Range {start: offset, end: offset + partial_bytes_length};
                offset = offset + partial_bytes_length;
				let partial_padding = nibble_count%NIBBLE_PER_BYTE;
				let value = if contains_hash {
                    let vp = ValuePlan::Node(Range {start: offset, end: offset + HASH_LENGTH})
                    offset = offset + HASH_LENGTH;
                    vp
                } else {
                    let count = compact_u32_decode(buffer, ref offset)?;
                    let vp = ValuePlan::Inline(Range {start: offset, end: offset + count});
                    offset = offset + count;
                    vp
                };

				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan{range: partial, padding: partial_padding},
					value,
				})
			},
            NodeHeader::Leaf(nibble_count) => {
				let padding = ((nibble_count % NIBBLE_PER_BYTE) != 0);
				// check that the padding is valid (if any)
				if padding && (bitand(*buffer.at(offset), NIBBLE_BITMASK_LEFT) != 0) {
					return Err('Bad Format');
				}
                let partial_bytes_length = ((nibble_count + (NIBBLE_PER_BYTE - 1)) / NIBBLE_PER_BYTE);
				let partial = Range {start: offset, end: offset + partial_bytes_length};
                offset = offset + partial_bytes_length;
				let partial_padding = nibble_count%NIBBLE_PER_BYTE;
				let value = if contains_hash {
                    let vp = ValuePlan::Node(Range {start: offset, end: offset + HASH_LENGTH})
                    offset = offset + HASH_LENGTH;
                    vp
                } else {
                    let count = compact_u32_decode(buffer, ref offset)?;
                    let vp = ValuePlan::Inline(Range {start: offset, end: offset + count});
                    offset = offset + count;
                    vp
                };

				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan{range: partial, padding: partial_padding},
					value,
				})
			},
		}

}

fn bitmap_decode(buffer: Slice<u8>, range: Range) -> u16 {
	assert((range.end - range.start) == 2, 'wrong bitmap len' );
	let value = u16_decode(Slice{span: buffer.span, range: range});
	if value ==0 {
		panic_with_felt252('Bitmap without a child');
	} else {
		value
	}
}

fn u16_decode(slice: Slice<u8>) -> u16 {
	assert((slice.range.end - slice.range.start) == 2, 'wrong u16 len' );

	// Little endian encoding
	// first byte is low
	let first: u16 = Into::<u8, u16>::into(*slice.span.at(slice.range.start));
	// second byte is high
	let second: u16 = Into::<u8, u16>::into(*slice.span.at(slice.range.start + 1));

	let res:u16 = first + (second * 256);
	res

}

fn u32_decode(slice: Slice<u8>) -> u32 {
	assert((slice.range.end - slice.range.start) == 4, 'wrong u32 len' );

	// Little endian encoding
	let first: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start));
	let second: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 1));
	let third: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 2));
	let fourth: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 3));

	let res:u32 = first + (second * 256) + (third * 256 * 256) + (fourth * 256 * 256 * 256);
	res

}

fn bitmap_value_at(bitmap: u16, itr: usize) -> bool {
	bitand(bitmap, TryInto::<u128,u16>::try_into(shl(1_u16.into(), itr.into())).unwrap()) != 0
}

fn compact_u32_decode(buffer: Slice<u8>, ref offset) -> Result<u32,felt252> {
	let prefix: u8 = *buffer.span.at(offset);
	offset = offset + 1;
	// let prefix = input.read_byte()?;

	let selector: u8 = prefix % 4;

	if selector == 0 {
		return Ok(Into::<u8, u32>::into(prefix)/4);
	} else if selector ==1 {

		// Little endian encoding
		// first byte is low - prefix
		let first: u32 = Into::<u8, u32>::into(prefix);
		// second byte is high - the following byte
		let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
		offset = offset + 1;

		let x: u32 = (first + (second * 256))/4;

		if x > 0x3F && x <= 0x3FFF {
			return Ok(x)
		} else {
			return Err('Bad compact u32 enc');
		}
	} else if selector == 2{

		// Little endian encoding
		let first: u32 = Into::<u8, u32>::into(prefix);
		let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
		offset = offset + 1;
		let third: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
		offset = offset + 1;
		let fourth: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
		offset = offset + 1;

		let x:u32 = (first + (second * 256) + (third * 256 * 256) + (fourth * 256 * 256 * 256))/4;

		if x > 0x3FFF && x <= (BoundedInt::<u32>::max()/4) {
			return Ok(x)
		} else {
			return Err('Bad compact u32 enc');
		}
	} else if selector == 3 {
		if (prefix/4) == 0 {
			// Little endian encoding
			let first: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
			offset = offset + 1;
			let second: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
			offset = offset + 1;
			let third: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
			offset = offset + 1;
			let fourth: u32 = Into::<u8, u32>::into(*buffer.span.at(offset));
			offset = offset + 1;

			let x:u32 = first + (second * 256) + (third * 256 * 256) + (fourth * 256 * 256 * 256);

			if x > (BoundedInt::<u32>::max()/4) {
				return Ok(x)
			} else {
				return Err('Bad compact u32 enc');
			}
		} else {
			return Err('Bad compact u32 enc');
		}
	}

}

fn decode_header(b: Slice<u8>, ref offset: usize) -> Result<NodeHeader, felt252> {
    let i = *b.span.at(offset);
	// TODO
    // safe inc? check against b.len()?
    offset = offset + 1;

    if i==EMPTY_TRIE{
        return Ok(NodeHeader::Null);
    }

    let masked_i = bitand(i, 0xC0);

    if masked_i == LEAF_PREFIX_MASK {
        Ok(NodeHeader::Leaf(decode_size(i, b, offset, 2)?));
    } else if masked_i == BRANCH_WITH_MASK {
        Ok(NodeHeader::Branch(true, decode_size(i, b, offset, 2)?));
    } else if masked_i == BRANCH_WITHOUT_MASK {
        Ok(NodeHeader::Branch(false, decode_size(i, b, offset, 2)?));
    } else if masked_i == EMPTY_TRIE {
        if bitand(i, 0xE0) == ALT_HASHING_LEAF_PREFIX_MASK {
            Ok(NodeHeader::HashedValueLeaf(decode_size(i, b, offset, 3)?))
        } else if bitand(i, 0xF0) == ALT_HASHING_BRANCH_WITH_MASK {
            Ok(NodeHeader::HashedValueBranch(decode_size(i, b, offset, 4)?))
        } else {
            // do not allow any special encoding
            Err("Unallowed encoding".into())
        }
    }
}

fn decode_size(first: u8, b:Slice<u8>, ref offset: usize, prefix_mask: usize) -> Result<usize, felt252> {
    let max_value = u8_shr(0xff, prefix_mask);

	let mut result: usize = bitand(first, max_value).into();

    if result < max_value.into() {
		return Ok(result)
	}

    result -= 1;
	loop {
		let n = Into::<u8, usize>::into(*b.span.at(offset));
        offset = offset + 1;
		if n < 255 {
			return Ok(result + n + 1)
		}
		result += 255;
	}
}

fn u8_shr(byte: u8, n: u8) -> u8 {
	TryInto::<u128, u8>::try_into(shr(byte.into(), n.into())).unwrap()
}