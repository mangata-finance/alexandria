use alexandria_math::BitShift;
use alexandria_searching::binary_search::binary_search;
use integer::{u64_wrapping_add, BoundedInt};
use traits::{Into, TryInto};
use option::OptionTrait;
use result::ResultTrait;
use array::{ArrayTrait, SpanTrait};
use core::clone::Clone;
use alexandria_substrate::blake2b::{blake2b};
use alexandria_substrate::substrate_storage_read_proof_verifier::{convert_u8_subarray_to_felt252_array};
use core::traits::Default;
use starknet::secp256_trait::{
    Signature, recover_public_key, verify_eth_signature, Secp256PointTrait, signature_from_vrs
};
use starknet::{eth_address::U256IntoEthAddress, EthAddress};
use integer::u256;
use starknet::secp256k1::{Secp256k1Point, Secp256k1PointImpl};
use starknet::SyscallResultTrait;
use debug::PrintTrait;
use zeroable::Zeroable;
use box::BoxTrait;


// Possibly unsafe and insecure substrate storage proof verifier
// DO NOT use in production - yet :)


const VALIDATOR_ADDRESS_LEN: usize = 20;
const VALIDATOR_SIGNATURE_LEN: usize = 65;
const BEEFY_FINALITY_PROOF_VERSION: u8= 1;
const BEEFY_PAYLOAD_ID_LEN: usize =2;
const HASH_LENGTH:usize = 32;

const BEEFY_LEAF_DATA_VERSION: u8 = 0;

const KECCAK_FULL_RATE_IN_U64S: usize = 17;
const BYTES_IN_U64_WORD: usize = 8;

#[derive(Drop, Copy, PartialEq)]
struct Range{
    start: usize,
    end: usize
}

#[derive(Drop, Copy)]
struct Slice<T>{
    span: Span<T>,
    range: Range,
}

#[derive(Drop, Copy)]
struct Leaf{
    pos: u64,
    hash: u256,
}

#[derive(Drop, Copy)]
struct BeefyPayloadEntryPlan<T>{
	span: Span<T>,
    BeefyPayloadIdPlanStart: usize,
    BeefyPayloadValuePlan: Range,
}

#[derive(Drop, Copy, PartialEq, starknet::Store,)]
struct BeefyData{
	version: u8,
    block_number: u32,
    hash: u256,
    leaf_extra: u256,
	beefy_next_authority_set: BeefyAuthoritySet,
}

#[derive(Drop, Copy, PartialEq, starknet::Store)]
struct BeefyAuthoritySet {
	id: u64,
	len: u32,
	keyset_commitment: u256,
}
#[derive(Drop, Copy, PartialEq, starknet::Store)]
struct BeefyProofInfo {
	block_number: u32,
	validator_set_id: u64,
	is_proof_verification_completed: bool,
}

#[derive(Drop, Copy)]
struct BeefyProofMetadata {
	commitment_pre_hashed: u256,
	signatures_from_bitfield: Span<u8>,
	validator_set_len: u32,
	signatures_compact_len: u32,
	signatures_compact: Span<u8>,
}


impl PartialEqBeefyPayloadEntryPlan<T, impl TEq: PartialEq<T>> of PartialEq<BeefyPayloadEntryPlan<T>> {
    fn eq(lhs: @BeefyPayloadEntryPlan<T>, rhs: @BeefyPayloadEntryPlan<T>) -> bool {
		let mut eq = true;
		let mut itr:usize = 0;
		loop{
			if itr== BEEFY_PAYLOAD_ID_LEN {break;}
			if !TEq::eq((*lhs.span).at(itr+*lhs.BeefyPayloadIdPlanStart), (*rhs.span).at(itr+*rhs.BeefyPayloadIdPlanStart)) {
				eq=false;
				break;
			}
			itr=itr+1;
		};
		eq
    }
    fn ne(lhs: @BeefyPayloadEntryPlan<T>, rhs: @BeefyPayloadEntryPlan<T>) -> bool {
		let mut eq = true;
		let mut itr:usize = 0;
		loop{
			if itr== BEEFY_PAYLOAD_ID_LEN {break;}
			if !TEq::eq((*lhs.span).at(itr+*lhs.BeefyPayloadIdPlanStart), (*rhs.span).at(itr+*rhs.BeefyPayloadIdPlanStart)) {
				eq=false;
				break;
			}
			itr=itr+1;
		};
		!eq
    }
}

impl PartialOrdBeefyPayloadEntryPlan<T, impl TPartialOrd: PartialOrd<T>, impl TCopy: Copy<T>, impl TDrop: Drop<T>> of PartialOrd<BeefyPayloadEntryPlan<T>> {
	// Big Endian
    fn le(lhs: BeefyPayloadEntryPlan<T>, rhs: BeefyPayloadEntryPlan<T>) -> bool{
		!PartialOrdBeefyPayloadEntryPlan::gt(lhs, rhs)
	}
    fn ge(lhs: BeefyPayloadEntryPlan<T>, rhs: BeefyPayloadEntryPlan<T>) -> bool{
		!PartialOrdBeefyPayloadEntryPlan::lt(lhs, rhs)
	}
    fn lt(lhs: BeefyPayloadEntryPlan<T>, rhs: BeefyPayloadEntryPlan<T>) -> bool{
		let mut lt = false;
		let mut itr:usize = 0;
		loop{
			if itr== BEEFY_PAYLOAD_ID_LEN {break;}

			if TPartialOrd::lt(*lhs.span.at(itr+lhs.BeefyPayloadIdPlanStart), *rhs.span.at(itr+rhs.BeefyPayloadIdPlanStart)) {
				lt=true;
				break;
			}
			if TPartialOrd::gt(*lhs.span.at(itr+lhs.BeefyPayloadIdPlanStart), *rhs.span.at(itr+rhs.BeefyPayloadIdPlanStart)) {
				lt=false;
				break;
			}
			itr=itr+1;
		};
		lt
	}
    fn gt(lhs: BeefyPayloadEntryPlan<T>, rhs: BeefyPayloadEntryPlan<T>) -> bool{
		let mut gt = false;
		let mut itr:usize = 0;
		loop{
			if itr== BEEFY_PAYLOAD_ID_LEN {break;}

			if TPartialOrd::gt(*lhs.span.at(itr+lhs.BeefyPayloadIdPlanStart), *rhs.span.at(itr+rhs.BeefyPayloadIdPlanStart)) {
				gt=true;
				break;
			}
			if TPartialOrd::lt(*lhs.span.at(itr+lhs.BeefyPayloadIdPlanStart), *rhs.span.at(itr+rhs.BeefyPayloadIdPlanStart)) {
				gt=false;
				break;
			}
			itr=itr+1;
		};
		gt
	}
}

fn decode_paradata(para_data: Span<u8>) -> (u32, Span<u8>){
	assert(para_data.len()>=5, 'bad para_data len');
	let mut offset:usize=0;

	let para_id = u32_decode(Slice{span: para_data, range: Range{start: offset, end:offset+4}});
	offset=offset+4;

	let para_head_len = compact_u32_decode(para_data, ref offset).expect('para_head_len decodes');
	assert((offset+para_head_len) == para_data.len(), 'offset not at para_data end');
	(para_id, para_data.slice(offset, para_head_len))

}

fn merkelize_for_merkle_root(hashed_leaves: Span<u256>) -> u256
{
	let mut next = match merkelize_row(hashed_leaves) {
		Result::Ok(root) => {return root;},
		Result::Err(next) => {
			if next.is_empty() {
				return 0_u256;
			} else {
				next
			}
		},
	};

	loop {

		match merkelize_row(next.span()) {
			Result::Ok(root) => {break root;},
			Result::Err(t) => {
				next = t;
			},
		};
	}

}

fn merkelize_row(
	mut row: Span<u256>,
) -> Result<u256, Array<u256>>
{
	let mut next: Array<u256> = array![];
	let mut itr: usize =0;

	let res: Result<u256, ()> = loop {

		let a = row.pop_front();
		let b = row.pop_front();

		if a.is_some() && b.is_some(){
			let merge_hash_le: u256 = keccak_u256s_be_inputs(array![*a.expect('is_some checked'), *b.expect('is_some checked')].span());
			let hash = u256_byte_reverse(merge_hash_le);

			next.append(hash);
		} 
		else if a.is_some() && b.is_none(){
			// Odd number of items. Promote the item to the upper layer.
			if !next.is_empty() {next.append(*a.expect('is_some checked'));}
			// Last item = root.
			else{break Result::Ok(*a.expect('is_some checked'));};
			}
		else {
			// Finish up, no more items.
			break Result::Err(());
		};
	};

	match res {
		Result::Ok(o) => {Result::Ok(o)},
		Result::Err(_) => {Result::Err(next)}
	}

}

fn get_hashes_from_items(buffer: Span<u8>, item_lengths: Span<usize>) -> Result<Array<u256>, felt252>{
	
	let item_lengths_len = item_lengths.len();
	if item_lengths_len == 0{
		return Result::Err('No items to hash');
	}

	let buffer_len = buffer.len();
	if buffer_len == 0{
		return Result::Err('No items to hash');
	}

	let mut offset: usize=0;
	let mut hashes: Array<u256> = array![];
	let mut itr: usize =0 ;

	let maybe_err: Result<(), felt252> = loop{
		if itr==item_lengths_len{break Result::Ok(());}
		let item_len = *item_lengths.at(itr);

		if offset + item_len > buffer_len{break Result::Err('offset beyond buffer len');}

		let hash_le: u256 = keccak_le(Slice{span: buffer, range: Range{start:offset, end: offset+item_len}});
		let hash: u256 = u256_byte_reverse(hash_le);

		hashes.append(hash);

		offset=offset+item_len;

		itr=itr+1;
	};

	match maybe_err {
		Result::Ok(_) => {},
		Result::Err(e) => {return Result::Err(e);}
	};

	if buffer_len != offset{
		return Result::Err('offset not at buffer end');
	}

	Result::Ok(hashes)

}

fn verify_merkle_proof(
	root: u256,
	proof: Span<u256>,
	number_of_leaves: usize,
	leaf_index: usize,
	leaf_hash: u256,
) -> bool
{
	if leaf_index >= number_of_leaves {
		return false;
	}

	let mut itr: usize = 0;
	let mut hash: u256 = leaf_hash;
	let mut position = leaf_index;
	let mut width = number_of_leaves;

	loop{
		if itr==proof.len(){break;}

		if position % 2 == 1 || position + 1 == width {
			let merge_hash_le: u256 = keccak_u256s_be_inputs(array![*proof.at(itr), hash].span());
			hash = u256_byte_reverse(merge_hash_le);
		} else {
			let merge_hash_le: u256 = keccak_u256s_be_inputs(array![hash, *proof.at(itr)].span());
			hash = u256_byte_reverse(merge_hash_le);
		}

		position /= 2;
		width = ((width - 1) / 2) + 1;

		itr=itr+1;
	};

	root == hash
}

fn encoded_leaf_to_leaf(buffer: Span<u8>) -> Result<BeefyData,felt252>{
	let mut offset: usize = 0;

	if buffer.len().is_zero(){
		return Result::Err('null encoded leaf');
	}

	let leaf_data_version: u8 = *buffer.at(offset);
	offset=offset+1;

	if leaf_data_version != BEEFY_LEAF_DATA_VERSION{
		return Result::Err('Bad beefy leaf data version');
	}

	let block_number: u32 = u32_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 4}});
	offset=offset + 4;

	let hash = *hashes_to_u256s(buffer.slice(offset, HASH_LENGTH)).expect('Should u256').at(0);
	offset=offset + HASH_LENGTH;

	let next_autority_set_id: u64 = u64_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 8}});
	offset=offset + 8;

	let next_autority_set_len: u32 = u32_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 4}});
	offset=offset + 4;

	let next_autority_set_commitment: u256 = *hashes_to_u256s(buffer.slice(offset, HASH_LENGTH)).expect('Should u256').at(0);
	offset=offset + HASH_LENGTH;

	let leaf_extra = *hashes_to_u256s(buffer.slice(offset, HASH_LENGTH)).expect('Should u256').at(0);
	offset=offset + HASH_LENGTH;

	let beefy_next_authority_set: BeefyAuthoritySet = BeefyAuthoritySet {
		id: next_autority_set_id,
		len: next_autority_set_len,
		keyset_commitment: next_autority_set_commitment,
	};

	let beefy_data: BeefyData =BeefyData{
		version: leaf_data_version,
		block_number: block_number,
		hash: hash,
		leaf_extra: leaf_extra,
		beefy_next_authority_set: beefy_next_authority_set,
	};

	Result::Ok(beefy_data)
}

fn encoded_opaque_leaves_to_leaves(buffer: Span<u8>) -> Result<Array<BeefyData>,felt252>{
	let mut offset: usize = 0;

	let number_leaves: usize = compact_u32_decode(buffer, ref offset)?;

	let mut leaves: Array<BeefyData> = array![];
	let mut itr: usize =0;
	let maybe_err: Result<(),felt252> = loop{
		if itr == number_leaves{break Result::Ok(());}
		let leaf_length = match compact_u32_decode(buffer, ref offset){
					Result::Ok(l)=> {l},
					Result::Err(e) => {break Result::Err(e);}
				};

		let leaf: BeefyData = match encoded_leaf_to_leaf(buffer.slice(offset, leaf_length)){
					Result::Ok(l)=> {l},
					Result::Err(e) => {break Result::Err(e);}
				};
		leaves.append(leaf);
		offset = offset + leaf_length;
		itr=itr+1;
	};

	match maybe_err {
		Result::Ok(_) => {},
		Result::Err(e) => {return Result::Err(e);}
	};

	if offset!=buffer.len(){
		return Result::Err('offset not at buffer end');
	}
	Result::Ok(leaves)
}

fn encoded_opaque_leaves_to_hashes(buffer: Span<u8>) -> Result<Array<u256>,felt252>{
	let mut offset: usize = 0;

	let number_leaves: usize = compact_u32_decode(buffer, ref offset)?;

	let mut hashes: Array<u256> = array![];
	let mut itr: usize =0;
	let maybe_err: Result<(),felt252> = loop{
		if itr == number_leaves{break Result::Ok(());}
		let leaf_length = match compact_u32_decode(buffer, ref offset){
					Result::Ok(l)=> {l},
					Result::Err(e) => {break Result::Err(e);}
				};

		let hash_le: u256 = keccak_le(Slice{span: buffer, range: Range{start:offset, end: offset+leaf_length}});
		let hash: u256 = u256_byte_reverse(hash_le);
		hashes.append(hash);
		offset = offset + leaf_length;
		itr=itr+1;
	};

	match maybe_err {
		Result::Ok(_) => {},
		Result::Err(e) => {return Result::Err(e);}
	};

	if offset!=buffer.len(){
		return Result::Err('offset not at buffer end');
	}
	Result::Ok(hashes)
}

// The hashes in leaves_hashes must be BE
fn verify_mmr_leaves_proof(mmr_root:u256, encoded_mmr_leaves_proof: Span<u8>, leaves_hashes_be_u256s: Span<u256>) -> Result<(),felt252>{

	let leaves_hashes_len:usize = leaves_hashes_be_u256s.len();

	let mut offset:usize = 0;

	let buffer = encoded_mmr_leaves_proof;

	let leaf_indices_len:usize = compact_u32_decode(buffer, ref offset)?;
	let leaf_indices: Span<u64> = read_u64_array(buffer, ref offset, leaf_indices_len).span();

	if leaf_indices_len != leaves_hashes_len{
		return Result::Err('indices_len hashes_len mismatch');
	}

	if !is_array_sorted_asc_strict(leaf_indices){
		return Result::Err('Unsorted proof leaf indices');
	};

	let mut leaves: Array<Leaf> = array![];

	let mut itr: usize = 0;

	loop{
		if itr==leaf_indices_len{
			break;
		};

		leaves.append(Leaf{pos: leaf_index_to_pos(*leaf_indices.at(itr)), hash: *leaves_hashes_be_u256s.at(itr)});
		itr=itr+1;
	};

	if !is_array_sorted_asc_strict(leaf_indices){
		return Result::Err('Unsorted proof leaf indices');
	};
	
	let leaf_count: u64 = u64_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 8}});
	offset=offset + 8;

	let items_len:usize = compact_u32_decode(buffer, ref offset)?;
	let proof_items = buffer.slice(offset, items_len*HASH_LENGTH);
	offset=offset+(items_len*HASH_LENGTH);

	if offset != buffer.len(){
		return Result::Err('offset not at buffer end');
	}

	let mmr_size: u64 = mmr_size_from_leaf_count(leaf_count);

	let proof_items_be_u256 = hashes_to_u256s(proof_items)?;
		
	let calculated_root_be_u256 = calculate_root(leaves.span(), mmr_size, proof_items_be_u256.span())?;

	if mmr_root == calculated_root_be_u256 {
		return Result::Ok(());
	} else {
		return Result::Err('Mmr root mismatch');
	}

	// Result::Err('Debug')
}

fn bagging_peaks_hashes(peaks_hashes: Span<u256>) -> Result<u256, felt252> {
	let peaks_hashes_len: usize = peaks_hashes.len();

	if peaks_hashes_len.is_zero(){
		return Result::Err('No peaks to bag');
	}
	if peaks_hashes_len == 1{
		return Result::Ok(*peaks_hashes.at(0));
	}

	let mut acc: u256 = *peaks_hashes.at(peaks_hashes_len - 1);
	let mut itr: usize = peaks_hashes_len - 2;

	loop{

		let merge_hash_le: u256 = keccak_u256s_be_inputs(array![acc, *peaks_hashes.at(itr)].span());
		acc = u256_byte_reverse(merge_hash_le);

		if itr == 0 {break;}
		itr = itr -1;
	};

	Result::Ok(acc)

}

fn calculate_peaks_hashes(mut leaves: Span<Leaf>, mmr_size: u64, mut proof_items: Span<u256>) -> Result<Array<u256>, felt252>{

	if leaves.is_empty(){
		return Result::Err('No leaves to verify');
	}

	let mut itr: usize =0;

	let maybe_err: Result<(), felt252> = loop{
		if itr==leaves.len(){break Result::Ok(());}
		if pos_height_in_tree(*leaves.at(itr).pos) > 0{
			break Result::Err('Leaves have non-zero height');
		}
		itr = itr +1;
	};

	match maybe_err {
		Result::Ok(_) => {},
		Result::Err(e) => {return Result::Err(e);}
	};

	if mmr_size == 1 && leaves.len() == 1 && (*leaves.at(0).pos).is_zero(){
		return Result::Ok(array![*leaves.at(0).hash]);
	}

	let peaks = get_peaks(mmr_size);
	let mut peaks_hashes: Array<u256> = array![];

	itr=0;

	let maybe_err: Result<(),felt252> = loop{
		if itr == peaks.len(){break Result::Ok(());}
		let leaves_for_peak = get_leaves_for_peak(ref leaves, *peaks.at(itr));
		let mut peak_root: u256 = 0; //dummy init
		if leaves_for_peak.len() == 1 && *leaves_for_peak.at(0).pos == *peaks.at(itr){
				peak_root = *leaves_for_peak.at(0).hash;
			}
			else if leaves_for_peak.is_empty(){
				match proof_items.pop_front() {
					Option::Some(h) => {
						peak_root = *h;
					},
					Option::None(()) => {
						break Result::Ok(());
					},
				};
			} else {
				match calculate_peak_root(leaves_for_peak, *peaks.at(itr), ref proof_items){
					Result::Ok(r)=> {peak_root = r},
					Result::Err(e) => {break Result::Err(e);}
				}
			};
		peaks_hashes.append(peak_root);
		itr = itr +1;
	};

	match maybe_err {
		Result::Ok(_) => {},
		Result::Err(e) => {return Result::Err(e);}
	};

	if !leaves.is_empty(){
		return Result::Err('leaves not empty at end');
	}

	match proof_items.pop_front() {
					Option::Some(h) => {
						peaks_hashes.append(*h);
					},
					Option::None(()) => {
					},
				};

	match proof_items.pop_front() {
					Option::Some(h) => {
						return Result::Err('Corrupted proof');
					},
					Option::None(()) => {
					},
				};

	Result::Ok(peaks_hashes)

}

fn calculate_peak_root(leaves: Span<Leaf>, peak_pos: u64, ref proof_items: Span<u256>) -> Result<u256, felt252>{

	let mut itr: usize =0;
	let mut queue: Array<(u64, u256, u32)> = array![];

	loop{
		if itr == leaves.len(){break;}
		let leaf = *leaves.at(itr);
		queue.append((leaf.pos,leaf.hash,0_u32));
		itr = itr + 1;
	};

	let result: Result<u256, felt252> = loop{
		match queue.pop_front() {
			Option::Some((pos, item, height)) => {
				if pos == peak_pos {
					if queue.is_empty() {
						break Result::Ok(item);
					} else {
						break Result::Err('Corrupted proof');
					}
				}
				// calculate sibling
				let next_height = pos_height_in_tree(pos + 1);
				let (sib_pos, parent_pos) = {
					let sibling_offset = sibling_offset(height);
					if next_height > height {
						// implies pos is right sibling
						(pos - sibling_offset, pos + 1)
					} else {
						// pos is left sibling
						(pos + sibling_offset, pos + parent_offset(height))
					}
				};

				let mut sibling_item: u256 = 0_u256; // dummy init
				let mut is_sibling_item_in_queue: bool = false;
				match queue.get(0){
					Option::Some(v) => {
						let (s_pos, _, _) = *v.unbox();
						if s_pos==sib_pos {
							is_sibling_item_in_queue = true;
						}
					},
					Option::None(()) => {
					},
				};

				if is_sibling_item_in_queue {
					match queue.pop_front() {
						Option::Some((_, s_item, _)) => {
							sibling_item = s_item;
						},
						Option::None(()) => {
							break Result::Err('queue.get(0) exists');
						},
					}
				} else {
					match proof_items.pop_front() {
						Option::Some(h) => {
							sibling_item = *h;
						},
						Option::None(()) => {
							break Result::Err('Corrupted proof');
						},
					}
				}

				let mut parent_item: u256 = 0_u256;
				if next_height > height{
					let merge_hash_le: u256 = keccak_u256s_be_inputs(array![sibling_item, item].span());
					parent_item = u256_byte_reverse(merge_hash_le);
				} else {
					let merge_hash_le: u256 = keccak_u256s_be_inputs(array![item, sibling_item].span());
					parent_item = u256_byte_reverse(merge_hash_le);
				};

				if parent_pos <= peak_pos{
					queue.append((parent_pos, parent_item, height + 1));
				} else {
					break Result::Err('Corrupted proof');
				}

			},
			Option::None(()) => {
				break Result::Err('Corrupted proof');
			},
		};
	};
	result

}

fn get_leaves_for_peak(ref leaves: Span<Leaf>, peak_pos: u64) -> Span<Leaf>{
	let mut itr: usize = 0;
	loop{
		if itr == leaves.len() {break;}
		if *leaves.at(itr).pos > peak_pos{
			break;
		}
		itr = itr + 1;
	};
	let leaves_for_peak = leaves.slice(0, itr);
	leaves = leaves.slice(itr, leaves.len() - itr);
	leaves_for_peak
}

fn calculate_root(leaves: Span<Leaf>, mmr_size: u64, proof_items: Span<u256>) -> Result<u256, felt252>{
	
	let peaks_hashes_be_u256: Array<u256> = calculate_peaks_hashes(leaves, mmr_size, proof_items)?;
	
    bagging_peaks_hashes(peaks_hashes_be_u256.span())
	// Result::Err('Debug')
}

fn u8_eth_addresses_to_u256(u8_addresses: Span<u8>) -> Array<u256>{
	let number_of_validators = u8_addresses.len()/VALIDATOR_ADDRESS_LEN;
	assert(number_of_validators*VALIDATOR_ADDRESS_LEN==u8_addresses.len(), 'bad validator_addresses len');

	let mut u256_addresses: Array<u256> = array![];

	let mut itr: usize =0;
	loop{
		if itr==number_of_validators{break;}

		let mut a_low:u128 = 0;
		let mut vitr: usize =0;

		loop{
			if vitr==16{
				break;
			}

			a_low = Into::<u8,u128>::into(*u8_addresses.at(4+vitr+itr*VALIDATOR_ADDRESS_LEN)) + a_low*256_u128;

			vitr=vitr+1;
		};

		let a_high: u128 = Into::<u8,u128>::into(*u8_addresses.at(3+itr*VALIDATOR_ADDRESS_LEN)) + ((Into::<u8,u128>::into(*u8_addresses.at(2+itr*VALIDATOR_ADDRESS_LEN)) + ((Into::<u8,u128>::into(*u8_addresses.at(1+itr*VALIDATOR_ADDRESS_LEN)) + (Into::<u8,u128>::into(*u8_addresses.at(0+itr*VALIDATOR_ADDRESS_LEN)) * 256_u128)) *256_u128)) * 256_u128);

		u256_addresses.append(u256{high:a_high, low:a_low});
		itr=itr+1;
	};
	u256_addresses
}

// Should not return a result, should just panic on bad len
fn hashes_to_u256s(hashes: Span<u8>) -> Result<Array<u256>, felt252>{
	let hashes_len: usize = hashes.len()/HASH_LENGTH;
	if (hashes_len*HASH_LENGTH) != hashes.len(){
		return Result::Err('Bad hashes len');
	}

	let mut itr:usize = 0;
	let mut val_u256:u256 = 0;
	let mut be_u256s: Array<u256> = array![];
	let mut citr: usize = 0;

	loop{
		if itr == hashes_len{break;}
		val_u256=0;
		citr = 0;

		loop {
			if citr == HASH_LENGTH{break;}
				val_u256 = Into::<u8,u256>::into(*hashes.at(itr*HASH_LENGTH+citr)) + val_u256*256_u256;
			citr=citr+1;
		};

		be_u256s.append(val_u256);
		itr=itr+1;
	};
	Result::Ok(be_u256s)
}

fn all_ones(num: u64) -> bool {
	num != 0 && (count_zeros(num) == leading_zeros(num))
}

fn jump_left(pos: u64) -> u64 {
	let bit_length = 64 - leading_zeros(pos);
	let most_significant_bits = BitShift::<u64>::shl(1, (bit_length - 1).into());
	pos - (most_significant_bits - 1)
}

fn pos_height_in_tree(mut pos: u64) -> u32 {
    pos += 1;
    
    loop  {
		if all_ones(pos) {break;}
        pos = jump_left(pos);
    };

    64 - leading_zeros(pos) - 1
}

fn parent_offset(height: u32) -> u64 {
	BitShift::<u32>::shl(2, height).into()
}

fn sibling_offset(height: u32) -> u64 {
    (BitShift::<u32>::shl(2, height).into()) - 1
}

fn get_peaks(mmr_size: u64) -> Array<u64> {
    let mut pos_s = ArrayTrait::<u64>::new();
    let (mut height, mut pos) = left_peak_height_pos(mmr_size);
    pos_s.append(pos);
    loop {
		if !(height > 0){break;}
        let (h, p) = match get_right_peak(height, pos, mmr_size) {
            Option::Some(peak) => peak,
            Option::None => {break;},
        };
		height = h;
		pos =p;
        pos_s.append(pos);
    };
    pos_s
}

fn get_right_peak(mut height: u32, mut pos: u64, mmr_size: u64) -> Option<(u32, u64)> {
    // move to right sibling pos
    pos += sibling_offset(height);
    // loop until we find a pos in mmr
    loop {
		if !(pos > (mmr_size - 1)) {break Option::Some((height, pos));}
        if height == 0 {
            break Option::None;
        }
        // move to left child
        pos -= parent_offset(height - 1);
        height -= 1;
    }
}

fn get_peak_pos_by_height(height: u32) -> u64 {
	(BitShift::<u32>::shl(1, (height + 1)).into()) - 2
}

fn left_peak_height_pos(mmr_size: u64) -> (u32, u64) {
    let mut height = 1;
    let mut prev_pos = 0;
    let mut pos = get_peak_pos_by_height(height);
    loop {
		if !(pos < mmr_size){break;}
        height += 1;
        prev_pos = pos;
        pos = get_peak_pos_by_height(height);
    };
    (height - 1, prev_pos)
}


/// Calculate number of peaks in the MMR.
fn number_of_peaks(no_of_leaves: u64) -> u64 {
	count_ones(no_of_leaves).into()
}

/// Calculate the total size of MMR (number of nodes).
fn mmr_size_from_leaf_count(no_of_leaves: u64) -> u64 {
	2 * no_of_leaves - number_of_peaks(no_of_leaves)
}

fn leaf_index_to_pos(index: u64) -> u64 {
    // mmr_size - H - 1, H is the height(intervals) of last peak
    leaf_index_to_mmr_size(index) - trailing_zeros(index + 1).into() - 1
}

fn leaf_index_to_mmr_size(index: u64) -> u64 {
    // leaf index start with 0
    let leaves_count = index + 1;

    // the peak count(k) is actually the count of 1 in leaves count's binary representation
    mmr_size_from_leaf_count(leaves_count)
}

fn trailing_zeros(mut n: u64) -> u32 {
	let mut trailing_zeros: u32 = 0;
	let mut itr: usize =0;
	loop{
		if itr == 64{
			break;
		}
		if (n & 1_u64).is_zero(){
			trailing_zeros = trailing_zeros +1;
			n = n /2;
		} else {
			break;
		}
		itr=itr+1;
	};
	trailing_zeros
}

fn leading_zeros(mut n: u64) -> u32 {
	let mut leading_zeros: u32 = 0;
	let mut itr: usize =0;
	loop{
		if itr == 64{
			break;
		}
		if (n & 0x8000000000000000_u64).is_zero(){
			leading_zeros = leading_zeros +1;
			n = n * 2;
		} else {
			break;
		}
		itr=itr+1;
	};
	leading_zeros
}

fn count_ones(mut n: u64) -> u32 {
    let mut count = 0;
    loop {
        if n.is_zero() {
            break count;
        }
        n = n & (n - 1);
        count += 1;
    }
}

fn count_zeros(n: u64) -> u32 {
    64_u32 - count_ones(n)
}

fn is_array_sorted_asc_strict<T, impl TDrop: Drop<T>, impl TCopy: Copy<T>, impl TPartialOrd: PartialOrd<T>,>(array: Span<T>) -> bool{

	let mut is_array_sorted_asc_strict = true;
	let mut itr:usize=1;
	let array_len = array.len();

	loop{
		if itr >= array_len{break;}

		if !TPartialOrd::gt(*array.at(itr), *array.at(itr-1)) {
			is_array_sorted_asc_strict = false;
			break;
		}

		itr=itr+1;
	};

	is_array_sorted_asc_strict
}

fn read_u64_array(buffer: Span<u8>, ref offset: usize, len: usize) -> Array<u64>{
	let mut leaf_indices: Array<u64> = array![];
	let mut itr:usize=0;

	loop{
		if itr == len{
			break;
		}

		let val = u64_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 8}});
		offset=offset + 8;
		
		leaf_indices.append(val);

		itr=itr+1;
	};

	leaf_indices
}

fn get_mmr_root_payload_id() -> Span<u8> {
	array![109_u8, 104_u8].span()
}

fn get_mmr_root(beefy_payloads: Span<BeefyPayloadEntryPlan<u8>>) -> Result<u256, felt252>{
	if beefy_payloads.is_empty(){
		return Result::Err('beefy_payloads is empty');
	}

	match binary_search(beefy_payloads, BeefyPayloadEntryPlan{
		span: get_mmr_root_payload_id(),
		BeefyPayloadIdPlanStart: 0_usize,
    	BeefyPayloadValuePlan: Range{start: BEEFY_PAYLOAD_ID_LEN, end: BEEFY_PAYLOAD_ID_LEN},
	}) {
		Option::Some(index) => {
			let beefy_payload: BeefyPayloadEntryPlan<u8> = *beefy_payloads.at(index);
			let beefy_payload_value_len:usize = beefy_payload.BeefyPayloadValuePlan.end - beefy_payload.BeefyPayloadValuePlan.start;
			if beefy_payload_value_len == HASH_LENGTH{
				return Result::Ok(*hashes_to_u256s(beefy_payload.span.slice(beefy_payload.BeefyPayloadValuePlan.start, beefy_payload_value_len)).expect('hashes_to_u256s works').at(0));
			} else {
				return Result::Err('mmr_root not 32 bytes long');
			}
			},
		Option::None => {return Result::Err('mmr_root not in beefy_payloads');}
	}
}

// We need to also add next validator set here to the input for when the validator set changes and we need to use the next selector
// Ideally this won't be inputs as such, just accessors
fn get_lean_beefy_proof_metadata(buffer: Span<u8>) -> Result<(BeefyProofMetadata, BeefyProofInfo, Array<BeefyPayloadEntryPlan<u8>>),felt252>{

let mut offset:usize = 0;

if *buffer.at(offset)!=BEEFY_FINALITY_PROOF_VERSION{
    return Result::Err('Version not supported');
}
offset = offset+1;

let commitment_start: usize = offset;

let number_of_payload_entries = compact_u32_decode(buffer, ref offset)?;

let mut beefy_payloads = ArrayTrait::<BeefyPayloadEntryPlan<u8>>::new();

let mut itr:usize =0;
let maybe_err: Result<(),felt252> = loop{
    if itr ==number_of_payload_entries{
        break Result::Ok(());
    }

    let beefy_payload_id_plan = offset;
    offset=offset+BEEFY_PAYLOAD_ID_LEN;

	let beefy_payload_value_len = match compact_u32_decode(buffer, ref offset){
		Result::Ok(v)=>{v},
		Result::Err(e)=>{
			break Result::Err(e);
			}
	};
    let beefy_payload_value_plan = Range{start: offset, end: offset+beefy_payload_value_len};
    offset=offset+beefy_payload_value_len;

    beefy_payloads.append(BeefyPayloadEntryPlan{span: buffer, BeefyPayloadIdPlanStart:beefy_payload_id_plan, BeefyPayloadValuePlan: beefy_payload_value_plan});

    itr=itr+1;
};

match maybe_err{
	Result::Ok(())=>{},
	Result::Err(e)=>{return Result::Err(e);}
};

// Done traversing through the payloads

let block_number = u32_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 4}});
offset=offset + 4;

let validator_set_id = u64_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 8}});
offset=offset + 8;

let commitment_end: usize = offset;

let commitment = Slice{span: buffer, range: Range{start:commitment_start, end:commitment_end}};
// commitment.range.start.print();
// commitment.range.end.print();

let commitment_pre_hashed_le = keccak_le(commitment);
let commitment_pre_hashed = u256_byte_reverse(commitment_pre_hashed_le);

// let mut validator_addresses = current_validator_addresses;
// let mut is_next_validator_set_id: bool = false;
// let mut is_validator_chain_broken: bool = false;

// if validator_set_id!=expected_validator_set_id{
// 	if validator_set_id==expected_validator_set_id+1{
// 		is_next_validator_set_id =true;
// 		validator_addresses = next_validator_addresses
// 	} else if validator_set_id<expected_validator_set_id{
//     	return Result::Err('Too low validator set id');
// 	} else {
//     	is_validator_chain_broken = true;
// 	}
// }

let signatures_from_bitfield_len = compact_u32_decode(buffer, ref offset)?;
let signatures_from_bitfield = Slice{span: buffer, range: Range{start: offset, end: offset+signatures_from_bitfield_len}};
offset=offset+signatures_from_bitfield_len;

// signatures_from_bitfield.range.start.print();
// signatures_from_bitfield.range.end.print();

let validator_set_len = u32_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 4}});
offset=offset + 4;


let signatures_compact_len = compact_u32_decode(buffer, ref offset)?;
let signatures_compact = Slice{span: buffer, range: Range{start: offset, end: offset+(signatures_compact_len*VALIDATOR_SIGNATURE_LEN)}};
offset=offset+(signatures_compact_len*VALIDATOR_SIGNATURE_LEN);

// signatures_compact.range.start.print();
// signatures_compact.range.end.print();

// TODO
// Add to caller
// if itr>=threshold(validator_addresses_len){
//     return Result::Err('Not enough sigs');
// }

//TODO
//Remove
// let validator_addresses=current_validator_addresses;

// let validator_addresses_len:usize = validator_addresses.len();
// let number_of_validators:usize = validator_addresses_len/VALIDATOR_ADDRESS_LEN;
// assert(number_of_validators*VALIDATOR_ADDRESS_LEN==validator_addresses_len, 'bad validator_addresses len');


// if validator_set_len!=number_of_validators{
//     return Result::Err('validator_set_len mismatch');
// }


// let mut bitfield_byte_bit_selector:u8=128;
// let mut bitfield_byte_pointer: usize=signatures_from_bitfield.range.start;
// let mut validator_count:usize=0;
// let mut bitfield_byte_offset=0;
// let mut itr =0;
// let maybe_err: Result<(),felt252> = loop{
// 	if itr ==signatures_compact_len{

// 		if bitfield_byte_pointer == signatures_from_bitfield.range.end{
// 			if bitfield_byte_bit_selector==128{
// 				if validator_count != validator_set_len{
// 					break Result::Err('Unexpected bitfield error');
// 				}
// 			} else {
// 				break Result::Err('Bitfield incorrectly terminated');
// 			}
// 		} else if bitfield_byte_pointer < signatures_from_bitfield.range.end{
// 			if validator_count > validator_set_len{
// 				break Result::Err('Unexpected bitfield error 2');
// 			}
			
// 			let mut trailing_zero_count = 0;
// 			// all in current byte from selector are 0
// 			let mut all_following_bits_in_byte_are_zero: bool = true;
// 			if bitfield_byte_bit_selector == 128{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 255_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+8;
// 			} else if bitfield_byte_bit_selector == 64{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 127_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+7;
// 			} else if bitfield_byte_bit_selector == 32{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 63_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+6;
// 			} else if bitfield_byte_bit_selector == 16{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 31_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+5;
// 			} else if bitfield_byte_bit_selector == 8{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 15_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+4;
// 			} else if bitfield_byte_bit_selector == 4{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 7_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+3;
// 			} else if bitfield_byte_bit_selector == 2{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 3_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+2;
// 			} else if bitfield_byte_bit_selector == 1{
// 				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 1_u8) != 0{
// 					all_following_bits_in_byte_are_zero = false;
// 				}
// 					trailing_zero_count=trailing_zero_count+1;
// 			}

// 			if all_following_bits_in_byte_are_zero != true{
// 				break Result::Err('Bitfield did not terminate');
// 			}

// 			bitfield_byte_pointer = bitfield_byte_pointer + 1;

// 			let mut all_following_bitfield_bytes_are_zero: bool = true;
// 			loop{
// 				if bitfield_byte_pointer == signatures_from_bitfield.range.end{
// 					break;
// 				}

// 				if *signatures_from_bitfield.span.at(bitfield_byte_pointer) != 0_u8{
// 					all_following_bitfield_bytes_are_zero = false;
// 				}
// 				trailing_zero_count=trailing_zero_count+8;

// 				bitfield_byte_pointer= bitfield_byte_pointer + 1;
// 			};

// 			if (trailing_zero_count+validator_count) < validator_set_len{
// 				break Result::Err('Unexpected bitfield error 3');
// 			}

// 			if (trailing_zero_count+validator_count) < 8{
// 				break Result::Err('Unexpected bitfield error 4');
// 			}

// 			if (trailing_zero_count+validator_count - 8) > validator_set_len{
// 				break Result::Err('Unexpected bitfield error 5');
// 			}

// 			if all_following_bitfield_bytes_are_zero != true{
// 				break Result::Err('Bitfield non-zero after last');
// 			}

// 		} else {
// 			break Result::Err('Bitfield incorrectly terminated');
// 		}

// 		break Result::Ok(());
// 	}
	
// 	match move_over_zeros(signatures_from_bitfield, ref bitfield_byte_pointer, ref bitfield_byte_bit_selector, ref validator_count){
// 		Result::Ok(())=>{},
// 		Result::Err(e)=>{break Result::Err(e);}
// 	};

// 	// DEBUG!!!
// 	// FOR BENCHMARKING!!!
// 	// TODO
// 	// REMOVE!!
// 	// let mut asdf:usize=0;
// 	// loop{
// 	// 	if asdf==2{break;}
// 	if !verify_eth_signature_pre_hashed(
// 			commitment_pre_hashed,
// 			Slice{span: buffer, range: Range{start: itr*VALIDATOR_SIGNATURE_LEN + signatures_compact_start,end: ((itr*VALIDATOR_SIGNATURE_LEN) + VALIDATOR_SIGNATURE_LEN + signatures_compact_start)}},
// 			Slice{span: validator_addresses, range: Range{start: validator_count*VALIDATOR_ADDRESS_LEN,end: ((validator_count*VALIDATOR_ADDRESS_LEN) + VALIDATOR_ADDRESS_LEN)}},
// 			)
// 			{
// 				// DEBUG!!!
// 				// FOR BENCHMARKING!!!
// 				// TODO
// 				// UNOD!!
// 		break Result::Err('Signature verification failed');
// 		// assert(false, 'Signature verification failed');
// 	}
// 	// asdf=asdf+1;
// 	// };

// 	inc_bitfield_marker_unchecked(signatures_from_bitfield, ref bitfield_byte_pointer, ref bitfield_byte_bit_selector, ref validator_count);

// 	itr=itr+1;
// };

// match maybe_err{
// 	Result::Ok(())=>{},
// 	Result::Err(e)=>{return Result::Err(e);}
// };

if signatures_compact_len<threshold(validator_set_len){
	return Result::Err('Not enough sigs');
}

if offset!=buffer.len(){
    return Result::Err('offset not at buffer end');
}

let beefy_proof_info = BeefyProofInfo {
	block_number: block_number,
	validator_set_id: validator_set_id,
	is_proof_verification_completed: false,
};

let beefy_proof_metadata = BeefyProofMetadata{
	commitment_pre_hashed: commitment_pre_hashed,
	signatures_from_bitfield: signatures_from_bitfield.span.slice(signatures_from_bitfield.range.start,signatures_from_bitfield.range.end-signatures_from_bitfield.range.start),
	 validator_set_len: validator_set_len,
	  signatures_compact_len: signatures_compact_len,
	  signatures_compact: signatures_compact.span.slice(signatures_compact.range.start,signatures_compact.range.end-signatures_compact.range.start)
};

Result::Ok((beefy_proof_metadata, beefy_proof_info, beefy_payloads))
}

fn verify_beefy_signatures(limit: Option<usize>, commitment_pre_hashed: u256,signatures_from_bitfield: Span<u8>, validator_set_len: u32, signatures_compact_len: u32, signatures_compact: Span<u8>, validator_addresses: Span<u256>)
-> Result<bool, felt252>{

let provided_signatures_compact_len = signatures_compact.len()/VALIDATOR_SIGNATURE_LEN;
assert(provided_signatures_compact_len*VALIDATOR_SIGNATURE_LEN==signatures_compact.len(), 'bad signatures_compact len');
assert(signatures_compact_len==provided_signatures_compact_len, 'signatures_compact len mismatch');


if validator_set_len!=validator_addresses.len(){
    return Result::Err('validator_set_len mismatch');
}


	let mut should_ver: bool = true;

	let mut signatures_from_bitfield_len:usize = signatures_from_bitfield.len();
	let mut bitfield_byte_bit_selector:u8=128;
	let mut bitfield_byte_pointer: usize=0;
	let mut validator_count:usize=0;
	let mut bitfield_byte_offset=0;
	let mut itr =0;
	let maybe_err: Result<(),felt252> = loop{
		if itr ==signatures_compact_len{

			if bitfield_byte_pointer == signatures_from_bitfield_len{
				if bitfield_byte_bit_selector==128{
					if validator_count != validator_set_len{
						break Result::Err('Unexpected bitfield error');
					}
				} else {
					break Result::Err('Bitfield incorrectly terminated');
				}
			} else if bitfield_byte_pointer < signatures_from_bitfield_len{
				if validator_count > validator_set_len{
					break Result::Err('Unexpected bitfield error 2');
				}
				
				let mut trailing_zero_count = 0;
				// all in current byte from selector are 0
				let mut all_following_bits_in_byte_are_zero: bool = true;
				if bitfield_byte_bit_selector == 128{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 255_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+8;
				} else if bitfield_byte_bit_selector == 64{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 127_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+7;
				} else if bitfield_byte_bit_selector == 32{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 63_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+6;
				} else if bitfield_byte_bit_selector == 16{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 31_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+5;
				} else if bitfield_byte_bit_selector == 8{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 15_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+4;
				} else if bitfield_byte_bit_selector == 4{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 7_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+3;
				} else if bitfield_byte_bit_selector == 2{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 3_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+2;
				} else if bitfield_byte_bit_selector == 1{
					if (*signatures_from_bitfield.at(bitfield_byte_pointer) & 1_u8) != 0{
						all_following_bits_in_byte_are_zero = false;
					}
						trailing_zero_count=trailing_zero_count+1;
				}

				if all_following_bits_in_byte_are_zero != true{
					break Result::Err('Bitfield did not terminate');
				}

				bitfield_byte_pointer = bitfield_byte_pointer + 1;

				let mut all_following_bitfield_bytes_are_zero: bool = true;
				loop{
					if bitfield_byte_pointer == signatures_from_bitfield_len{
						break;
					}

					if *signatures_from_bitfield.at(bitfield_byte_pointer) != 0_u8{
						all_following_bitfield_bytes_are_zero = false;
					}
					trailing_zero_count=trailing_zero_count+8;

					bitfield_byte_pointer= bitfield_byte_pointer + 1;
				};

				if (trailing_zero_count+validator_count) < validator_set_len{
					break Result::Err('Unexpected bitfield error 3');
				}

				if (trailing_zero_count+validator_count) < 8{
					break Result::Err('Unexpected bitfield error 4');
				}

				if (trailing_zero_count+validator_count - 8) > validator_set_len{
					break Result::Err('Unexpected bitfield error 5');
				}

				if all_following_bitfield_bytes_are_zero != true{
					break Result::Err('Bitfield non-zero after last');
				}

			} else {
				break Result::Err('Bitfield incorrectly terminated');
			}

			break Result::Ok(());
		}
		
		match move_over_zeros(signatures_from_bitfield, ref bitfield_byte_pointer, ref bitfield_byte_bit_selector, ref validator_count){
			Result::Ok(())=>{},
			Result::Err(e)=>{break Result::Err(e);}
		};

		// DEBUG!!!
		// FOR BENCHMARKING!!!
		// TODO
		// REMOVE!!
		// let mut asdf:usize=0;
		// loop{
		// 	if asdf==2{break;}

		if should_ver && limit.is_some() {
			let limit = limit.expect('is_some checked');
			if itr>=limit{
				should_ver=false;
			}
		}

		if should_ver{
			if !verify_eth_signature_pre_hashed_u256_address(
					commitment_pre_hashed,
					signatures_compact.slice(itr*VALIDATOR_SIGNATURE_LEN, VALIDATOR_SIGNATURE_LEN),
					*validator_addresses.at(validator_count),
					)
					{
						// DEBUG!!!
						// FOR BENCHMARKING!!!
						// TODO
						// UNOD!!
				break Result::Err('Signature verification failed');
				// assert(false, 'Signature verification failed');
			}
		};
		
		// asdf=asdf+1;
		// };

		inc_bitfield_marker_unchecked(signatures_from_bitfield, ref bitfield_byte_pointer, ref bitfield_byte_bit_selector, ref validator_count);

		itr=itr+1;
	};

	match maybe_err{
		Result::Ok(())=>{},
		Result::Err(e)=>{return Result::Err(e);}
	};

	Result::Ok(true)

}

fn move_over_zeros(bitfield: Span<u8>, ref bitfield_byte_pointer: usize, ref selector:u8, ref validator_count: usize) -> Result<(),felt252>{

	// changes to selector and bitfield_pointer must be valid
	loop{
		if (*bitfield.at(bitfield_byte_pointer) & selector) != selector{
			inc_bitfield_marker_unchecked(bitfield, ref bitfield_byte_pointer, ref selector, ref validator_count);
			if bitfield_byte_pointer>=bitfield.len(){
				break Result::Err('Bitfield ended prematurely');
			}
		} else {
			break Result::Ok(());
		};
	}
}

fn inc_bitfield_marker_unchecked(bitfield: Span<u8>, ref bitfield_byte_pointer: usize, ref selector:u8, ref validator_count: usize){
	if selector == 128{
		selector = 64;
	} else if selector == 64{
		selector = 32;
	} else if selector == 32{
		selector = 16;
	} else if selector == 16{
		selector = 8;
	} else if selector == 8{
		selector = 4;
	} else if selector == 4{
		selector = 2;
	} else if selector == 2{
		selector = 1;
	} else if selector == 1{
		bitfield_byte_pointer = bitfield_byte_pointer+1;
		selector = 128;
	}
	validator_count=validator_count+1;
}

// returns le encoded output
fn keccak_le(input: Slice<u8>) -> u256{

	let len: usize = input.range.end-input.range.start;
	let number_of_full_u64_words = len/8;

	let mut input_u64_le = ArrayTrait::<u64>::new();

	let mut itr:usize=0;
	let mut word:u64=0;
	loop{
		if itr == number_of_full_u64_words{
			break;
		}
		word = 0;

		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+7)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+6)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+5)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+4)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+3)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+2)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+1)) + word*256_u64;
		word = Into::<u8,u64>::into(*input.span.at(input.range.start + itr*8+0)) + word*256_u64;

		input_u64_le.append(word);
		itr=itr+1;
	};

	let last_input_num_bytes = len - (number_of_full_u64_words*8);
	let mut last_input_word:u64=0;
	
	itr=0;

	loop{
		if itr == last_input_num_bytes{
			break;
		}
		
		last_input_word=Into::<u8,u64>::into(*input.span.at(input.range.end-1-itr))+last_input_word*256_u64;

		itr=itr+1;
	};

	cairo_keccak(ref input_u64_le, last_input_word, last_input_num_bytes)
}

fn verify_eth_signature_pre_hashed(pre_hashed_message: u256, signature: Span<u8>, address: Span<u8>) -> bool{

	assert(address.len()==20, 'Bad address len');
	let address_u256: u256 = *u8_eth_addresses_to_u256(address).at(0);
	verify_eth_signature_pre_hashed_u256_address(pre_hashed_message, signature, address_u256)
}

fn verify_eth_signature_pre_hashed_u256_address(pre_hashed_message: u256, signature: Span<u8>, address: u256) -> bool{
	let mut r_high:u128 = 0;
	let mut r_low:u128 = 0;
	let mut s_high:u128 = 0;
	let mut s_low:u128 = 0;
	let mut a_low:u128 = 0;
	assert(signature.len()==65, 'Bad signature len');

	let mut itr: usize = 0;
	

	loop{
		if itr==16{
			break;
		}

		r_high = Into::<u8,u128>::into(*signature.at(itr)) + r_high*256_u128;
		r_low = Into::<u8,u128>::into(*signature.at(16+itr)) + r_low*256_u128;

		s_high = Into::<u8,u128>::into(*signature.at(32+itr)) + s_high*256_u128;
		s_low = Into::<u8,u128>::into(*signature.at(48+itr)) + s_low*256_u128;

		itr=itr+1;
	};

	let v:u32 = Into::<u8,u32>::into(*signature.at(64));

	let eth_signature = signature_from_vrs(v, u256{high: r_high, low: r_low }, u256{high:s_high, low:s_low});
	verify_eth_signature::<Secp256k1Point>(pre_hashed_message, eth_signature, Into::<u256, EthAddress>::into(address));
	true
}

fn array_eq_slice(a: Array<u8>, s:Slice<u8>) -> bool{
	if a.len()!=(s.range.end-s.range.start){
		return false;
	}
	let len = a.len();
	let mut is_eq:bool = true;
	let mut itr:usize =0;
	loop{
		if itr==len{break;}
		if *a.at(itr)!=*s.span.at(itr+s.range.start){
			is_eq = false;
		}
		itr=itr+1;
	};
	is_eq
}

fn u256_byte_reverse(le: u256) -> u256{
	u256{high: integer::u128_byte_reverse(le.low), low: integer::u128_byte_reverse(le.high)}
}

fn threshold(v: usize)->usize{
	if v==0{return 0;}
	let faulty = (v - 1)/3;
	v - faulty 
}

fn u32_decode(slice: Slice<u8>) -> u32 {
	assert((slice.range.end - slice.range.start) == 4, 'wrong u32 len' );

	// Little endian encoding
	let first: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start));
	let second: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 1));
	let third: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 2));
	let fourth: u32 = Into::<u8, u32>::into(*slice.span.at(slice.range.start + 3));

	let res:u32 = first + ((second + ((third + (fourth * 256)) *256)) * 256);
	res

}

fn u64_decode(slice: Slice<u8>) -> u64 {
	assert((slice.range.end - slice.range.start) == 8, 'wrong u64 len' );

	// Little endian encoding
	let first: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start));
	let second: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 1));
	let third: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 2));
	let fourth: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 3));
	let fifth: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 4));
	let sixth: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 5));
	let seventh: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 6));
	let eigth: u64 = Into::<u8, u64>::into(*slice.span.at(slice.range.start + 7));

	let res:u64 = (first + ((second + ((third + ((fourth + ((fifth + ((sixth + ((seventh + (eigth * 256)) *256)) * 256))*256)) * 256)) *256)) * 256));
	res

}

fn compact_u32_decode(buffer: Span<u8>, ref offset: usize) -> Result<u32,felt252> {
	let prefix: u8 = *buffer.at(offset);
	offset = offset + 1;

	let selector: u8 = prefix % 4;

	if selector == 0 {
		return Result::Ok(Into::<u8, u32>::into(prefix)/4);
	} else if selector ==1 {

		// Little endian encoding
		// first byte is low - prefix
		let first: u32 = Into::<u8, u32>::into(prefix);
		// second byte is high - the following byte
		let second: u32 = Into::<u8, u32>::into(*buffer.at(offset));
		offset = offset + 1;

		let x: u32 = (first + (second * 256))/4;

		if x > 0x3F && x <= 0x3FFF {
			return Result::Ok(x);
		} else {
			return Result::Err('Bad compact u32 enc');
		}
	} else if selector == 2{

		// Little endian encoding
		let first: u32 = Into::<u8, u32>::into(prefix);
		let second: u32 = Into::<u8, u32>::into(*buffer.at(offset));
		offset = offset + 1;
		let third: u32 = Into::<u8, u32>::into(*buffer.at(offset));
		offset = offset + 1;
		let fourth: u32 = Into::<u8, u32>::into(*buffer.at(offset));
		offset = offset + 1;

		let x:u32 = (first + ((second + ((third + (fourth * 256)) *256)) * 256))/4;

		if x > 0x3FFF && x <= (BoundedInt::<u32>::max()/4) {
			return Result::Ok(x);
		} else {
			return Result::Err('Bad compact u32 enc');
		}
	} else if selector == 3 {
		if (prefix/4) == 0 {
			// Little endian encoding
			let first: u32 = Into::<u8, u32>::into(*buffer.at(offset));
			offset = offset + 1;
			let second: u32 = Into::<u8, u32>::into(*buffer.at(offset));
			offset = offset + 1;
			let third: u32 = Into::<u8, u32>::into(*buffer.at(offset));
			offset = offset + 1;
			let fourth: u32 = Into::<u8, u32>::into(*buffer.at(offset));
			offset = offset + 1;

			let x:u32 = first + ((second + ((third + (fourth * 256)) *256)) * 256);

			if x > (BoundedInt::<u32>::max()/4) {
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

// Source impl

// Computes the keccak of `input` + `last_input_num_bytes` LSB bytes of `last_input_word`.
// To use this function, split the input into words of 64 bits (little endian).
// For example, to compute keccak('Hello world!'), use:
//   inputs = [8031924123371070792, 560229490]
// where:
//   8031924123371070792 == int.from_bytes(b'Hello wo', 'little')
//   560229490 == int.from_bytes(b'rld!', 'little')
//
// Returns the hash as a little endian u256.
fn cairo_keccak(ref input: Array<u64>, last_input_word: u64, last_input_num_bytes: usize) -> u256 {
    add_padding(ref input, last_input_word, last_input_num_bytes);
    starknet::syscalls::keccak_syscall(input.span()).unwrap_syscall()
}

// The padding in keccak256 is "1 0* 1".
// `last_input_num_bytes` (0-7) is the number of bytes in the last u64 input - `last_input_word`.
fn add_padding(ref input: Array<u64>, last_input_word: u64, last_input_num_bytes: usize) {
    let words_divisor = KECCAK_FULL_RATE_IN_U64S.try_into().unwrap();
    // `last_block_num_full_words` is in range [0, KECCAK_FULL_RATE_IN_U64S - 1]
    let (_, last_block_num_full_words) = integer::u32_safe_divmod(input.len(), words_divisor);
    // `last_block_num_bytes` is in range [0, KECCAK_FULL_RATE_IN_BYTES - 1]
    let last_block_num_bytes = last_block_num_full_words * BYTES_IN_U64_WORD + last_input_num_bytes;

    // The first word to append would be of the form
    //     0x1<`last_input_num_bytes` LSB bytes of `last_input_word`>.
    // For example, for `last_input_num_bytes == 4`:
    //     0x1000000 + (last_input_word & 0xffffff)
    let first_word_to_append = if last_input_num_bytes == 0 {
        // This case is handled separately to avoid unnecessary computations.
        1
    } else {
        let first_padding_byte_part = if last_input_num_bytes == 1 {
            0x100
        } else if last_input_num_bytes == 2 {
            0x10000
        } else if last_input_num_bytes == 3 {
            0x1000000
        } else if last_input_num_bytes == 4 {
            0x100000000
        } else if last_input_num_bytes == 5 {
            0x10000000000
        } else if last_input_num_bytes == 6 {
            0x1000000000000
        } else if last_input_num_bytes == 7 {
            0x100000000000000
        } else {
            panic_with_felt252('Keccak last input word >7b')
        };
        let (_, r) = integer::u64_safe_divmod(
            last_input_word, first_padding_byte_part.try_into().unwrap()
        );
        first_padding_byte_part + r
    };

    if last_block_num_full_words == KECCAK_FULL_RATE_IN_U64S - 1 {
        input.append(0x8000000000000000 + first_word_to_append);
        return;
    }

    // last_block_num_full_words < KECCAK_FULL_RATE_IN_U64S - 1
    input.append(first_word_to_append);
    finalize_padding(ref input, KECCAK_FULL_RATE_IN_U64S - 1 - last_block_num_full_words);
}

// Finalize the padding by appending "0* 1".
fn finalize_padding(ref input: Array<u64>, num_padding_words: u32) {
    if (num_padding_words == 1) {
        input.append(0x8000000000000000);
        return;
    }

    input.append(0);
    finalize_padding(ref input, num_padding_words - 1);
}

fn keccak_add_u256_be(ref keccak_input: Array::<u64>, v: u256) {
    let (high, low) = u128_split(integer::u128_byte_reverse(v.high));
    keccak_input.append(low);
    keccak_input.append(high);
    let (high, low) = u128_split(integer::u128_byte_reverse(v.low));
    keccak_input.append(low);
    keccak_input.append(high);
}

// Computes the keccak256 of multiple u256 values.
// The input values are interpreted as big-endian.
// The 32-byte result is represented as a little-endian u256.
fn keccak_u256s_be_inputs(mut input: Span<u256>) -> u256 {
    let mut keccak_input: Array::<u64> = Default::default();

    loop {
        match input.pop_front() {
            Option::Some(v) => {
                keccak_add_u256_be(ref keccak_input, *v);
            },
            Option::None => {
                break ();
            },
        };
    };

    add_padding(ref keccak_input, 0, 0);
    starknet::syscalls::keccak_syscall(keccak_input.span()).unwrap_syscall()
}

fn u128_split(input: u128) -> (u64, u64) {
    let (high, low) = integer::u128_safe_divmod(
        input, 0x10000000000000000_u128.try_into().unwrap()
    );

    (u128_to_u64(high), u128_to_u64(low))
}

fn u128_to_u64(input: u128) -> u64 {
    input.try_into().unwrap()
}