use alexandria_math::BitShift;
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

const VALIDATOR_ADDRESS_LEN: usize = 20;
const VALIDATOR_SIGNATURE_LEN: usize = 65;
const BEEFY_FINALITY_PROOF_VERSION: u8= 1;
const BEEFY_PAYLOAD_ID_LEN: usize =2;


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
struct BeefyPayloadEntry<T>{
    BeefyPayloadId: Slice<u8>,
    BeefyPayloadValue: Slice<u8>,
}

#[derive(Drop, Copy)]
struct BeefyPayloadEntryPlan{
    BeefyPayloadIdPlan: Range,
    BeefyPayloadValuePlan: Range,
}

// We need to also add next validator set here to the input for when the validator set changes and we need to use the next selector
// Ideally this won't be inputs as such, just accessors
fn verify_lean_beefy_proof_with_validator_set(buffer: Span<u8>, current_validator_addresses: Span<u8>, next_validator_addresses: Span<u8>, expected_validator_set_id: u64, last_block_number: u32) -> Result<(bool, Array<BeefyPayloadEntryPlan>),felt252>{

let mut offset:usize = 0;

if *buffer.at(offset)!=BEEFY_FINALITY_PROOF_VERSION{
    return Result::Err('Version not supported');
}
offset = offset+1;

let commitment_start: usize = offset;

let number_of_payload_entries = compact_u32_decode(buffer, ref offset)?;

let mut beefy_payloads = ArrayTrait::<BeefyPayloadEntryPlan>::new();

let mut itr:usize =0;
let maybe_err: Result<(),felt252> = loop{
    if itr ==number_of_payload_entries{
        break Result::Ok(());
    }

    let beefy_payload_id_plan = Range{start: offset, end: offset+BEEFY_PAYLOAD_ID_LEN};
    offset=offset+BEEFY_PAYLOAD_ID_LEN;

	let beefy_payload_value_len = match compact_u32_decode(buffer, ref offset){
		Result::Ok(v)=>{v},
		Result::Err(e)=>{
			break Result::Err(e);
			0_u32 //dummy value for the return type
			}
	};
    let beefy_payload_value_plan = Range{start: offset, end: offset+beefy_payload_value_len};
    offset=offset+beefy_payload_value_len;

    beefy_payloads.append(BeefyPayloadEntryPlan{BeefyPayloadIdPlan:beefy_payload_id_plan, BeefyPayloadValuePlan: beefy_payload_value_plan});

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

let commitment_pre_hashed_le = keccak(commitment);
let commitment_pre_hashed = u256_le_to_be(commitment_pre_hashed_le);

let mut validator_addresses = current_validator_addresses;
let is_next_validator_set_id: bool =false;

if validator_set_id!=expected_validator_set_id{
	if validator_set_id==expected_validator_set_id+1{
		let is_next_validator_set_id: bool =true;
		validator_addresses = next_validator_addresses
	} else if validator_set_id<expected_validator_set_id{
    	return Result::Err('Too low validator set id');
	} else {
    	return Result::Err('Broken validator chain, update');
	}
}

let signatures_from_bitfield_len = compact_u32_decode(buffer, ref offset)?;
let signatures_from_bitfield = Slice{span: buffer, range: Range{start: offset, end: offset+signatures_from_bitfield_len}};
offset=offset+signatures_from_bitfield_len;

let validator_addresses_len:usize = validator_addresses.len();
let number_of_validators:usize = validator_addresses_len/VALIDATOR_ADDRESS_LEN;
assert(number_of_validators*VALIDATOR_ADDRESS_LEN==validator_addresses_len, 'bad validator_addresses len');

let validator_set_len = u32_decode(Slice{span: buffer, range:Range {start: offset, end: offset + 4}});
offset=offset + 4;

if validator_set_len!=number_of_validators{
    return Result::Err('validator_set_len mismatch');
}

let signatures_compact_len = compact_u32_decode(buffer, ref offset)?;
let signatures_compact = Slice{span: buffer, range: Range{start: offset, end: offset+(signatures_compact_len*VALIDATOR_SIGNATURE_LEN)}};
let signatures_compact_start = offset;
offset=offset+(signatures_compact_len*VALIDATOR_SIGNATURE_LEN);

let mut bitfield_byte_bit_selector:u8=128;
let mut bitfield_byte_pointer: usize=signatures_from_bitfield.range.start;
let mut validator_count:usize=0;
let mut bitfield_byte_offset=0;
itr =0;
let maybe_err: Result<(),felt252> = loop{
    if itr ==signatures_compact_len{

		if bitfield_byte_pointer == signatures_from_bitfield.range.end{
			if bitfield_byte_bit_selector==128{
				if validator_count != validator_set_len{
					break Result::Err('Unexpected bitfield error');
				}
			} else {
				break Result::Err('Bitfield incorrectly terminated');
			}
		} else if bitfield_byte_pointer < signatures_from_bitfield.range.end{
			if validator_count > validator_set_len{
				break Result::Err('Unexpected bitfield error 2');
			}
			
			let mut trailing_zero_count = 0;
			// all in current byte from selector are 0
			let mut all_following_bits_in_byte_are_zero: bool = true;
			if bitfield_byte_bit_selector == 128{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 255_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+8;
			} else if bitfield_byte_bit_selector == 64{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 127_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+7;
			} else if bitfield_byte_bit_selector == 32{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 63_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+6;
			} else if bitfield_byte_bit_selector == 16{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 31_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+5;
			} else if bitfield_byte_bit_selector == 8{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 15_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+4;
			} else if bitfield_byte_bit_selector == 4{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 7_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+3;
			} else if bitfield_byte_bit_selector == 2{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 3_u8) != 0{
					all_following_bits_in_byte_are_zero = false;
				}
					trailing_zero_count=trailing_zero_count+2;
			} else if bitfield_byte_bit_selector == 1{
				if (*signatures_from_bitfield.span.at(bitfield_byte_pointer) & 1_u8) != 0{
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
				if bitfield_byte_pointer == signatures_from_bitfield.range.end{
					break;
				}

				if *signatures_from_bitfield.span.at(bitfield_byte_pointer) != 0_u8{
					all_following_bits_in_byte_are_zero = true;
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
				break Result::Err('Bitfield did not terminate');
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

	if !verify_eth_signature_pre_hashed(
			commitment_pre_hashed,
			Slice{span: buffer, range: Range{start: itr*VALIDATOR_SIGNATURE_LEN + signatures_compact_start,end: ((itr*VALIDATOR_SIGNATURE_LEN) + VALIDATOR_SIGNATURE_LEN + signatures_compact_start)}},
			Slice{span: validator_addresses, range: Range{start: validator_count*VALIDATOR_ADDRESS_LEN,end: ((validator_count*VALIDATOR_ADDRESS_LEN) + VALIDATOR_ADDRESS_LEN)}},
			)
			{
		break Result::Err('Signature verification failed');
	}

	inc_bitfield_marker_unchecked(signatures_from_bitfield, ref bitfield_byte_pointer, ref bitfield_byte_bit_selector, ref validator_count);

    itr=itr+1;
};

match maybe_err{
	Result::Ok(())=>{},
	Result::Err(e)=>{return Result::Err(e);}
};

if itr>=threshold(validator_addresses_len){
    return Result::Err('Not enough sigs');
}

if offset!=buffer.len(){
    return Result::Err('offset not at buffer end');
}

// DEBUG
// TODO Remove
Result::Ok((true, ArrayTrait::<BeefyPayloadEntryPlan>::new()))
}

fn move_over_zeros(bitfield: Slice<u8>, ref bitfield_byte_pointer: usize, ref selector:u8, ref validator_count: usize) -> Result<(),felt252>{

	// changes to selector and bitfield_pointer must be valid
	loop{
		if (*bitfield.span.at(bitfield_byte_pointer) & selector) != selector{
			inc_bitfield_marker_unchecked(bitfield, ref bitfield_byte_pointer, ref selector, ref validator_count);
			if bitfield_byte_pointer>=bitfield.range.end{
				break Result::Err('Bitfield ended prematurely');
			}
		} else {
			break Result::Ok(());
		};
	}
}

fn inc_bitfield_marker_unchecked(bitfield: Slice<u8>, ref bitfield_byte_pointer: usize, ref selector:u8, ref validator_count: usize){
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
fn keccak(input: Slice<u8>) -> u256{

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

fn verify_eth_signature_pre_hashed(pre_hashed_message: u256, signature: Slice<u8>, address: Slice<u8>) -> bool{
	let mut r_high:u128 = 0;
	let mut r_low:u128 = 0;
	let mut s_high:u128 = 0;
	let mut s_low:u128 = 0;
	let mut a_low:u128 = 0;
	assert((signature.range.end-signature.range.start)==65, 'Bad signature len');
	assert((address.range.end-address.range.start)==20, 'Bad address len');

	let mut itr: usize = 0;
	

	loop{
		if itr==16{
			break;
		}

		r_high = Into::<u8,u128>::into(*signature.span.at(itr+signature.range.start)) + r_high*256_u128;
		r_low = Into::<u8,u128>::into(*signature.span.at(16+itr+signature.range.start)) + r_low*256_u128;

		s_high = Into::<u8,u128>::into(*signature.span.at(32+itr+signature.range.start)) + s_high*256_u128;
		s_low = Into::<u8,u128>::into(*signature.span.at(48+itr+signature.range.start)) + s_low*256_u128;

		a_low = Into::<u8,u128>::into(*address.span.at(4+itr+address.range.start)) + a_low*256_u128;

		itr=itr+1;
	};

	let a_high: u128 = Into::<u8,u128>::into(*address.span.at(3)) + ((Into::<u8,u128>::into(*address.span.at(2)) + ((Into::<u8,u128>::into(*address.span.at(1)) + (Into::<u8,u128>::into(*address.span.at(0)) * 256_u128)) *256_u128)) * 256_u128);

	let v:u32 = Into::<u8,u32>::into(*signature.span.at(64+signature.range.start));

	let eth_signature = signature_from_vrs(v, u256{high: r_high, low: r_low }, u256{high:s_high, low:s_low});
	verify_eth_signature::<Secp256k1Point>(pre_hashed_message, eth_signature, Into::<u256, EthAddress>::into(u256{high:a_high, low:a_low}));
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

fn u256_le_to_be(le: u256) -> u256{
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
