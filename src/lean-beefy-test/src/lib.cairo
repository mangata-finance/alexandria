/// The Contract Class Hash is 0x8873aa28af0a0e6ac6aa647aa8e8c02cea7752bb7950284dbbbae1be35e9cb
/// The contract is deployed on the Starknet testnet. The contract address is 0x056d42ddcc1c85959989aaef369e284804a8e59cc5ce519e579fcb121b18f724

/// @dev Core Library Imports for the Traits outside the Starknet Contract
use starknet::ContractAddress;
use array::{ArrayTrait, SpanTrait};
use option::OptionTrait;
use result::ResultTrait;

use traits::{Default, Into, TryInto};
use starknet::{ Store, StorageBaseAddress,
    SyscallResult, syscalls::{storage_read_syscall, storage_write_syscall},
    contract_address::{Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
    class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
};
use serde::Serde;

/// @dev Trait defining the functions that can be implemented or called by the Starknet Contract
#[starknet::interface]
trait VoteTrait<T> {
    /// @dev Function that returns the current vote status
    // fn get_vote_status(self: @T) -> (u8, u8, u8, u8);

    /// @dev Function that checks if the user at the specified address is allowed to vote
    fn voter_can_vote(ref self: T, user_address: ContractAddress, array: Array<u8>) -> Array<u8>;
    // fn voter_can_vote_2(ref self: T, user_address: ContractAddress, array: Array<u8>) -> Array<u8>;
    // fn voter_can_vote_3(ref self: T, user_address: ContractAddress, array: Array<u8>) -> Array<u8>;

    fn check_beefy_payload_len(self: @T, array: Array<u8>) -> u32;
    fn check_beefy_payload_len_u256(self: @T, array: Array<u256>) -> u32;


    fn check_beefy_payload_len_invoke(ref self: T, array: Array<u8>) -> u32;
    fn check_beefy_payload_len_u256_invoke(ref self: T, array: Array<u256>) -> u32;

    fn write_u8_array(ref self: T, array: Array<u8>, len:usize);
    fn read_u8_array(self: @T, len:usize) -> usize;

    fn unset_validator_set_info(ref self: T, validator_set_id: u64);
    fn set_validator_set_info(ref self: T, validator_set_id: u64, validator_set_list: Array<u256>);
    fn set_validator_set_info_u8_array(ref self: T, validator_set_id: u64, validator_set_list_u8_array: Array<u8>);
    fn calculate_merkle_hash_for_validator_set(ref self: T, validator_set_id: u64);
    fn full_reset_current_beefy_proof(ref self: T);
    fn verify_lean_beefy_proof(ref self: T, lean_beefy_proof: Array<u8>);
    fn verify_beefy_mmr_leaves_proof(ref self: T, leaves: Array<u8>, proof: Array<u8>);
    fn verify_beefy_para_data(ref self: T, leaf_index: usize, leaf: Array<u8>, proof: Array<u8>, number_of_leaves:usize);
    fn validate_next_validator_set_info(ref self: T);
    fn finalize_current_lean_beefy_proof(ref self: T);
    

    // fn verify_lean_beefy(self: @T);
    // fn verify_lean_beefy_2(ref self: T);

    fn ver_eth_sig(ref self: T);
    fn ver_eth_sig_test(ref self: T);

    fn verify_mmr_leaves_proof_test(ref self: T);
    fn verify_mmr_leaves_proof_test_2(ref self: T);
    fn merkelize_for_merkle_root_test(ref self: T, len: usize);
    fn verify_merkle_proof_test(ref self: T);

}

impl StoreFelt252Array of Store<Array<felt252>> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Array<felt252>> {
        StoreFelt252Array::read_at_offset(address_domain, base, 0)
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: Array<felt252>
    ) -> SyscallResult<()> {
        StoreFelt252Array::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8
    ) -> SyscallResult<Array<felt252>> {
        let mut arr: Array<felt252> = ArrayTrait::new();

        // Read the stored array's length. If the length is superior to 255, the read will fail.
        let len: u8 = Store::<u8>::read_at_offset(address_domain, base, offset)
            .expect('Storage Span too large');
        offset += 1;

        // Sequentially read all stored elements and append them to the array.
        let exit = len + offset;
        loop {
            if offset >= exit {
                break;
            }

            let value = Store::<felt252>::read_at_offset(address_domain, base, offset).unwrap();
            arr.append(value);
            offset += Store::<felt252>::size();
        };

        // Return the array.
        Result::Ok(arr)
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8, mut value: Array<felt252>
    ) -> SyscallResult<()> {
        // // Store the length of the array in the first storage slot.
        let len: u8 = value.len().try_into().expect('Storage - Span too large');
        Store::<u8>::write_at_offset(address_domain, base, offset, len);
        offset += 1;

        // Store the array elements sequentially
        loop {
            match value.pop_front() {
                Option::Some(element) => {
                    Store::<felt252>::write_at_offset(address_domain, base, offset, element);
                    offset += Store::<felt252>::size();
                },
                Option::None(_) => {
                    break Result::Ok(());
                }
            };
        }
    }

    fn size() -> u8 {
        255 * Store::<felt252>::size()
    }
}

// Do not use for arrays
impl StoreOptionT<T, impl TCopy: Copy<T>, impl TDrop: Drop<T>, impl TStore: Store<T>,
> of Store<Option<T>> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Option<T>> {
        StoreOptionT::read_at_offset(address_domain, base, 0)
    }

    fn write(
        address_domain: u32, base: StorageBaseAddress, value: Option<T>
    ) -> SyscallResult<()> {
        StoreOptionT::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8
    ) -> SyscallResult<Option<T>> {
        assert(Store::<T>::size()<255, 'T too large to option');
        let exists: bool = Store::<bool>::read_at_offset(address_domain, base, offset)
            .expect('bool should read');
        offset += 1;

        if exists == false{
            return SyscallResult::Ok(Option::None);
        }

        let value = Store::<T>::read_at_offset(address_domain, base, offset).unwrap();
        offset += Store::<T>::size();

        SyscallResult::Ok(Option::Some(value))
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8, mut value: Option<T>
    ) -> SyscallResult<()> {

        assert(Store::<T>::size()<255, 'T too large to option');

        let was_value: bool = Store::<bool>::read_at_offset(address_domain, base, offset)
            .expect('bool should read');

        match value{
            Option::Some(v) => {
                Store::<bool>::write_at_offset(address_domain, base, offset, true);
                offset += 1;
                Store::<T>::write_at_offset(address_domain, base, offset, v);
                offset += Store::<T>::size();
            },
            Option::None(()) => {
                if was_value{
                    Store::<bool>::write_at_offset(address_domain, base, offset, false);
                    offset += 1;
                    let mut itr:usize=0;
                    let t_size: usize = Store::<T>::size().into();
                    loop{
                        if itr==t_size{break;}
                        Store::<felt252>::write_at_offset(address_domain, base, offset, Default::default());
                        offset += 1;
                        itr=itr+1;
                    };
                        
                } else {

                };
            },
        };
        
        SyscallResult::Ok(())
    }

    fn size() -> u8 {
        1 + Store::<T>::size()
    }
}


/// @dev Starknet Contract allowing three registered voters to vote on a proposal
#[starknet::contract]
mod Vote {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
use array::{ArrayTrait, SpanTrait};
use option::OptionTrait;
use result::ResultTrait;
use alexandria_substrate::blake2b::{blake2b};
use alexandria_math::ed25519::{p, Point, verify_signature, SpanU8TryIntoPoint};
use alexandria_substrate::substrate_storage_read_proof_verifier::{verify_substrate_storage_read_proof, verify_substrate_storage_read_proof_given_hashes, convert_u8_subarray_to_u8_array};
use alexandria_substrate::lean_beefy_verifier::{decode_paradata, Slice, u256_byte_reverse, keccak_le, Range, encoded_opaque_leaves_to_leaves, u8_eth_addresses_to_u256,verify_beefy_signatures, get_mmr_root, VALIDATOR_ADDRESS_LEN, get_lean_beefy_proof_metadata, BeefyProofInfo, BeefyAuthoritySet, BeefyData, hashes_to_u256s, verify_merkle_proof, get_hashes_from_items, merkelize_for_merkle_root,encoded_opaque_leaves_to_hashes,verify_mmr_leaves_proof};
use core::clone::Clone;
use alexandria_math::sha256::sha256;
use alexandria_math::sha512::{sha512};
use zeroable::Zeroable;

use super::{StoreFelt252Array, StoreOptionT};

use traits::{Into, TryInto};
use starknet::{ secp256_trait::{Signature,verify_eth_signature, Secp256PointTrait, signature_from_vrs},Store, StorageBaseAddress,
    SyscallResult, syscalls::{storage_read_syscall, storage_write_syscall},
    contract_address::{Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
    class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
};
use starknet::secp256k1::{Secp256k1Point, Secp256k1PointImpl};
use starknet::{eth_address::U256IntoEthAddress, EthAddress};
use serde::Serde;
use debug::PrintTrait;


    use poseidon::poseidon_hash_span;
    use starknet::storage_access::Felt252TryIntoStorageAddress;
    use starknet::StorageAddress;

    type ValidatorSetId = u64;
    const PARA_ID: u32 = 2110;

    const YES: u8 = 1_u8;
    const NO: u8 = 0_u8;

    const TEST_BASE_ADDRESS: felt252 = 'test_base_address';

    /// @dev Structure that stores vote counts and voter states
    #[storage]
    struct Storage {
        yes_votes: u8,
        no_votes: u8,
        can_vote: LegacyMap::<ContractAddress, bool>,
        registered_voter: LegacyMap::<ContractAddress, bool>,
        array_map: LegacyMap::<ContractAddress, Array<felt252>>,
        test_u256: LegacyMap::<ContractAddress, u256>,
        
        array_storage: Array<felt252>,

        validator_set_info: LegacyMap::<ValidatorSetId, Option<ValidatorSetInfo>>,
        validator_set_list: LegacyMap::< (ValidatorSetId, u32), u256>,
        current_mmr_root: Option<u256>,
        current_beefy_proof_info: Option<BeefyProofInfo>,
        current_beefy_data: Option<BeefyData>,
        current_para_data: Option<ParaData>,
        last_mmr_root: Option<u256>,
        last_beefy_proof_info: Option<BeefyProofInfo>,
        last_beefy_data: Option<BeefyData>,
        last_para_data: Option<ParaData>,
        last_block_broken_validator_chain: Option<(u32, ValidatorSetId,u32,ValidatorSetId)>,
        last_block_unvalidated_validator_set: Option<(u32, ValidatorSetId)>,
        // last_read_value: Option<LargeArray>,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct ValidatorSetInfo {
        number_of_validators: u32,
        merkle_hash: Option<u256>,
        validated_at: Option<u32>,
    }

    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct ParaData {
        // para_head: LargeArray,
        keccak_hash: u256,
        parent_blake2b_hash: u256,
        storage_root: u256,
        blake2b_hash: Option<u256>,
    }

    /// @dev Contract constructor initializing the contract with a list of registered voters and 0 vote count
    #[constructor]
    fn constructor(
        ref self: ContractState,
        voter_1: ContractAddress,
        voter_2: ContractAddress,
        voter_3: ContractAddress
    ) {
        // Register all voters by calling the _register_voters function 
        self._register_voters(voter_1, voter_2, voter_3);

        // Initialize the vote count to 0
        self.yes_votes.write(0_u8);
        self.no_votes.write(0_u8);
    }

    /// @dev Event that gets emitted when a vote is cast
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        VoteCast: VoteCast,
        UnauthorizedAttempt: UnauthorizedAttempt,
    }

    /// @dev Represents a vote that was cast
    #[derive(Drop, starknet::Event)]
    struct VoteCast {
        voter: ContractAddress,
        vote: u8,
    }

    /// @dev Represents an unauthorized attempt to vote
    #[derive(Drop, starknet::Event)]
    struct UnauthorizedAttempt {
        unauthorized_address: ContractAddress, 
    }

    

    /// @dev Implementation of VoteTrait for ContractState
    #[external(v0)]
    impl VoteImpl of super::VoteTrait<ContractState> {
        /// @dev Returns the voting results
        // fn get_vote_status(self: @ContractState) -> (u8, u8, u8, u8) {
        //     let (n_yes, n_no) = self._get_voting_result();
        //     let (yes_percentage, no_percentage) = self._get_voting_result_in_percentage();
        //     return (n_yes, n_no, yes_percentage, no_percentage);
        // }

        /// @dev Check whether a voter is allowed to vote
        fn voter_can_vote(ref self: ContractState, user_address: ContractAddress, array: Array<u8>) -> Array<u8> {
            // self.can_vote.read(user_address)
            // TryInto::<usize, u8>::try_into(array.len()).unwrap()
            let x = blake2b(array.clone());
            self.emit(VoteCast { voter: user_address, vote: *x.at(0),  });
            x
        }

        /// @dev Check whether a voter is allowed to vote
        fn check_beefy_payload_len(self: @ContractState, array: Array<u8>) -> u32 {
            array.len()
        }

        fn check_beefy_payload_len_u256(self: @ContractState, array: Array<u256>) -> u32 {
            array.len()
        }

        fn check_beefy_payload_len_invoke(ref self: ContractState, array: Array<u8>) -> u32 {
            array.len()
        }

        fn check_beefy_payload_len_u256_invoke(ref self: ContractState, array: Array<u256>) -> u32 {
            array.len()
        }

        fn write_u8_array(ref self: ContractState, array: Array<u8>, len:usize) {
            self.write_test_array(array, len);
        }

        fn read_u8_array(self: @ContractState, len:usize) -> usize {
            let array = self.read_test_array(len);
            array.span().len()
        }

        // fn voter_can_vote_2(ref self: ContractState, user_address: ContractAddress, array: Array<u8>) -> Array<u8> {
        //     // self.can_vote.read(user_address)
        //     // TryInto::<usize, u8>::try_into(array.len()).unwrap()
        //     sha256(array.clone())
        // }

        // fn voter_can_vote_3(ref self: ContractState, user_address: ContractAddress, array: Array<u8>) -> Array<u8> {
        //     // self.can_vote.read(user_address)
        //     // TryInto::<usize, u8>::try_into(array.len()).unwrap()
        //     sha512(array.clone())
        // }

        // Ingest beefy proof - Sets Proof info, and maybe metadata about the signature validations
        // 

        // fn finalize current beefy proof() - updates is_validated_by_proof_before_current and is_validated

        // fn remove_validator_set_info(ref self: ContractState, validator_set_id: u64){
        //     let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
        //     match maybe_validator_set_info{
        //         Option::Some(validator_set_info)=>{
        //             let number_of_validators = validator_set_info.number_of_validators;
        //             let mut itr:u32=0;
        //             loop{
        //                 if itr==number_of_validators{break;}
        //                 self.validator_set_list.write((validator_set_id, itr), 0_u256);
        //                 itr=itr+1;
        //             };

        //             self.validator_set_info.write(validator_set_id, Option::None);
        //         },
        //         Option::None=>{}
        //     };
        // }

        // fn depopulate_validator_set(ref self: ContractState, validator_set_id: u64){
        //     let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
        //     match maybe_validator_set_info{
        //         Option::Some(validator_set_info)=>{
        //             let number_of_validators = validator_set_info.number_of_validators;
        //             let mut itr:u32=0;
        //             loop{
        //                 if itr==number_of_validators{break;}
        //                 self.validator_set_list.write((validator_set_id, itr), 0_u256);
        //                 itr=itr+1;
        //             };

        //             self.validator_set_info.write(validator_set_id, Option::Some(ValidatorSetInfo {
        //                 number_of_validators: number_of_validators,
        //                 merkle_hash: validator_set_info.merkle_hash,
        //                 is_validator_set_populated: false,
        //                 is_validated: false,
        //                 is_validated_by_proof_before_current: false,
        //             }));
        //         },
        //         Option::None=>{}
        //     };
        // }

        // fn populate_validator_set(ref self: ContractState, validator_set_id: u64, validator_set_list: Array<u256>){
        //     let number_of_validators = validator_set_list.len().try_into().unwrap();
        //     let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
        //     match maybe_validator_set_info{
        //         Option::Some(validator_set_info)=>{
        //             assert(validator_set_info.is_validator_set_populated,'Validator set already populated');
        //             assert()
        //         },
        //         Option::None=>{}
        //     }
        // }

        fn unset_validator_set_info(ref self: ContractState, validator_set_id: u64){
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info{
                Option::Some(validator_set_info)=>{
                    let number_of_validators = validator_set_info.number_of_validators;
                    let mut itr:u32=0;
                    loop{
                        if itr==number_of_validators{break;}
                        self.validator_set_list.write((validator_set_id, itr), 0_u256);
                        itr=itr+1;
                    };

                    self.validator_set_info.write(validator_set_id, Option::None);
                },
                Option::None=>{}
            };
        }

        fn set_validator_set_info(ref self: ContractState, validator_set_id: u64, validator_set_list: Array<u256>){
            let number_of_validators: u32 = validator_set_list.len();
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info{
                Option::Some(validator_set_info)=>{
                    panic_with_felt252('Validator set info already set');
                },
                Option::None=>{
                    let mut itr:u32=0;
                    loop{
                        if itr==number_of_validators{break;}
                        self.validator_set_list.write((validator_set_id, itr), *validator_set_list.at(itr.into()));
                        itr=itr+1;
                    };

                    self.validator_set_info.write(validator_set_id, Option::Some(ValidatorSetInfo{
                        number_of_validators: number_of_validators,
                        merkle_hash: Option::None,
                        validated_at: Option::None,
                    }));
                }
            };
        }

        fn set_validator_set_info_u8_array(ref self: ContractState, validator_set_id: u64, validator_set_list_u8_array: Array<u8>){

            let validator_set_list: Array<u256> = u8_eth_addresses_to_u256(validator_set_list_u8_array.span());

            let number_of_validators: u32 = validator_set_list.len();
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info{
                Option::Some(validator_set_info)=>{
                    panic_with_felt252('Validator set info already set');
                },
                Option::None=>{
                    let mut itr:u32=0;
                    loop{
                        if itr==number_of_validators{break;}
                        self.validator_set_list.write((validator_set_id, itr), *validator_set_list.at(itr.into()));
                        itr=itr+1;
                    };

                    self.validator_set_info.write(validator_set_id, Option::Some(ValidatorSetInfo{
                        number_of_validators: number_of_validators,
                        merkle_hash: Option::None,
                        validated_at: Option::None,
                    }));
                }
            };
        }

        fn calculate_merkle_hash_for_validator_set(ref self: ContractState, validator_set_id: u64){

            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info{
                Option::Some(validator_set_info)=>{
                    let number_of_validators: u32 = validator_set_info.number_of_validators;
                    let mut validator_set_list: Array<u256> = array![];
                    let mut itr:u32=0;
                    
                    loop{
                        if itr==number_of_validators{break;}
                        validator_set_list.append(self.validator_set_list.read((validator_set_id, itr)));
                        itr=itr+1;
                    };

                    let merkle_root = merkelize_for_merkle_root(validator_set_list.span());

                    self.validator_set_info.write(validator_set_id, Option::Some(ValidatorSetInfo{
                        number_of_validators: number_of_validators,
                        merkle_hash: Option::Some(merkle_root),
                        validated_at: Option::None,
                    }));
                },
                Option::None=>{
                    panic_with_felt252('Validator set info not set');
                },
            }
        }


        fn full_reset_current_beefy_proof(ref self: ContractState){
            self.current_mmr_root.write(Option::None);
            self.current_beefy_proof_info.write(Option::None);
            self.current_beefy_data.write(Option::None);
            self.current_para_data.write(Option::None);
        }

        fn verify_lean_beefy_proof(ref self: ContractState, lean_beefy_proof: Array<u8>){

            assert(self.current_mmr_root.read().is_none(), 'current_mmr_root exists');
            assert(self.current_beefy_proof_info.read().is_none(), 'current_beefy_proof_info exists');
            assert(self.current_beefy_data.read().is_none(), 'current_beefy_data exists');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');

            let (metadata, mut info, beefy_payloads_plan) = get_lean_beefy_proof_metadata(lean_beefy_proof.span()).expect('get metadata failed');
            let mmr_root = get_mmr_root(beefy_payloads_plan.span()).expect('get_mmr_root failed');

            let last_info = self.last_beefy_proof_info.read();
            if last_info.is_some(){
                let last_info = last_info.expect('checked by is_some');
                assert(info.validator_set_id>=last_info.validator_set_id, 'stale proof');
                assert(info.block_number>last_info.block_number, 'stale proof');
                if info.validator_set_id>last_info.validator_set_id+1{
                    self.last_block_broken_validator_chain.write(Option::Some((
                        last_info.block_number,
                        last_info.validator_set_id,
                        info.block_number,
                        info.validator_set_id
                    )));
                }
            }

            let validator_set_info = self.validator_set_info.read(info.validator_set_id).expect('Validators not set for set id');
            let number_of_validators = validator_set_info.number_of_validators;

            if validator_set_info.validated_at.is_none(){
                self.last_block_unvalidated_validator_set.write(Option::Some(
                    (info.block_number,
                    info.validator_set_id)));
            }

            assert(number_of_validators == metadata.validator_set_len, 'number_of_validators mismatch');

            let mut itr:usize=0;
            let mut validator_addresses: Array<u256> = array![];

            loop{
                if itr==number_of_validators{break;}
                validator_addresses.append(self.validator_set_list.read((info.validator_set_id, itr)));
                itr=itr+1;
            };

            assert(
                verify_beefy_signatures(Option::Some(2),
                    metadata.commitment_pre_hashed,
                    metadata.signatures_from_bitfield,
                    metadata.validator_set_len,
                    metadata.signatures_compact_len,
                    metadata.signatures_compact,
                    validator_addresses.span())
                .expect('verify_beefy_signatures failed'),
                'verify_beefy_signatures failed'
            );

            info.is_proof_verification_completed = true;
            self.current_mmr_root.write(Option::Some(mmr_root));
            self.current_beefy_proof_info.write(Option::Some(info));
        }

        fn verify_beefy_mmr_leaves_proof(ref self: ContractState, leaves: Array<u8>, proof: Array<u8>){

            assert(self.current_beefy_proof_info.read().is_some(), 'no current_beefy_proof_info');
            assert(self.current_beefy_data.read().is_none(), 'current_beefy_data exists');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');

            let mmr_root = self.current_mmr_root.read().expect('no current_mmr_root');
            let leaves_hashes = encoded_opaque_leaves_to_hashes(leaves.span()).expect('leaves_to_hashes works');
            assert(verify_mmr_leaves_proof(mmr_root, proof.span(), leaves_hashes.span()).is_ok(),
                'verify_mmr_leaves_proof failed');
            let beefy_data_array = encoded_opaque_leaves_to_leaves(leaves.span()).expect('decoding leaves failed');
            assert(!beefy_data_array.len().is_zero(), 'no beefy data');
            self.current_beefy_data.write(Option::Some(*beefy_data_array.at(0)));
        }

        fn verify_beefy_para_data(ref self: ContractState, leaf_index: usize, leaf: Array<u8>, proof: Array<u8>, number_of_leaves:usize){
            assert(self.current_mmr_root.read().is_some(), 'no current_mmr_root');
            assert(self.current_beefy_proof_info.read().is_some(), 'no current_beefy_proof_info');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');
            let current_beefy_data = self.current_beefy_data.read().expect('current_beefy_data missing');

            let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).expect('get_hashes works').at(0);
            let res = verify_merkle_proof(current_beefy_data.leaf_extra, hashes_to_u256s(proof.span()).expect('hashes_to_u256s works').span(), number_of_leaves, leaf_index, leaf_hash);
            assert(res, 'merkle proof ver failed');

            let (para_id, para_head) = decode_paradata(leaf.span());
            assert(para_id == PARA_ID, 'Wrong Para Id');

            let keccak_hash = u256_byte_reverse(keccak_le(Slice{span: para_head, range: Range{start: 0, end: para_head.len()}}));
            let parent_hash = *hashes_to_u256s(para_head.slice(0, 32)).expect('hashes_to_u256s works').at(0);
            let storage_root = *hashes_to_u256s(para_head.slice(36,32)).expect('hashes_to_u256s works').at(0);

            self.current_para_data.write(Option::Some(
                ParaData{
                    keccak_hash: keccak_hash,
                    parent_blake2b_hash: parent_hash,
                    storage_root: storage_root,
                    blake2b_hash: Option::None,
                }
            ));
        }

        fn validate_next_validator_set_info(ref self: ContractState){
            let current_beefy_proof_info = self.current_beefy_proof_info.read().expect('no current_beefy_proof_info');
            let current_beefy_data = self.current_beefy_data.read().expect('current_beefy_data missing');

            match self.validator_set_info.read(current_beefy_proof_info.validator_set_id+1){
                Option::Some(mut validator_set_info)=>{
                    match validator_set_info.merkle_hash{
                        Option::Some(merkle_hash)=>{
                            if current_beefy_data.beefy_next_authority_set.keyset_commitment == merkle_hash{
                                validator_set_info.validated_at = Option::Some(current_beefy_proof_info.block_number);
                                self.validator_set_info.write(current_beefy_proof_info.validator_set_id+1, Option::Some(validator_set_info));
                            } else {
                                panic_with_felt252('commitment merkle_hash mismatch');
                            }
                        },
                        Option::None=>{panic_with_felt252('validator_set merkle_hash unset');}
                    }
                },
                Option::None=>{panic_with_felt252('validator_set_info unset');}
            };
        }

        fn finalize_current_lean_beefy_proof(ref self: ContractState){
            let current_mmr_root = self.current_mmr_root.read().expect('current_mmr_root missing');
            let current_beefy_proof_info = self.current_beefy_proof_info.read().expect('no current_beefy_proof_info');
            let current_beefy_data = self.current_beefy_data.read().expect('current_beefy_data missing');
            let current_para_data = self.current_para_data.read().expect('current_para_data missing');

            match self.validator_set_info.read(current_beefy_proof_info.validator_set_id+1){
                Option::Some(mut validator_set_info)=>{
                    match validator_set_info.merkle_hash{
                        Option::Some(merkle_hash)=>{
                            if current_beefy_data.beefy_next_authority_set.keyset_commitment == merkle_hash{
                                validator_set_info.validated_at = Option::Some(current_beefy_proof_info.block_number);
                                self.validator_set_info.write(current_beefy_proof_info.validator_set_id+1, Option::Some(validator_set_info));
                            }
                        },
                        Option::None=>{}
                    }
                },
                Option::None=>{}
            };

            
            self.current_mmr_root.write(Option::None);
            self.current_beefy_proof_info.write(Option::None);
            self.current_beefy_data.write(Option::None);
            self.current_para_data.write(Option::None);

            
            self.current_mmr_root.write(Option::Some(current_mmr_root));
            self.current_beefy_proof_info.write(Option::Some(current_beefy_proof_info));
            self.current_beefy_data.write(Option::Some(current_beefy_data));
            self.current_para_data.write(Option::Some(current_para_data));

        }

        // fn verify_lean_beefy(self: @ContractState) {
        //     verify_lean_beefy_proof_with_validator_set(
        //         self.get_lean_beefy_proof().span(),
        //          self.get_current_validator_addresses().span(),
        //           ArrayTrait::<u8>::new().span(), 3, 39);
        // }

        // fn verify_lean_beefy_2(ref self: ContractState) {
        //     verify_lean_beefy_proof_with_validator_set(self.get_lean_beefy_proof_2().span(), self.get_current_validator_addresses_2().span(), ArrayTrait::<u8>::new().span(), 7, 79);
        // }

        fn ver_eth_sig_test(ref self: ContractState) {
            let y_parity = true;
            let (msg_hash, signature, expected_public_key_x, expected_public_key_y, eth_address) =
                self.get_message_and_signature(
                :y_parity
            );
            verify_eth_signature::<Secp256k1Point>(:msg_hash, :signature, :eth_address);
        }

        fn ver_eth_sig(ref self: ContractState) {
            let pre_hashed_message = u256{ low:0x5ad896dbb14e39c1fecaff6ae02bbb50 

            ,high: 0xcee2819ce46ce268649072040ce1b33e} ;

            let v:u32 = 0x00;

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

        // fn ver_eth_sig(ref self: ContractState) {
        //     let pre_hashed_message = u256{ low:0x5ad896dbb14e39c1fecaff6ae02bbb50 

        //     ,high: 0xcee2819ce46ce268649072040ce1b33e} ;

        //     let v:u32 = 0x1;

        //     let r_high = 0x0755a50112e6b29bbcabffd3fce5d7f1 ;

        //     let r_low = 0x10bc0ac7193b081b1fe25b885136414f ;

        //     // let r = u256{high: r_high, low: r_low};

        //     let s_high = 0x184d3f82b94a53eb15f889253c7b685d ;

        //     let s_low = 0xab08356867af8d581689c8b4c1ac9b3c ;

        //     // let s = u256{high: s_high, low: s_low};

        //     let a_high = 0x000000000000000000000000e04cc55e ;

        //     let a_low = 0xbee1cbce552f250e85c57b70b2e2625b;

        //     // let a = u256{high: a_high, low: a_low};

        //     let eth_signature = signature_from_vrs(v, u256{high: r_high, low: r_low }, u256{high:s_high, low:s_low});

        //     verify_eth_signature::<Secp256k1Point>(pre_hashed_message, eth_signature, Into::<u256, EthAddress>::into(u256{high:a_high, low:a_low}));
        // }

        fn verify_mmr_leaves_proof_test(ref self: ContractState) {
            let leaves_hashes = encoded_opaque_leaves_to_hashes(self.get_leaves().span()).unwrap();
            let res = verify_mmr_leaves_proof(self.mmr_root(), self.get_proof().span(), leaves_hashes.span());

            match res{
                Result::Ok(_)=>{},
                Result::Err(e)=>{e.print();
            assert(false, 'Ver failed');},
            };
            // panic(convert_u8_array_to_felt252_array(maybe_mmr_root.unwrap()));
        }


        fn verify_mmr_leaves_proof_test_2(ref self: ContractState) {
            let leaves_hashes = encoded_opaque_leaves_to_hashes(self.get_leaves_2().span()).unwrap();
            let res = verify_mmr_leaves_proof(self.mmr_root_2(), self.get_proof_2().span(), leaves_hashes.span());

            match res{
                Result::Ok(_)=>{},
                Result::Err(e)=>{e.print();
            assert(false, 'Ver failed');},
            };
            // panic(convert_u8_array_to_felt252_array(maybe_mmr_root.unwrap()));
        }


        fn merkelize_for_merkle_root_test(ref self: ContractState, len: usize) {
            
            let mut array: Array<u256> = array![];
            let mut itr: usize =0;
            loop{
                if itr==len{break;}
                let x: u256 = 0x7;
                array.append(x);
                itr=itr+1;
            };

            merkelize_for_merkle_root(array.span());
        }

        fn verify_merkle_proof_test(ref self: ContractState){
            let (leaf_index, leaf) = self.get_leaf_data_2_1();
            let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span()).unwrap().at(0);
            let res = verify_merkle_proof(*hashes_to_u256s(self.get_expected_merkle_root_2().span()).unwrap().at(0), hashes_to_u256s(self.get_merkle_proof_2_1().span()).unwrap().span(), self.get_number_of_leaves_2(), leaf_index, leaf_hash);
            assert(res, 'merkle proof ver failed');
        }

    }


    #[generate_trait]
    impl WriteTestArray of IWriteTestArray {
        fn write_test_array(ref self: ContractState, array: Array<u8>, len: usize) {
            let mut address = WriteTestArray::get_address_from_name(TEST_BASE_ADDRESS);
            let mut itr: usize =0;
            loop{
                if itr==len{break;}
                storage_write_syscall(0, address.try_into().unwrap(), (*array.at(0)).into());
                address=address+Store::<u8>::size().into();
                itr=itr+1;
            };
            
        }

        fn read_test_array(self: @ContractState, len: usize) -> Array<u8> {
            let mut address = WriteTestArray::get_address_from_name(TEST_BASE_ADDRESS);
            let mut array: Array<u8> = array![];
            let mut itr: usize =0;
            loop{
                if itr==len{break;}
                array.append(storage_read_syscall(0, address.try_into().unwrap())
                .unwrap_syscall()
                .try_into()
                .unwrap()
                );
                address=address+Store::<u8>::size().into();
                itr=itr+1;
            };
            array
        }
        fn get_address_from_name(variable_name: felt252) -> felt252 {
            let hashed_name: felt252 = poseidon_hash_span(array![variable_name].span());
            let MASK_250: u256 = 0x03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
            // By taking the 250 least significant bits of the hash output, we get a valid 250bits storage address.
            let result: felt252 = (hashed_name.into() & MASK_250).try_into().unwrap();
            // let result: StorageAddress = result.try_into().unwrap();
            result
        }
    }


    /// @dev Internal Functions implementation for the Vote contract
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {

        fn get_expected_merkle_root_2(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x1d);i.append(0x81);i.append(0x52);i.append(0x57);i.append(0xae);i.append(0x6a);i.append(0x56);i.append(0x0d);i.append(0x93);i.append(0xf3);i.append(0x82);i.append(0x0f);i.append(0xa6);i.append(0x5d);i.append(0x0f);i.append(0xd7);i.append(0x7a);i.append(0xeb);i.append(0xb7);i.append(0x72);i.append(0x20);i.append(0xf4);i.append(0x58);i.append(0x37);i.append(0x60);i.append(0x5b);i.append(0xc7);i.append(0xf4);i.append(0x8a);i.append(0x6e);i.append(0x3e);i.append(0xf9);
            i
        }

        fn get_number_of_leaves_2(self: @ContractState) -> usize {
            22
        }

        fn get_leaf_data_2_1(self: @ContractState)  -> (usize, Array<u8>) {
            let mut i: Array<u8> = Default::default();
            i.append(0x39);i.append(0xB3);i.append(0x8a);i.append(0xd7);i.append(0x4b);i.append(0x8b);i.append(0xCc);i.append(0x5C);i.append(0xE5);i.append(0x64);i.append(0xf7);i.append(0xa2);i.append(0x7A);i.append(0xc1);i.append(0x90);i.append(0x37);i.append(0xA9);i.append(0x5B);i.append(0x60);i.append(0x99);
            (11, i)
        }

        fn get_merkle_proof_2_1(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x3a);i.append(0xc0);i.append(0x5b);i.append(0x0c);i.append(0xcf);i.append(0xde);i.append(0x7f);i.append(0x55);i.append(0xab);i.append(0x70);i.append(0xca);i.append(0xb0);i.append(0xf5);i.append(0x1b);i.append(0xe5);i.append(0xfa);i.append(0xdf);i.append(0xcc);i.append(0xbb);i.append(0x69);i.append(0x32);i.append(0xeb);i.append(0xb4);i.append(0x4a);i.append(0x9c);i.append(0x75);i.append(0xe9);i.append(0x56);i.append(0xbe);i.append(0x04);i.append(0x77);i.append(0x8d);i.append(0xc6);i.append(0x1b);i.append(0x19);i.append(0xf5);i.append(0x83);i.append(0x26);i.append(0xbd);i.append(0xcf);i.append(0xf9);i.append(0x32);i.append(0x2b);i.append(0xcd);i.append(0xcf);i.append(0xfa);i.append(0xce);i.append(0xfa);i.append(0xcc);i.append(0x67);i.append(0xe3);i.append(0xa3);i.append(0xa5);i.append(0x26);i.append(0x4f);i.append(0x61);i.append(0x06);i.append(0xbd);i.append(0x59);i.append(0x70);i.append(0xfa);i.append(0x34);i.append(0x9f);i.append(0x3d);i.append(0x62);i.append(0xf3);i.append(0xed);i.append(0x9d);i.append(0x0b);i.append(0x00);i.append(0x6f);i.append(0xae);i.append(0x87);i.append(0x2c);i.append(0x2f);i.append(0xe6);i.append(0x20);i.append(0x20);i.append(0x2b);i.append(0xe7);i.append(0xe1);i.append(0x6b);i.append(0x74);i.append(0x12);i.append(0x32);i.append(0xc9);i.append(0xb7);i.append(0x64);i.append(0x1a);i.append(0x13);i.append(0x49);i.append(0x15);i.append(0xa7);i.append(0x9f);i.append(0xa6);i.append(0x4e);i.append(0x89);i.append(0xdc);i.append(0x78);i.append(0xc3);i.append(0xc6);i.append(0x41);i.append(0xd0);i.append(0xbb);i.append(0x2e);i.append(0xb1);i.append(0xb6);i.append(0xd6);i.append(0xc1);i.append(0x1f);i.append(0x07);i.append(0xea);i.append(0xc8);i.append(0xd4);i.append(0x8e);i.append(0x7c);i.append(0x81);i.append(0x6f);i.append(0x82);i.append(0xc3);i.append(0xc5);i.append(0x21);i.append(0x42);i.append(0x27);i.append(0xfc);i.append(0x2c);i.append(0x2d);i.append(0xe6);i.append(0x13);i.append(0x50);i.append(0x85);i.append(0x60);i.append(0xed);i.append(0xa7);i.append(0xc5);i.append(0x23);i.append(0x99);i.append(0xe5);i.append(0x32);i.append(0x27);i.append(0x5d);i.append(0xea);i.append(0xb0);i.append(0xdc);i.append(0xff);i.append(0x01);i.append(0x11);i.append(0xf9);i.append(0x20);i.append(0x44);i.append(0xb7);i.append(0x4d);i.append(0x3e);i.append(0x4a);i.append(0x7d);i.append(0x95);i.append(0x6f);i.append(0x42);i.append(0x7a);i.append(0x52);
            i
        }

        fn get_leaves_2(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x04);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x8f);i.append(0x48);i.append(0x6d);i.append(0x00);i.append(0x01);i.append(0x77);i.append(0xbc);i.append(0x87);i.append(0x18);i.append(0x9c);i.append(0x45);i.append(0x0c);i.append(0xe5);i.append(0x4a);i.append(0xb7);i.append(0x8d);i.append(0xdc);i.append(0x73);i.append(0xa6);i.append(0x01);i.append(0xdb);i.append(0xdc);i.append(0x2d);i.append(0xe2);i.append(0xbf);i.append(0x52);i.append(0x2e);i.append(0xba);i.append(0xc6);i.append(0x58);i.append(0xc4);i.append(0x85);i.append(0x72);i.append(0x1e);i.append(0x27);i.append(0x42);i.append(0xf0);i.append(0x2f);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x6f);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x03);i.append(0xaf);i.append(0xf6);i.append(0x13);i.append(0xb5);i.append(0x29);i.append(0x59);i.append(0xe3);i.append(0x04);i.append(0x5f);i.append(0x7c);i.append(0xcb);i.append(0xde);i.append(0xf6);i.append(0x89);i.append(0x25);i.append(0x9e);i.append(0xe6);i.append(0x59);i.append(0xed);i.append(0x29);i.append(0x07);i.append(0xcc);i.append(0x28);i.append(0xeb);i.append(0x24);i.append(0xfc);i.append(0xaf);i.append(0xa6);i.append(0x5e);i.append(0x28);i.append(0x1c);i.append(0x04);i.append(0x4f);i.append(0x45);i.append(0x4c);i.append(0x13);i.append(0x19);i.append(0x23);i.append(0x0b);i.append(0xbf);i.append(0xbe);i.append(0xa1);i.append(0xf4);i.append(0xa9);i.append(0x99);i.append(0xa4);i.append(0x33);i.append(0x04);i.append(0x36);i.append(0x5a);i.append(0xf5);i.append(0x49);i.append(0x45);i.append(0xe3);i.append(0x6e);i.append(0xa8);i.append(0xf9);i.append(0x54);i.append(0x89);i.append(0x46);i.append(0xd0);i.append(0x7c);i.append(0x1d);
            i
        }

        fn get_proof_2(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x04);i.append(0x13);i.append(0x3d);i.append(0x33);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x89);i.append(0x3e);i.append(0x33);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x48);i.append(0x40);i.append(0xdc);i.append(0x3a);i.append(0x58);i.append(0xd2);i.append(0xac);i.append(0xbc);i.append(0xea);i.append(0xcb);i.append(0x54);i.append(0x70);i.append(0x40);i.append(0x88);i.append(0x0f);i.append(0xc7);i.append(0x61);i.append(0x5e);i.append(0x67);i.append(0x54);i.append(0xe2);i.append(0xee);i.append(0x36);i.append(0x6d);i.append(0x5f);i.append(0x9a);i.append(0x6e);i.append(0xcd);i.append(0x1f);i.append(0xec);i.append(0x39);i.append(0x84);i.append(0xf7);i.append(0x00);i.append(0x60);i.append(0x50);i.append(0xbb);i.append(0x67);i.append(0x34);i.append(0xed);i.append(0x9a);i.append(0x77);i.append(0xb4);i.append(0x0d);i.append(0x03);i.append(0xbc);i.append(0x4b);i.append(0x87);i.append(0x7b);i.append(0x6b);i.append(0xa8);i.append(0x22);i.append(0x12);i.append(0xcb);i.append(0x64);i.append(0x20);i.append(0x5e);i.append(0xf1);i.append(0x19);i.append(0xaa);i.append(0xae);i.append(0x94);i.append(0x96);i.append(0x9d);i.append(0xc1);i.append(0x95);i.append(0x08);i.append(0xc9);i.append(0xe6);i.append(0x8a);i.append(0x69);i.append(0x07);i.append(0x30);i.append(0x66);i.append(0xf3);i.append(0x9c);i.append(0x0d);i.append(0xed);i.append(0xf4);i.append(0x92);i.append(0x41);i.append(0x09);i.append(0x98);i.append(0xc3);i.append(0xc6);i.append(0xab);i.append(0x37);i.append(0xb9);i.append(0x30);i.append(0xd6);i.append(0x98);i.append(0xbf);i.append(0x72);i.append(0x2e);i.append(0xfe);i.append(0xe8);i.append(0x2b);i.append(0x69);i.append(0x79);i.append(0xd1);i.append(0x7b);i.append(0xe0);i.append(0x53);i.append(0x74);i.append(0x27);i.append(0x4c);i.append(0xbe);i.append(0xc6);i.append(0xd6);i.append(0xb9);i.append(0x94);i.append(0x06);i.append(0x2d);i.append(0x99);i.append(0x80);i.append(0x1c);i.append(0x69);i.append(0x66);i.append(0x5a);i.append(0x68);i.append(0xc0);i.append(0xec);i.append(0x6a);i.append(0x95);i.append(0x2a);i.append(0x51);i.append(0xc4);i.append(0x69);i.append(0x70);i.append(0xea);i.append(0x70);i.append(0xb4);i.append(0xe3);i.append(0x7e);i.append(0x7b);i.append(0x1e);i.append(0x4e);i.append(0x95);i.append(0x9c);i.append(0xde);i.append(0xf7);i.append(0x84);i.append(0xe2);i.append(0x9e);i.append(0xe0);i.append(0xd7);i.append(0xef);i.append(0xc3);i.append(0x1e);i.append(0x39);i.append(0xd3);i.append(0xc7);i.append(0xb4);i.append(0xc4);i.append(0x0a);i.append(0xec);i.append(0xf1);i.append(0xba);i.append(0x4a);i.append(0x0b);i.append(0xa5);i.append(0xb0);i.append(0x6e);i.append(0xb9);i.append(0x68);i.append(0xe8);i.append(0x37);i.append(0x4c);i.append(0x60);i.append(0xcb);i.append(0xfe);i.append(0xd2);i.append(0x5d);i.append(0x96);i.append(0x1f);i.append(0x7c);i.append(0x90);i.append(0x2e);i.append(0x54);i.append(0x91);i.append(0x03);i.append(0x64);i.append(0xfd);i.append(0x04);i.append(0x2e);i.append(0x34);i.append(0x3f);i.append(0xaa);i.append(0x23);i.append(0x6c);i.append(0xc8);i.append(0x0a);i.append(0x8a);i.append(0x91);i.append(0xd0);i.append(0x57);i.append(0x11);i.append(0x58);i.append(0x30);i.append(0x6c);i.append(0x2c);i.append(0x60);i.append(0xac);i.append(0xc9);i.append(0x98);i.append(0x30);i.append(0x44);i.append(0x6f);i.append(0xbb);i.append(0x0d);i.append(0x17);i.append(0xee);i.append(0x33);i.append(0x9b);i.append(0x7b);i.append(0xa8);i.append(0x6f);i.append(0xb4);i.append(0x54);i.append(0x07);i.append(0xd2);i.append(0x04);i.append(0x0e);i.append(0xaa);i.append(0xe7);i.append(0xeb);i.append(0x1c);i.append(0x65);i.append(0x46);i.append(0x8d);i.append(0xe5);i.append(0x0b);i.append(0x7c);i.append(0x9d);i.append(0xf1);i.append(0xda);i.append(0x89);i.append(0x8e);i.append(0xe6);i.append(0x15);i.append(0x79);i.append(0x2c);i.append(0x22);i.append(0x3b);i.append(0xf4);i.append(0x0f);i.append(0xa4);i.append(0x76);i.append(0xab);i.append(0xd5);i.append(0x72);i.append(0xfe);i.append(0xb8);i.append(0xe6);i.append(0x9d);i.append(0x1c);i.append(0x6a);i.append(0xd5);i.append(0xb9);i.append(0xf7);i.append(0xb6);i.append(0x7e);i.append(0x7d);i.append(0xa6);i.append(0xba);i.append(0xcd);i.append(0x7d);i.append(0x00);i.append(0x0b);i.append(0x4f);i.append(0x6e);i.append(0xf4);i.append(0x44);i.append(0xf6);i.append(0xa0);i.append(0x4a);i.append(0x62);i.append(0xc3);i.append(0x61);i.append(0x9b);i.append(0x70);i.append(0x2b);i.append(0x12);i.append(0x47);i.append(0xdc);i.append(0x35);i.append(0xfc);i.append(0xe6);i.append(0x6a);i.append(0x26);i.append(0xb8);i.append(0x71);i.append(0x25);i.append(0x01);i.append(0xf8);i.append(0xa5);i.append(0xf1);i.append(0x20);i.append(0x97);i.append(0x80);i.append(0x20);i.append(0xbd);i.append(0x4c);i.append(0xef);i.append(0xd0);i.append(0xb3);i.append(0xc6);i.append(0xda);i.append(0xa8);i.append(0xf8);i.append(0xa2);i.append(0x01);i.append(0x1d);i.append(0x25);i.append(0x5e);i.append(0xd2);i.append(0xb4);i.append(0xb8);i.append(0x8b);i.append(0xb8);i.append(0x6a);i.append(0x29);i.append(0xad);i.append(0x5b);i.append(0x93);i.append(0x40);i.append(0xc3);i.append(0x95);i.append(0x42);i.append(0x5d);i.append(0x2c);i.append(0x73);i.append(0xd7);i.append(0x9f);i.append(0x67);i.append(0xe4);i.append(0x0a);i.append(0x1e);i.append(0xca);i.append(0x3e);i.append(0x16);i.append(0xc5);i.append(0x1d);i.append(0x53);i.append(0x4a);i.append(0x42);i.append(0x41);i.append(0xd3);i.append(0x72);i.append(0x3c);i.append(0xca);i.append(0x00);i.append(0x1a);i.append(0x21);i.append(0x87);i.append(0x67);i.append(0xa0);i.append(0xa8);i.append(0xc1);i.append(0x05);i.append(0xc4);i.append(0x4a);i.append(0x59);i.append(0xa9);i.append(0xd2);i.append(0x50);i.append(0x76);i.append(0x72);i.append(0xb7);i.append(0xb9);i.append(0x4a);i.append(0x5b);i.append(0x51);i.append(0x3a);i.append(0x5b);i.append(0xa6);i.append(0x55);i.append(0x75);i.append(0x28);i.append(0x80);i.append(0x04);i.append(0x95);i.append(0xda);i.append(0x9c);i.append(0x35);i.append(0x5d);i.append(0x2c);i.append(0x15);i.append(0x25);i.append(0x2e);i.append(0xe2);i.append(0xb6);i.append(0x87);i.append(0xc4);i.append(0xd5);i.append(0x2f);i.append(0x61);i.append(0x66);i.append(0xbe);i.append(0x65);i.append(0x2c);i.append(0x90);i.append(0xc9);i.append(0x93);i.append(0x48);i.append(0x33);i.append(0xf5);i.append(0x2e);i.append(0x92);i.append(0xf8);i.append(0xdc);i.append(0x22);i.append(0x7d);i.append(0xa4);i.append(0xd9);i.append(0xa0);i.append(0x52);i.append(0x91);i.append(0x35);i.append(0x3c);i.append(0xaa);i.append(0x25);i.append(0x7d);i.append(0x52);i.append(0x28);i.append(0x20);i.append(0xc5);i.append(0xd1);i.append(0x4c);i.append(0xc7);i.append(0x45);i.append(0xa8);i.append(0x03);i.append(0x77);i.append(0xab);i.append(0xdb);i.append(0xb4);i.append(0x44);i.append(0xfd);i.append(0x9a);i.append(0x62);i.append(0xe1);i.append(0x28);i.append(0x3e);i.append(0xb6);i.append(0x84);i.append(0xc7);i.append(0x1a);i.append(0x98);i.append(0x2a);i.append(0xfa);i.append(0x72);i.append(0xed);i.append(0x32);i.append(0x76);i.append(0x43);i.append(0xf3);i.append(0x67);i.append(0x20);i.append(0x15);i.append(0xaa);i.append(0x0f);i.append(0xbf);i.append(0xfa);i.append(0xe7);i.append(0xf8);i.append(0xb3);i.append(0x14);i.append(0x27);i.append(0xb6);i.append(0x58);i.append(0xe6);i.append(0x36);i.append(0xb3);i.append(0xdc);i.append(0xe9);i.append(0xa6);i.append(0x51);i.append(0xa7);i.append(0x30);i.append(0xee);i.append(0xf6);i.append(0x95);i.append(0x59);i.append(0x3a);i.append(0x14);i.append(0xe2);i.append(0xf3);i.append(0x38);i.append(0xa7);i.append(0x45);i.append(0x70);i.append(0x53);i.append(0x91);i.append(0x3a);i.append(0x0e);i.append(0xc5);i.append(0x9f);i.append(0xb8);i.append(0x68);i.append(0x27);i.append(0xb9);i.append(0x3b);i.append(0x79);i.append(0x44);i.append(0xc5);i.append(0x73);i.append(0x32);i.append(0x47);i.append(0x3c);i.append(0xf3);i.append(0x77);i.append(0x3d);i.append(0x22);i.append(0x2c);i.append(0x61);i.append(0x34);i.append(0x7c);i.append(0x78);i.append(0xf2);i.append(0x26);i.append(0x8c);i.append(0x94);i.append(0x85);i.append(0x29);i.append(0x32);i.append(0x50);i.append(0xe2);i.append(0xaf);i.append(0x08);i.append(0xbb);i.append(0x35);i.append(0x37);i.append(0xd5);i.append(0xbc);i.append(0x62);i.append(0x0c);i.append(0x74);i.append(0xc1);i.append(0x35);i.append(0x86);i.append(0x2e);i.append(0x55);i.append(0xeb);i.append(0xa3);i.append(0xa5);i.append(0x2a);i.append(0x52);i.append(0x30);i.append(0x14);i.append(0x45);i.append(0xa1);i.append(0xee);i.append(0x28);i.append(0xa2);i.append(0xd5);i.append(0xac);i.append(0x12);i.append(0x19);i.append(0xa0);i.append(0x0b);i.append(0xc9);i.append(0x0a);i.append(0x43);i.append(0x77);i.append(0xe8);i.append(0xcf);i.append(0xa3);i.append(0x23);i.append(0x20);i.append(0xf8);i.append(0x4f);i.append(0x04);i.append(0x6a);i.append(0x6d);i.append(0x83);i.append(0xba);
            i
        }

        // 0xac4b38b0dd9d7562b44102f26ef2292d076a533cbed89f531f6a63f939fdb475
        fn mmr_root_2(self: @ContractState) -> u256 {
            let mut i: Array<u8> = Default::default();
            i.append(0xac);i.append(0x4b);i.append(0x38);i.append(0xb0);i.append(0xdd);i.append(0x9d);i.append(0x75);i.append(0x62);i.append(0xb4);i.append(0x41);i.append(0x02);i.append(0xf2);i.append(0x6e);i.append(0xf2);i.append(0x29);i.append(0x2d);i.append(0x07);i.append(0x6a);i.append(0x53);i.append(0x3c);i.append(0xbe);i.append(0xd8);i.append(0x9f);i.append(0x53);i.append(0x1f);i.append(0x6a);i.append(0x63);i.append(0xf9);i.append(0x39);i.append(0xfd);i.append(0xb4);i.append(0x75);
            *hashes_to_u256s(i.span()).expect('hashes_to_u256s works').at(0)
        }

        fn get_leaves(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x04);i.append(0xc5);i.append(0x01);i.append(0x00);i.append(0x04);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x27);i.append(0x44);i.append(0xcc);i.append(0x3e);i.append(0x4b);i.append(0x2f);i.append(0x9d);i.append(0x1d);i.append(0x92);i.append(0xce);i.append(0xa9);i.append(0x3b);i.append(0x8c);i.append(0x1c);i.append(0xad);i.append(0x27);i.append(0x76);i.append(0x7e);i.append(0x41);i.append(0xe5);i.append(0x21);i.append(0x42);i.append(0x70);i.append(0xe2);i.append(0x19);i.append(0xd6);i.append(0x11);i.append(0xe3);i.append(0x0d);i.append(0x28);i.append(0xd2);i.append(0xcc);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xae);i.append(0xb4);i.append(0x7a);i.append(0x26);i.append(0x93);i.append(0x93);i.append(0x29);i.append(0x7f);i.append(0x4b);i.append(0x0a);i.append(0x3c);i.append(0x9c);i.append(0x9c);i.append(0xfd);i.append(0x00);i.append(0xc7);i.append(0xa4);i.append(0x19);i.append(0x52);i.append(0x55);i.append(0x27);i.append(0x4c);i.append(0xf3);i.append(0x9d);i.append(0x83);i.append(0xda);i.append(0xbc);i.append(0x2f);i.append(0xcc);i.append(0x9f);i.append(0xf3);i.append(0xd7);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
            i
        }

        fn get_proof(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x04);i.append(0x04);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x0a);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x10);i.append(0x3b);i.append(0xac);i.append(0xf5);i.append(0xac);i.append(0x3f);i.append(0xf9);i.append(0x12);i.append(0xcc);i.append(0xd0);i.append(0xb2);i.append(0x02);i.append(0x68);i.append(0xad);i.append(0x05);i.append(0x4a);i.append(0xef);i.append(0xd2);i.append(0xde);i.append(0x8d);i.append(0x23);i.append(0x3a);i.append(0xec);i.append(0xe8);i.append(0x16);i.append(0x6c);i.append(0xb1);i.append(0x58);i.append(0xfc);i.append(0xa1);i.append(0x0f);i.append(0x2b);i.append(0xfd);i.append(0xa5);i.append(0xe1);i.append(0xca);i.append(0xfc);i.append(0xd9);i.append(0x50);i.append(0x44);i.append(0x96);i.append(0x65);i.append(0xff);i.append(0x18);i.append(0x86);i.append(0xa3);i.append(0x1a);i.append(0xba);i.append(0x5a);i.append(0x70);i.append(0x2c);i.append(0x6a);i.append(0xe6);i.append(0x44);i.append(0xdf);i.append(0x4b);i.append(0x36);i.append(0xc2);i.append(0xd4);i.append(0x1c);i.append(0x3a);i.append(0x27);i.append(0xed);i.append(0x83);i.append(0x8c);i.append(0x86);i.append(0x91);i.append(0x78);i.append(0x51);i.append(0x80);i.append(0x2d);i.append(0x6c);i.append(0xf4);i.append(0x21);i.append(0xf5);i.append(0x68);i.append(0x77);i.append(0x29);i.append(0xba);i.append(0x4a);i.append(0x43);i.append(0x60);i.append(0xe3);i.append(0xf6);i.append(0x1a);i.append(0x2e);i.append(0x76);i.append(0x40);i.append(0xfa);i.append(0xef);i.append(0x05);i.append(0x85);i.append(0x11);i.append(0x84);i.append(0x3b);i.append(0xde);i.append(0x81);i.append(0xe2);i.append(0x99);i.append(0x90);i.append(0x1d);i.append(0x86);i.append(0x88);i.append(0xfb);i.append(0x6f);i.append(0xf7);i.append(0xda);i.append(0xff);i.append(0x09);i.append(0x2c);i.append(0x5b);i.append(0xad);i.append(0xf2);i.append(0xd1);i.append(0x11);i.append(0xf1);i.append(0x76);i.append(0x8b);i.append(0x2a);i.append(0x1f);i.append(0x74);i.append(0x86);i.append(0xa8);i.append(0xce);i.append(0x15);i.append(0x74);i.append(0x6a);i.append(0xd5);i.append(0xdb);
            i
        }


        // 0xebfa14a7554db04e6128dc6102bb51e44970825d4c2bfb4c4b237af4efe7a791
        fn mmr_root(self: @ContractState) -> u256 {
            let mut i: Array<u8> = Default::default();
            i.append(0xeb);i.append(0xfa);i.append(0x14);i.append(0xa7);i.append(0x55);i.append(0x4d);i.append(0xb0);i.append(0x4e);i.append(0x61);i.append(0x28);i.append(0xdc);i.append(0x61);i.append(0x02);i.append(0xbb);i.append(0x51);i.append(0xe4);i.append(0x49);i.append(0x70);i.append(0x82);i.append(0x5d);i.append(0x4c);i.append(0x2b);i.append(0xfb);i.append(0x4c);i.append(0x4b);i.append(0x23);i.append(0x7a);i.append(0xf4);i.append(0xef);i.append(0xe7);i.append(0xa7);i.append(0x91);
            *hashes_to_u256s(i.span()).expect('hashes_to_u256s works').at(0)
        }

        fn get_message_and_signature(self: @ContractState, y_parity: bool) -> (u256, Signature, u256, u256, EthAddress) {
            let msg_hash = 0xe888fbb4cf9ae6254f19ba12e6d9af54788f195a6f509ca3e934f78d7a71dd85;
            let r:u256 = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
            let s:u256 = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;

            let (public_key_x, public_key_y) = if y_parity {
                (
                    0xa9a02d48081294b9bb0d8740d70d3607feb20876964d432846d9b9100b91eefd,
                    0x18b410b5523a1431024a6ab766c89fa5d062744c75e49efb9925bf8025a7c09e
                )
            } else {
                (
                    0x57a910a2a58ef7d57f452e1f6ea7ee0080789091de946b0ca6e5c6af2c8ff5c8,
                    0x249d233d0d21f35db55ce852edbd340d31e92ea4d591886149ca5d89911331ac
                )
            };
            let eth_address = 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256.into();

            (msg_hash, Signature { r, s, y_parity }, public_key_x, public_key_y, eth_address)
        }

        fn get_lean_beefy_proof(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(1); i.append(4); i.append(109); i.append(104); i.append(128); i.append(179); i.append(10); i.append(26); i.append(159); i.append(204); i.append(101); i.append(198); i.append(159); i.append(193); i.append(248); i.append(252); i.append(202); i.append(209); i.append(86); i.append(155); i.append(24); i.append(110); i.append(223); i.append(138); i.append(34); i.append(95); i.append(114); i.append(204); i.append(31); i.append(32); i.append(122); i.append(203); i.append(1); i.append(9); i.append(158); i.append(139); i.append(81); i.append(39); i.append(0); i.append(0); i.append(0); i.append(3); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(4); i.append(128); i.append(1); i.append(0); i.append(0); i.append(0); i.append(4); i.append(120); i.append(22); i.append(51); i.append(21); i.append(207); i.append(121); i.append(231); i.append(214); i.append(63); i.append(72); i.append(203); i.append(215); i.append(107); i.append(111); i.append(16); i.append(79); i.append(100); i.append(125); i.append(7); i.append(1); i.append(69); i.append(205); i.append(94); i.append(253); i.append(203); i.append(131); i.append(255); i.append(72); i.append(221); i.append(139); i.append(248); i.append(93); i.append(63); i.append(165); i.append(61); i.append(175); i.append(90); i.append(88); i.append(98); i.append(215); i.append(96); i.append(93); i.append(92); i.append(252); i.append(175); i.append(190); i.append(205); i.append(88); i.append(227); i.append(166); i.append(55); i.append(16); i.append(191); i.append(34); i.append(214); i.append(117); i.append(227); i.append(120); i.append(167); i.append(128); i.append(50); i.append(187); i.append(183); i.append(11); i.append(0);
            i
        }

        fn get_current_validator_addresses(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
            i
        }

        fn get_lean_beefy_proof_2(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(1); i.append(4); i.append(109); i.append(104); i.append(128); i.append(9); i.append(60); i.append(135); i.append(194); i.append(44); i.append(243); i.append(27); i.append(165); i.append(135); i.append(135); i.append(229); i.append(11); i.append(224); i.append(172); i.append(76); i.append(236); i.append(61); i.append(110); i.append(240); i.append(137); i.append(146); i.append(98); i.append(184); i.append(184); i.append(64); i.append(91); i.append(232); i.append(194); i.append(81); i.append(142); i.append(207); i.append(195); i.append(79); i.append(0); i.append(0); i.append(0); i.append(7); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(0); i.append(4); i.append(128); i.append(1); i.append(0); i.append(0); i.append(0); i.append(4); i.append(7); i.append(85); i.append(165); i.append(1); i.append(18); i.append(230); i.append(178); i.append(155); i.append(188); i.append(171); i.append(255); i.append(211); i.append(252); i.append(229); i.append(215); i.append(241); i.append(16); i.append(188); i.append(10); i.append(199); i.append(25); i.append(59); i.append(8); i.append(27); i.append(31); i.append(226); i.append(91); i.append(136); i.append(81); i.append(54); i.append(65); i.append(79); i.append(24); i.append(77); i.append(63); i.append(130); i.append(185); i.append(74); i.append(83); i.append(235); i.append(21); i.append(248); i.append(137); i.append(37); i.append(60); i.append(123); i.append(104); i.append(93); i.append(171); i.append(8); i.append(53); i.append(104); i.append(103); i.append(175); i.append(141); i.append(88); i.append(22); i.append(137); i.append(200); i.append(180); i.append(193); i.append(172); i.append(155); i.append(60); i.append(1);    
            i
        }

        fn get_current_validator_addresses_2(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(224); i.append(76); i.append(197); i.append(94); i.append(190); i.append(225); i.append(203); i.append(206); i.append(85); i.append(47); i.append(37); i.append(14); i.append(133); i.append(197); i.append(123); i.append(112); i.append(178); i.append(226); i.append(98); i.append(91);
            i
        }

        /// @dev Registers the voters and initializes their voting status to true (can vote)
        fn _register_voters(
            ref self: ContractState,
            voter_1: ContractAddress,
            voter_2: ContractAddress,
            voter_3: ContractAddress
        ) {
            self.registered_voter.write(voter_1, true);
            self.can_vote.write(voter_1, true);

            self.registered_voter.write(voter_2, true);
            self.can_vote.write(voter_2, true);

            self.registered_voter.write(voter_3, true);
            self.can_vote.write(voter_3, true);
        }

        fn get_expected_raw_storage(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0xda);i.append(0xc0);i.append(0xc7);i.append(0x8d);i.append(0xd0);i.append(0xd9);i.append(0x2a);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0xc6);i.append(0xb0);i.append(0x01);i.append(0x5d);i.append(0x90);i.append(0xbe);i.append(0x39);i.append(0xb6);i.append(0x73);i.append(0x59);i.append(0x81);i.append(0x01);i.append(0x00);i.append(0x00);i.append(0x00);i.append(0x00);
            i
        }

        fn get_key(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0xcb);i.append(0xed);i.append(0xab);i.append(0x01);i.append(0x91);i.append(0x91);i.append(0x42);i.append(0x83);i.append(0x92);i.append(0x36);i.append(0xb4);i.append(0xc4);i.append(0x81);i.append(0xd7);i.append(0x0a);i.append(0xdb);i.append(0x4c);i.append(0x72);i.append(0x01);i.append(0x6d);i.append(0x74);i.append(0xb6);i.append(0x3a);i.append(0xe8);i.append(0x3d);i.append(0x79);i.append(0xb0);i.append(0x2e);i.append(0xfd);i.append(0xb5);i.append(0x52);i.append(0x8e);i.append(0xe9);i.append(0x67);i.append(0x60);i.append(0xd2);i.append(0x74);i.append(0x65);i.append(0x3a);i.append(0x39);i.append(0xb4);i.append(0x29);i.append(0xa8);i.append(0x7e);i.append(0xba);i.append(0xae);i.append(0x9d);i.append(0x3a);i.append(0xa4);i.append(0xfd);i.append(0xf5);i.append(0x8b);i.append(0x90);i.append(0x96);i.append(0xcf);i.append(0x0b);i.append(0xeb);i.append(0xc7);i.append(0xc4);i.append(0xe5);i.append(0xa4);i.append(0xc2);i.append(0xed);i.append(0x8d);
            i
        }

        fn get_root(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0xfd);i.append(0xc5);i.append(0x6b);i.append(0xd3);i.append(0xa6);i.append(0xe7);i.append(0x87);i.append(0x90);i.append(0xed);i.append(0xf0);i.append(0x11);i.append(0xe2);i.append(0xe7);i.append(0x46);i.append(0x8d);i.append(0xb8);i.append(0xe4);i.append(0x1c);i.append(0xc6);i.append(0xad);i.append(0x6a);i.append(0x35);i.append(0x23);i.append(0xb4);i.append(0xac);i.append(0xc0);i.append(0x35);i.append(0xfc);i.append(0x2f);i.append(0xf4);i.append(0x10);i.append(0xa2);
            i
        }

        fn get_storage_proof_data(self: @ContractState) -> (Array<u8>, Array<usize>) {
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

        fn get_hashes(self: @ContractState) -> Array<u8> {
            let mut i: Array<u8> = Default::default();
            i.append(0x4e);i.append(0xe2);i.append(0x3d);i.append(0x25);i.append(0x8f);i.append(0xfd);i.append(0x21);i.append(0xf2);i.append(0x05);i.append(0x60);i.append(0x56);i.append(0x55);i.append(0x01);i.append(0x14);i.append(0xea);i.append(0x9b);i.append(0xd2);i.append(0x4b);i.append(0x4d);i.append(0x1e);i.append(0x7d);i.append(0x8e);i.append(0x21);i.append(0x71);i.append(0x46);i.append(0xa0);i.append(0xff);i.append(0x51);i.append(0xef);i.append(0x35);i.append(0xfb);i.append(0x40);
            i.append(0x17);i.append(0x7e);i.append(0x3d);i.append(0xf8);i.append(0x30);i.append(0x1c);i.append(0xb7);i.append(0x01);i.append(0x3f);i.append(0x74);i.append(0x16);i.append(0xcc);i.append(0x6c);i.append(0x0f);i.append(0xac);i.append(0xdb);i.append(0xea);i.append(0xdd);i.append(0xde);i.append(0xd6);i.append(0x50);i.append(0x01);i.append(0xad);i.append(0xf6);i.append(0x97);i.append(0x3f);i.append(0x02);i.append(0xd9);i.append(0xb0);i.append(0xbf);i.append(0xad);i.append(0x3a);
            i.append(0xb7);i.append(0x96);i.append(0xfe);i.append(0x3a);i.append(0x18);i.append(0x16);i.append(0x36);i.append(0x82);i.append(0x72);i.append(0xdf);i.append(0xa8);i.append(0x57);i.append(0x06);i.append(0x74);i.append(0xb8);i.append(0x97);i.append(0x7a);i.append(0x0e);i.append(0x1a);i.append(0x07);i.append(0xe5);i.append(0x33);i.append(0x0b);i.append(0xfc);i.append(0x23);i.append(0x98);i.append(0xf8);i.append(0xaa);i.append(0x12);i.append(0x93);i.append(0xf4);i.append(0x9a);
            i.append(0x09);i.append(0x62);i.append(0xc9);i.append(0xc6);i.append(0xba);i.append(0xab);i.append(0x45);i.append(0x58);i.append(0x60);i.append(0xe6);i.append(0xb8);i.append(0x0f);i.append(0xd9);i.append(0xf6);i.append(0x72);i.append(0xe0);i.append(0x9b);i.append(0x62);i.append(0x24);i.append(0x38);i.append(0xf3);i.append(0xdf);i.append(0xd6);i.append(0x5a);i.append(0x29);i.append(0x4b);i.append(0x4f);i.append(0xb0);i.append(0x38);i.append(0xe3);i.append(0x8c);i.append(0x8e);
            i.append(0xfd);i.append(0xc5);i.append(0x6b);i.append(0xd3);i.append(0xa6);i.append(0xe7);i.append(0x87);i.append(0x90);i.append(0xed);i.append(0xf0);i.append(0x11);i.append(0xe2);i.append(0xe7);i.append(0x46);i.append(0x8d);i.append(0xb8);i.append(0xe4);i.append(0x1c);i.append(0xc6);i.append(0xad);i.append(0x6a);i.append(0x35);i.append(0x23);i.append(0xb4);i.append(0xac);i.append(0xc0);i.append(0x35);i.append(0xfc);i.append(0x2f);i.append(0xf4);i.append(0x10);i.append(0xa2);
            i.append(0xdc);i.append(0xb6);i.append(0x55);i.append(0x78);i.append(0x71);i.append(0x7e);i.append(0xd8);i.append(0x66);i.append(0x34);i.append(0xa8);i.append(0xce);i.append(0xa3);i.append(0x20);i.append(0x44);i.append(0x91);i.append(0x62);i.append(0x48);i.append(0xc2);i.append(0x97);i.append(0x21);i.append(0x8f);i.append(0xfb);i.append(0x61);i.append(0x1f);i.append(0x69);i.append(0x3a);i.append(0x72);i.append(0x43);i.append(0x81);i.append(0xbe);i.append(0x98);i.append(0x2f);
            i.append(0xbd);i.append(0x80);i.append(0x21);i.append(0x0e);i.append(0x32);i.append(0xa5);i.append(0x31);i.append(0x36);i.append(0x35);i.append(0x94);i.append(0x4b);i.append(0x7f);i.append(0xea);i.append(0x4c);i.append(0x10);i.append(0xaf);i.append(0x4b);i.append(0x61);i.append(0x56);i.append(0x14);i.append(0x3b);i.append(0x85);i.append(0x98);i.append(0x4a);i.append(0xec);i.append(0xaa);i.append(0x64);i.append(0xb2);i.append(0x17);i.append(0xf4);i.append(0xa4);i.append(0x0a);
            i
        }
    }

    /// @dev Asserts implementation for the Vote contract
    #[generate_trait]
    impl AssertsImpl of AssertsTrait {
        // @dev Internal function that checks if an address is allowed to vote
        fn _assert_allowed(ref self: ContractState, address: ContractAddress) {
            let is_voter: bool = self.registered_voter.read((address));
            let can_vote: bool = self.can_vote.read((address));

            if (can_vote == false) {
                self.emit(UnauthorizedAttempt { unauthorized_address: address,  });
            }

            assert(is_voter == true, 'USER_NOT_REGISTERED');
            assert(can_vote == true, 'USER_ALREADY_VOTED');
        }
    }

    /// @dev Implement the VotingResultTrait for the Vote contract
    #[generate_trait]
    impl VoteResultFunctionsImpl of VoteResultFunctionsTrait {
        // @dev Internal function to get the voting results (yes and no vote counts)
        fn _get_voting_result(self: @ContractState) -> (u8, u8) {
            let n_yes: u8 = self.yes_votes.read();
            let n_no: u8 = self.no_votes.read();

            return (n_yes, n_no);
        }

        // @dev Internal function to calculate the voting results in percentage
        fn _get_voting_result_in_percentage(self: @ContractState) -> (u8, u8) {
            let n_yes: u8 = self.yes_votes.read();
            let n_no: u8 = self.no_votes.read();

            let total_votes: u8 = n_yes + n_no;

            let yes_percentage: u8 = (n_yes * 100_u8) / (total_votes);
            let no_percentage: u8 = (n_no * 100_u8) / (total_votes);

            return (yes_percentage, no_percentage);
        }
    }
}
