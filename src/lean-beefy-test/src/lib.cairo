/// The Contract Class Hash is 0x8873aa28af0a0e6ac6aa647aa8e8c02cea7752bb7950284dbbbae1be35e9cb
/// The contract is deployed on the Starknet testnet. The contract address is 0x056d42ddcc1c85959989aaef369e284804a8e59cc5ce519e579fcb121b18f724

/// @dev Core Library Imports for the Traits outside the Starknet Contract
use starknet::ContractAddress;
use array::{ArrayTrait, SpanTrait};
use option::OptionTrait;
use result::ResultTrait;

use traits::{Default, Into, TryInto};
use starknet::{
    Store, StorageBaseAddress, SyscallResult,
    syscalls::{storage_read_syscall, storage_write_syscall},
    contract_address::{Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
    class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
};
use serde::Serde;

/// @dev Trait defining the functions that can be implemented or called by the Starknet Contract
#[starknet::interface]
trait VoteTrait<T> {
    fn unset_validator_set_info(ref self: T, validator_set_id: u64);
    fn set_validator_set_info(ref self: T, validator_set_id: u64, validator_set_list: Array<u256>);
    fn set_validator_set_info_u8_array(
        ref self: T, validator_set_id: u64, validator_set_list_u8_array: Array<u8>
    );
    fn calculate_merkle_hash_for_validator_set(ref self: T, validator_set_id: u64);
    fn full_reset_current_beefy_proof(ref self: T);
    fn verify_lean_beefy_proof(ref self: T, lean_beefy_proof: Array<u8>, sig_ver_limit: Option<usize>);
    fn verify_beefy_mmr_leaves_proof(ref self: T, leaves: Array<u8>, proof: Array<u8>);
    fn verify_beefy_para_data(
        ref self: T, leaf_index: usize, leaf: Array<u8>, proof: Array<u8>, number_of_leaves: usize
    );
    fn validate_next_validator_set_info(ref self: T);
    fn finalize_current_lean_beefy_proof(ref self: T);
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
impl StoreOptionT<
    T, impl TCopy: Copy<T>, impl TDrop: Drop<T>, impl TStore: Store<T>, 
> of Store<Option<T>> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Option<T>> {
        StoreOptionT::read_at_offset(address_domain, base, 0)
    }

    fn write(address_domain: u32, base: StorageBaseAddress, value: Option<T>) -> SyscallResult<()> {
        StoreOptionT::write_at_offset(address_domain, base, 0, value)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8
    ) -> SyscallResult<Option<T>> {
        assert(Store::<T>::size() < 255, 'T too large to option');
        let exists: bool = Store::<bool>::read_at_offset(address_domain, base, offset)
            .expect('bool should read');
        offset += 1;

        if exists == false {
            return SyscallResult::Ok(Option::None);
        }

        let value = Store::<T>::read_at_offset(address_domain, base, offset).unwrap();
        offset += Store::<T>::size();

        SyscallResult::Ok(Option::Some(value))
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, mut offset: u8, mut value: Option<T>
    ) -> SyscallResult<()> {
        assert(Store::<T>::size() < 255, 'T too large to option');

        let was_value: bool = Store::<bool>::read_at_offset(address_domain, base, offset)
            .expect('bool should read');

        match value {
            Option::Some(v) => {
                Store::<bool>::write_at_offset(address_domain, base, offset, true);
                offset += 1;
                Store::<T>::write_at_offset(address_domain, base, offset, v);
                offset += Store::<T>::size();
            },
            Option::None(()) => {
                if was_value {
                    Store::<bool>::write_at_offset(address_domain, base, offset, false);
                    offset += 1;
                    let mut itr: usize = 0;
                    let t_size: usize = Store::<T>::size().into();
                    loop {
                        if itr == t_size {
                            break;
                        }
                        Store::<felt252>::write_at_offset(
                            address_domain, base, offset, Default::default()
                        );
                        offset += 1;
                        itr = itr + 1;
                    };
                } else {};
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
    use alexandria_substrate::substrate_storage_read_proof_verifier::{
        verify_substrate_storage_read_proof, verify_substrate_storage_read_proof_given_hashes,
        convert_u8_subarray_to_u8_array
    };
    use alexandria_substrate::lean_beefy_verifier::{keccak_be,
        decode_paradata, Slice, u256_byte_reverse, keccak_le, Range,
        encoded_opaque_leaves_to_leaves, u8_eth_addresses_to_u256, verify_beefy_signatures,
        get_mmr_root, VALIDATOR_ADDRESS_LEN, get_lean_beefy_proof_metadata, BeefyProofInfo,
        BeefyAuthoritySet, BeefyData, hashes_to_u256s, verify_merkle_proof, get_hashes_from_items,
        merkelize_for_merkle_root, encoded_opaque_leaves_to_hashes, verify_mmr_leaves_proof
    };
    use core::clone::Clone;
    use alexandria_math::sha256::sha256;
    use alexandria_math::sha512::{sha512};
    use zeroable::Zeroable;

    use super::{StoreFelt252Array, StoreOptionT};

    use traits::{Into, TryInto};
    use starknet::{
        secp256_trait::{Signature, verify_eth_signature, Secp256PointTrait, signature_from_vrs},
        Store, StorageBaseAddress, SyscallResult,
        syscalls::{storage_read_syscall, storage_write_syscall},
        contract_address::{Felt252TryIntoContractAddress, ContractAddressIntoFelt252},
        class_hash::{ClassHash, Felt252TryIntoClassHash, ClassHashIntoFelt252}
    };
    use starknet::secp256k1::{Secp256k1Point, Secp256k1PointImpl};
    use starknet::{eth_address::U256IntoEthAddress, EthAddress};
    use serde::Serde;
    use debug::PrintTrait;


    use poseidon::poseidon_hash_span;
    use starknet::storage_access::{Felt252TryIntoStorageAddress, storage_base_address_from_felt252, storage_address_from_base_and_offset};
    use starknet::StorageAddress;

    type ValidatorSetId = u64;
    const PARA_ID: u32 = 2110;

    const READ_PROOF_KEY_ADDRESS: felt252 = 'read_proof_key';
    const READ_PROOF_VALUE_ADDRESS: felt252 = 'read_proof_value';


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
        validator_set_list: LegacyMap::<(ValidatorSetId, u32), u256>,
        current_mmr_root: Option<u256>,
        current_beefy_proof_info: Option<BeefyProofInfo>,
        current_beefy_data: Option<BeefyData>,
        current_para_data: Option<ParaData>,
        broken_validator_chain_info: Option<(u32, ValidatorSetId, u32, ValidatorSetId)>,
        unvalidated_validator_set_info: Option<(u32, ValidatorSetId)>,
        last_mmr_root: Option<u256>,
        last_beefy_proof_info: Option<BeefyProofInfo>,
        last_beefy_data: Option<BeefyData>,
        last_para_data: Option<ParaData>,
        last_block_broken_validator_chain: Option<(u32, ValidatorSetId, u32, ValidatorSetId)>,
        last_block_unvalidated_validator_set: Option<(u32, ValidatorSetId)>,

        // the keccak hash here would be the cumulative hash of the node hashes 
        read_proof_info: Option<(u256, u32, Option<u32>, Option<u32>)>,
        read_proof_nodes: LegacyMap::<u32, (u256, Option<u256>)>,
        // read_proof_key:
        // read_proof_value:
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

        fn unset_validator_set_info(ref self: ContractState, validator_set_id: u64) {
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info {
                Option::Some(validator_set_info) => {
                    let number_of_validators = validator_set_info.number_of_validators;
                    let mut itr: u32 = 0;
                    loop {
                        if itr == number_of_validators {
                            break;
                        }
                        self.validator_set_list.write((validator_set_id, itr), 0_u256);
                        itr = itr + 1;
                    };

                    self.validator_set_info.write(validator_set_id, Option::None);
                },
                Option::None => {}
            };
        }

        fn set_validator_set_info(
            ref self: ContractState, validator_set_id: u64, validator_set_list: Array<u256>
        ) {
            let number_of_validators: u32 = validator_set_list.len();
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info {
                Option::Some(validator_set_info) => {
                    panic_with_felt252('Validator set info already set');
                },
                Option::None => {
                    let mut itr: u32 = 0;
                    loop {
                        if itr == number_of_validators {
                            break;
                        }
                        self
                            .validator_set_list
                            .write((validator_set_id, itr), *validator_set_list.at(itr.into()));
                        itr = itr + 1;
                    };

                    self
                        .validator_set_info
                        .write(
                            validator_set_id,
                            Option::Some(
                                ValidatorSetInfo {
                                    number_of_validators: number_of_validators,
                                    merkle_hash: Option::None,
                                    validated_at: Option::None,
                                }
                            )
                        );
                }
            };
        }

        fn set_validator_set_info_u8_array(
            ref self: ContractState, validator_set_id: u64, validator_set_list_u8_array: Array<u8>
        ) {
            let validator_set_list: Array<u256> = u8_eth_addresses_to_u256(
                validator_set_list_u8_array.span()
            );

            let number_of_validators: u32 = validator_set_list.len();
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info {
                Option::Some(validator_set_info) => {
                    panic_with_felt252('Validator set info already set');
                },
                Option::None => {
                    let mut itr: u32 = 0;
                    loop {
                        if itr == number_of_validators {
                            break;
                        }
                        self
                            .validator_set_list
                            .write((validator_set_id, itr), *validator_set_list.at(itr.into()));
                        itr = itr + 1;
                    };

                    self
                        .validator_set_info
                        .write(
                            validator_set_id,
                            Option::Some(
                                ValidatorSetInfo {
                                    number_of_validators: number_of_validators,
                                    merkle_hash: Option::None,
                                    validated_at: Option::None,
                                }
                            )
                        );
                }
            };
        }

        fn calculate_merkle_hash_for_validator_set(ref self: ContractState, validator_set_id: u64) {
            let maybe_validator_set_info = self.validator_set_info.read(validator_set_id);
            match maybe_validator_set_info {
                Option::Some(validator_set_info) => {
                    let number_of_validators: u32 = validator_set_info.number_of_validators;
                    let mut validator_set_list: Array<u256> = array![];
                    let mut itr: u32 = 0;

                    loop {
                        if itr == number_of_validators {
                            break;
                        }
                        validator_set_list
                            .append(self.validator_set_list.read((validator_set_id, itr)));
                        itr = itr + 1;
                    };

                    let merkle_root = merkelize_for_merkle_root(validator_set_list.span());

                    self
                        .validator_set_info
                        .write(
                            validator_set_id,
                            Option::Some(
                                ValidatorSetInfo {
                                    number_of_validators: number_of_validators,
                                    merkle_hash: Option::Some(merkle_root),
                                    validated_at: Option::None,
                                }
                            )
                        );
                },
                Option::None => {
                    panic_with_felt252('Validator set info not set');
                },
            }
        }


        fn full_reset_current_beefy_proof(ref self: ContractState) {
            self.current_mmr_root.write(Option::None);
            self.current_beefy_proof_info.write(Option::None);
            self.current_beefy_data.write(Option::None);
            self.current_para_data.write(Option::None);
        }

        fn verify_lean_beefy_proof(ref self: ContractState, lean_beefy_proof: Array<u8>, sig_ver_limit: Option<usize>) {
            assert(self.current_mmr_root.read().is_none(), 'current_mmr_root exists');
            assert(
                self.current_beefy_proof_info.read().is_none(), 'current_beefy_proof_info exists'
            );
            assert(self.current_beefy_data.read().is_none(), 'current_beefy_data exists');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');

            let (metadata, mut info, beefy_payloads_plan) = get_lean_beefy_proof_metadata(
                lean_beefy_proof.span()
            )
                .expect('get metadata failed');
            let mmr_root = get_mmr_root(beefy_payloads_plan.span()).expect('get_mmr_root failed');

            let last_info = self.last_beefy_proof_info.read();
            if last_info.is_some() {
                let last_info = last_info.expect('checked by is_some');
                assert(info.validator_set_id >= last_info.validator_set_id, 'stale proof');
                assert(info.block_number > last_info.block_number, 'stale proof');
                if info.validator_set_id > last_info.validator_set_id + 1 {
                    self
                        .broken_validator_chain_info
                        .write(
                            Option::Some(
                                (
                                    last_info.block_number,
                                    last_info.validator_set_id,
                                    info.block_number,
                                    info.validator_set_id
                                )
                            )
                        );
                }
            }

            let validator_set_info = self
                .validator_set_info
                .read(info.validator_set_id)
                .expect('Validators not set for set id');
            let number_of_validators = validator_set_info.number_of_validators;

            if validator_set_info.validated_at.is_none() {
                self
                    .unvalidated_validator_set_info
                    .write(Option::Some((info.block_number, info.validator_set_id)));
            }

            assert(
                number_of_validators == metadata.validator_set_len, 'number_of_validators mismatch'
            );

            let mut itr: usize = 0;
            let mut validator_addresses: Array<u256> = array![];

            loop {
                if itr == number_of_validators {
                    break;
                }
                validator_addresses
                    .append(self.validator_set_list.read((info.validator_set_id, itr)));
                itr = itr + 1;
            };

            assert(
                verify_beefy_signatures(
                    sig_ver_limit,
                    metadata.commitment_pre_hashed,
                    metadata.signatures_from_bitfield,
                    metadata.validator_set_len,
                    metadata.signatures_compact_len,
                    metadata.signatures_compact,
                    validator_addresses.span()
                )
                    .expect('verify_beefy_signatures failed'),
                'verify_beefy_signatures failed'
            );

            info.is_proof_verification_completed = true;
            self.current_mmr_root.write(Option::Some(mmr_root));
            self.current_beefy_proof_info.write(Option::Some(info));
        }

        fn verify_beefy_mmr_leaves_proof(
            ref self: ContractState, leaves: Array<u8>, proof: Array<u8>
        ) {
            assert(self.current_beefy_proof_info.read().is_some(), 'no current_beefy_proof_info');
            assert(self.current_beefy_data.read().is_none(), 'current_beefy_data exists');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');

            let mmr_root = self.current_mmr_root.read().expect('no current_mmr_root');
            let leaves_hashes = encoded_opaque_leaves_to_hashes(leaves.span())
                .expect('leaves_to_hashes works');
            assert(
                verify_mmr_leaves_proof(mmr_root, proof.span(), leaves_hashes.span()).is_ok(),
                'verify_mmr_leaves_proof failed'
            );
            let beefy_data_array = encoded_opaque_leaves_to_leaves(leaves.span())
                .expect('decoding leaves failed');
            assert(!beefy_data_array.len().is_zero(), 'no beefy data');
            self.current_beefy_data.write(Option::Some(*beefy_data_array.at(0)));
        }

        fn verify_beefy_para_data(
            ref self: ContractState,
            leaf_index: usize,
            leaf: Array<u8>,
            proof: Array<u8>,
            number_of_leaves: usize
        ) {
            assert(self.current_mmr_root.read().is_some(), 'no current_mmr_root');
            assert(self.current_beefy_proof_info.read().is_some(), 'no current_beefy_proof_info');
            assert(self.current_para_data.read().is_none(), 'current_para_data exists');
            let current_beefy_data = self
                .current_beefy_data
                .read()
                .expect('current_beefy_data missing');

            let leaf_hash = *get_hashes_from_items(leaf.span(), array![leaf.len()].span())
                .expect('get_hashes works')
                .at(0);
            let res = verify_merkle_proof(
                current_beefy_data.leaf_extra,
                hashes_to_u256s(proof.span()).expect('hashes_to_u256s works').span(),
                number_of_leaves,
                leaf_index,
                leaf_hash
            );
            assert(res, 'merkle proof ver failed');

            let (para_id, para_head) = decode_paradata(leaf.span());
            assert(para_id == PARA_ID, 'Wrong Para Id');

            let keccak_hash = u256_byte_reverse(
                keccak_le(
                    Slice { span: para_head, range: Range { start: 0, end: para_head.len() } }
                )
            );
            let parent_hash = *hashes_to_u256s(para_head.slice(0, 32))
                .expect('hashes_to_u256s works')
                .at(0);
            let storage_root = *hashes_to_u256s(para_head.slice(36, 32))
                .expect('hashes_to_u256s works')
                .at(0);

            self
                .current_para_data
                .write(
                    Option::Some(
                        ParaData {
                            keccak_hash: keccak_hash,
                            parent_blake2b_hash: parent_hash,
                            storage_root: storage_root,
                            blake2b_hash: Option::None,
                        }
                    )
                );
        }

        fn validate_next_validator_set_info(ref self: ContractState) {
            let current_beefy_proof_info = self
                .current_beefy_proof_info
                .read()
                .expect('no current_beefy_proof_info');
            let current_beefy_data = self
                .current_beefy_data
                .read()
                .expect('current_beefy_data missing');

            match self.validator_set_info.read(current_beefy_proof_info.validator_set_id + 1) {
                Option::Some(mut validator_set_info) => {
                    match validator_set_info.merkle_hash {
                        Option::Some(merkle_hash) => {
                            if current_beefy_data
                                .beefy_next_authority_set
                                .keyset_commitment == merkle_hash {
                                validator_set_info
                                    .validated_at =
                                        Option::Some(current_beefy_proof_info.block_number);
                                self
                                    .validator_set_info
                                    .write(
                                        current_beefy_proof_info.validator_set_id + 1,
                                        Option::Some(validator_set_info)
                                    );
                            } else {
                                panic_with_felt252('commitment merkle_hash mismatch');
                            }
                        },
                        Option::None => {
                            panic_with_felt252('validator_set merkle_hash unset');
                        }
                    }
                },
                Option::None => {
                    panic_with_felt252('validator_set_info unset');
                }
            };
        }

        fn finalize_current_lean_beefy_proof(ref self: ContractState) {
            let current_mmr_root = self.current_mmr_root.read().expect('current_mmr_root missing');
            let current_beefy_proof_info = self
                .current_beefy_proof_info
                .read()
                .expect('no current_beefy_proof_info');
            let current_beefy_data = self
                .current_beefy_data
                .read()
                .expect('current_beefy_data missing');
            let current_para_data = self
                .current_para_data
                .read()
                .expect('current_para_data missing');

            match self.validator_set_info.read(current_beefy_proof_info.validator_set_id + 1) {
                Option::Some(mut validator_set_info) => {
                    match validator_set_info.merkle_hash {
                        Option::Some(merkle_hash) => {
                            if current_beefy_data
                                .beefy_next_authority_set
                                .keyset_commitment == merkle_hash {
                                validator_set_info
                                    .validated_at =
                                        Option::Some(current_beefy_proof_info.block_number);
                                self
                                    .validator_set_info
                                    .write(
                                        current_beefy_proof_info.validator_set_id + 1,
                                        Option::Some(validator_set_info)
                                    );
                            }
                        },
                        Option::None => {}
                    }
                },
                Option::None => {}
            };

            let broken_validator_chain_info = self.broken_validator_chain_info.read();
            let unvalidated_validator_set_info = self.unvalidated_validator_set_info.read();

            if broken_validator_chain_info.is_some(){
                self.last_block_broken_validator_chain.write(broken_validator_chain_info);
            }

            if unvalidated_validator_set_info.is_some(){
                self.last_block_unvalidated_validator_set.write(unvalidated_validator_set_info);
            }

            self.current_mmr_root.write(Option::None);
            self.current_beefy_proof_info.write(Option::None);
            self.current_beefy_data.write(Option::None);
            self.current_para_data.write(Option::None);
            self.broken_validator_chain_info.write(Option::None);
            self.unvalidated_validator_set_info.write(Option::None);

            self.last_mmr_root.write(Option::Some(current_mmr_root));
            self.last_beefy_proof_info.write(Option::Some(current_beefy_proof_info));
            self.last_beefy_data.write(Option::Some(current_beefy_data));
            self.last_para_data.write(Option::Some(current_para_data));
        }

    }

    fn initialize_storage_read_proof_verification(ref self: ContractState, buffer: Array<u8>, buffer_index: Array<u8>, key: Array<u8>) {
        assert(self.read_proof_info.read().is_none(), 'use unset_storage_read_proof');

    }

    fn verify_storage_read_proof_and_get_value(ref self: ContractState, buffer: Array<u8>, buffer_index: Array<u8>, key: Array<u8>) {
    }

    fn unset_storage_read_proof(ref self: ContractState) {

        let read_proof_info = self.read_proof_info.read();

        match read_proof_info{
            Option::Some((_keccak_hash, num_nodes, maybe_num_bytes_key, maybe_num_bytes_value))=>{
                let mut itr:usize =0;
                loop{
                    if itr==num_nodes{break;}
                    self.read_proof_nodes.write(itr, (0, Option::None));
                    itr=itr+1;
                };

                if maybe_num_bytes_key.is_some(){
                    self.write_large_array::<u8>(READ_PROOF_KEY_ADDRESS, array![]);
                }

                if maybe_num_bytes_value.is_some(){
                    self.write_large_array::<u8>(READ_PROOF_VALUE_ADDRESS, array![]);
                }
                self.read_proof_info.write(Option::None);
            },
            Option::None=>{},
        }

    }


    #[generate_trait]
    impl StoreLargeArray of IStoreLargeArray {

        fn write_large_array<T, impl TCopy: Copy<T>, impl TDrop: Drop<T>, impl TStore: Store<T>, 
            >(ref self: ContractState, address:felt252, array: Array<T>)
            {
            let mut address = StoreLargeArray::get_address_from_name(address);

            let old_array_size: u64 = Store::<u64>::read(0, storage_base_address_from_felt252(address)).expect('read works');

            let element_size: u8 = Store::<T>::size();
            let array_len: u32 = array.len();
            let array_size: u64 = array_len.into() * element_size.into();

            if old_array_size>array_size{
                let mut offset:felt252 =0;
                offset=offset + Store::<u8>::size().into() + Store::<u32>::size().into() + array_size.into();
                let num_del_slots = old_array_size-array_size;

                let mut itr:u64 =0;
                loop{
                    if itr==num_del_slots{break;}
                    storage_write_syscall(0, storage_address_from_base_and_offset(storage_base_address_from_felt252(address + offset), 0), 0);
                    offset=offset + Store::<felt252>::size().into();
                    itr=itr+1;
                }
            }

            
            Store::<u64>::write(0, storage_base_address_from_felt252(address), array_size);
            address = address + Store::<u64>::size().into();
            Store::<u32>::write(0, storage_base_address_from_felt252(address), array_len);
            address = address + Store::<u32>::size().into();

            let mut itr: usize = 0;
            loop {
                if itr == array_len {
                    break;
                }
                Store::<T>::write(0, storage_base_address_from_felt252(address), (*array.at(itr)).into());
                address = address + element_size.into();
                itr = itr + 1;
            };
        }

        fn read_large_array<T, impl TCopy: Copy<T>, impl TDrop: Drop<T>, impl TStore: Store<T>, 
            >(ref self: ContractState, address:felt252) -> Array<T>{
            let mut address = StoreLargeArray::get_address_from_name(address);
            let array_size = Store::<u64>::read(0, storage_base_address_from_felt252(address)).expect('read works');
            address = address + Store::<felt252>::size().into();
            let array_length = Store::<u32>::read(0, storage_base_address_from_felt252(address)).expect('read works');
            address = address + Store::<u32>::size().into();

            let mut array: Array<T> = array![];
            let mut itr: usize = 0;
            loop {
                if itr == array_length {
                    break;
                }
                array.append(
                        Store::<T>::read(0, storage_base_address_from_felt252(address)).expect('read works')
                    );
                address = address + Store::<T>::size().into();
                itr = itr + 1;
            };
            array
        }

        fn read_large_array_len<T, impl TCopy: Copy<T>, impl TDrop: Drop<T>, impl TStore: Store<T>, 
            >(ref self: ContractState, address:felt252) -> u32{
            let mut address = StoreLargeArray::get_address_from_name(address);
            let array_size = Store::<u64>::read(0, storage_base_address_from_felt252(address)).expect('read works');
            address = address + Store::<felt252>::size().into();
            let array_length = Store::<u32>::read(0, storage_base_address_from_felt252(address)).expect('read works');
            address = address + Store::<u32>::size().into();

            array_length
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
