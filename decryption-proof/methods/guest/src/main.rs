#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;

//use concrete_ntt::prime64::Plan;

use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::ABox;
use tfhe_fft::c64;

//use tfhe::core_crypto::prelude::*;
//use rayon::prelude::*;

risc0_zkvm::guest::entry!(main);
//use serde::Deserialize;

fn main() {
    // Read serialized data
    let serialized_std_bootstrapping_key: Vec<u8> = env::read();
    let serialized_fourier_bsk: Vec<u8> = env::read();
    let serialized_lwe_ciphertext_in_clear: Vec<u8> = env::read();
    let serialized_cleartext_multiplication_result: Vec<u8> = env::read();
    let serialized_accumulator: Vec<u8> = env::read();
    let serialized_pbs: Vec<u8> = env::read();
    let serialized_big_lwe_sk: Vec<u8> = env::read();

    // Helper function for deserialization with better error messages
    fn deserialize_with_context<T: for<'a> serde::Deserialize<'a>>(data: &[u8], context: &str) -> T {
        bincode::deserialize(data).unwrap_or_else(|e| {
            panic!("Failed to deserialize {}: {:?}", context, e);
        })
    }

    // Deserialize all inputs
    let std_bootstrapping_key: LweBootstrapKeyOwned<u64> = deserialize_with_context(&serialized_std_bootstrapping_key, "std_bootstrapping_key");
    let fourier_bsk: FourierLweBootstrapKey<ABox<[c64]>> = deserialize_with_context(&serialized_fourier_bsk, "fourier_bsk");
    let lwe_ciphertext_in_clear: LweCiphertextOwned<u64> = deserialize_with_context(&serialized_lwe_ciphertext_in_clear, "lwe_ciphertext_in_clear");
    let cleartext_multiplication_result: u64 = deserialize_with_context(&serialized_cleartext_multiplication_result, "cleartext_multiplication_result");
    let mut accumulator: GlweCiphertextOwned<u64> = deserialize_with_context(&serialized_accumulator, "accumulator");
    let mut pbs_multiplication_ct: LweCiphertextOwned<u64> = deserialize_with_context(&serialized_pbs, "pbs");
    let big_lwe_sk: LweSecretKeyOwned<u64> = deserialize_with_context(&serialized_big_lwe_sk, "big_lwe_sk");

    // Constants
    let message_modulus = 1u64 << 4;
    let delta = (1_u64 << 63) / message_modulus;



    // Decrypt and verify
    let pbs_multiplication_plaintext = decrypt_lwe_ciphertext(&big_lwe_sk, &pbs_multiplication_ct);
    
    let signed_decomposer = SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));
    let pbs_multiplication_result = signed_decomposer.closest_representable(pbs_multiplication_plaintext.0) / delta;

    // Verify results match
    assert_eq!(cleartext_multiplication_result, pbs_multiplication_result);

    // Commit the result
    env::commit(&pbs_multiplication_ct);
}
