// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{
    HELLO_GUEST_ELF, HELLO_GUEST_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv};
//use serde::{Deserialize, Serialize};
//use risc0_zkvm::serde::from_slice;
use tfhe::core_crypto::entities::*;
use tfhe::core_crypto::commons::parameters::*;
use tfhe::core_crypto::algorithms::*;
use tfhe::core_crypto::prelude::*;
//use tfhe::core_crypto::commons::ciphertext_modulus::*;
use std::error::Error;
use tfhe::core_crypto::fft_impl::fft64::ABox;
use tfhe_fft::c64;

fn main() -> Result<(), Box<dyn Error>> { 
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
    // computations
    // Define the parameters for a 4 bits message able to hold the doubled 2 bits message
    let small_lwe_dimension = LweDimension(742);
    let glwe_dimension = GlweDimension(1);
    let polynomial_size = PolynomialSize(2048);
    let lwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);
    let pbs_base_log = DecompositionBaseLog(23);
    let pbs_level = DecompositionLevelCount(1);
    let ciphertext_modulus = CiphertextModulus::new_native();

    // Request the best seeder possible, starting with hardware entropy sources and falling back to
    // /dev/random on Unix systems if enabled via cargo features
    let mut boxed_seeder = new_seeder();
    // Get a mutable reference to the seeder as a trait object from the Box returned by new_seeder
    let seeder = boxed_seeder.as_mut();

    // Create a generator which uses a CSPRNG to generate secret keys
    let mut secret_generator =
        SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

    // Create a generator which uses two CSPRNGs to generate public masks and secret encryption
    // noise
    let mut encryption_generator =
        EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

    println!("Generating keys...");

    // Generate an LweSecretKey with binary coefficients
    let small_lwe_sk =
        LweSecretKey::generate_new_binary(small_lwe_dimension, &mut secret_generator);

    // Generate a GlweSecretKey with binary coefficients
    let glwe_sk =
        GlweSecretKey::generate_new_binary(glwe_dimension, polynomial_size, &mut secret_generator);

    // Create a copy of the GlweSecretKey re-interpreted as an LweSecretKey
    let big_lwe_sk = glwe_sk.clone().into_lwe_secret_key();

    // Generate the bootstrapping key, we use the parallel variant for performance reason
    let std_bootstrapping_key = par_allocate_and_generate_new_lwe_bootstrap_key(
        &small_lwe_sk,
        &glwe_sk,
        pbs_base_log,
        pbs_level,
        glwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Create the empty bootstrapping key in the Fourier domain
    let mut fourier_bsk = FourierLweBootstrapKey::new(
        std_bootstrapping_key.input_lwe_dimension(),
        std_bootstrapping_key.glwe_size(),
        std_bootstrapping_key.polynomial_size(),
        std_bootstrapping_key.decomposition_base_log(),
        std_bootstrapping_key.decomposition_level_count(),
    );

    // Use the conversion function (a memory optimized version also exists but is more complicated
    // to use) to convert the standard bootstrapping key to the Fourier domain
    convert_standard_lwe_bootstrap_key_to_fourier(&std_bootstrapping_key, &mut fourier_bsk);
    // We don't need the standard bootstrapping key anymore
    drop(std_bootstrapping_key.clone());

    // Our 4 bits message space
    let message_modulus = 1u64 << 4;

    // Our input message
    let input_message = 3u64;

    // Delta used to encode 4 bits of message + a bit of padding on u64
    let delta = (1_u64 << 63) / message_modulus;

    // Apply our encoding
    let plaintext = Plaintext(input_message * delta);

    // Allocate a new LweCiphertext and encrypt our plaintext
    let lwe_ciphertext_in: LweCiphertextOwned<u64> = allocate_and_encrypt_new_lwe_ciphertext(
        &small_lwe_sk,
        plaintext,
        lwe_noise_distribution,
        ciphertext_modulus,
        &mut encryption_generator,
    );

    // Compute a cleartext multiplication by 2
    let mut cleartext_multiplication_ct = lwe_ciphertext_in.clone();
    println!("Performing cleartext multiplication...");
    lwe_ciphertext_cleartext_mul(
        &mut cleartext_multiplication_ct,
        &lwe_ciphertext_in,
        Cleartext(2),
    );

    // Decrypt the cleartext multiplication result
    let cleartext_multiplication_plaintext: Plaintext<u64> =
        decrypt_lwe_ciphertext(&small_lwe_sk, &cleartext_multiplication_ct);

    // Create a SignedDecomposer to perform the rounding of the decrypted plaintext
    // We pass a DecompositionBaseLog of 5 and a DecompositionLevelCount of 1 indicating we want to
    // round the 5 MSB, 1 bit of padding plus our 4 bits of message
    let signed_decomposer =
        SignedDecomposer::new(DecompositionBaseLog(5), DecompositionLevelCount(1));

    // Round and remove our encoding
    let cleartext_multiplication_result: u64 =
        signed_decomposer.closest_representable(cleartext_multiplication_plaintext.0) / delta;

    println!("Checking result...");
    assert_eq!(6, cleartext_multiplication_result);
    println!(
        "Cleartext multiplication result is correct! \
        Expected 6, got {cleartext_multiplication_result}"
    );

    // Now we will use a PBS to compute the same multiplication, it is NOT the recommended way of
    // doing this operation in terms of performance as it's much more costly than a multiplication
    // with a cleartext, however it resets the noise in a ciphertext to a nominal level and allows
    // to evaluate arbitrary functions so depending on your use case it can be a better fit.

    // Generate the accumulator for our multiplication by 2 using a simple closure
    let accumulator: GlweCiphertextOwned<u64> = generate_programmable_bootstrap_glwe_lut(
        polynomial_size,
        glwe_dimension.to_glwe_size(),
        message_modulus as usize,
        ciphertext_modulus,
        delta,
        |x: u64| 2 * x,
    );

    // Allocate the LweCiphertext to store the result of the PBS
    let mut pbs_multiplication_ct = LweCiphertext::new(
        0u64,
        big_lwe_sk.lwe_dimension().to_lwe_size(),
        ciphertext_modulus,
    );
    println!("Computing PBS...");
    programmable_bootstrap_lwe_ciphertext(
        &lwe_ciphertext_in,
        &mut pbs_multiplication_ct,
        &accumulator,
        &fourier_bsk,
    );
    

    
    let input_data = bincode::serialize(&std_bootstrapping_key)?;
    let result_in: LweBootstrapKeyOwned<u64> = bincode::deserialize(&input_data)?;
    println!("std_bootstrapping_key: {:?}", result_in);

    let input_data_2 = bincode::serialize(&fourier_bsk)?;
    let result_in_2: FourierLweBootstrapKey<ABox<[c64]>> = bincode::deserialize(&input_data_2)?;
    println!("fourier_bsk: {:?}", result_in_2);

    let input_data_3 = bincode::serialize(&lwe_ciphertext_in)?;
    let result_in_3: LweCiphertextOwned<u64> = bincode::deserialize(&input_data_3)?;
    println!("lwe_ciphertext_in_clear: {:?}", result_in_3);

    let input_data_4 = bincode::serialize(&cleartext_multiplication_result)?;
    let result_in_4: u64 = bincode::deserialize(&input_data_4)?;
    println!("cleartext_multiplication_result: {:?}", result_in_4);

    let input_data_5 = bincode::serialize(&accumulator)?;
    let result_in_5: GlweCiphertextOwned<u64> = bincode::deserialize(&input_data_5)?;
    println!("accumulator_bf: {:?}", result_in_5);

    let input_data_6 = bincode::serialize(&pbs_multiplication_ct)?;
    let result_in_6: LweCiphertextOwned<u64> = bincode::deserialize(&input_data_6)?;
    println!("pbs_multiplication_ct: {:?}", result_in_6);

    let input_data_7 = bincode::serialize(&big_lwe_sk)?;
    let result_in_7: LweSecretKeyOwned<u64> = bincode::deserialize(&input_data_7)?;
    println!("big_lwe_sk: {:?}", result_in_7);

    

    

    // par_convert_standard_lwe_bootstrap_key_to_ntt64(&std_bootstrapping_key, &mut ntt_bsk);
    // println!("ntt_bsk_af: {:?}", ntt_bsk);

    // blind_rotate_ntt64_assign(&lwe_ciphertext_in_clear, &mut accumulator, &ntt_bsk);
    // println!("accumulator_af: {:?}", accumulator);

    // extract_lwe_sample_from_glwe_ciphertext(
    //     &accumulator,
    //     &mut pbs_multiplication_ct,
    //     MonomialDegree(0),
    // );
    // println!("pbs_output: {:?}", pbs_multiplication_ct);
    
    let env = ExecutorEnv::builder()
        .write(&input_data)
        .unwrap()
        .write(&input_data_2)
        .unwrap()
        .write(&input_data_3)
        .unwrap()
        .write(&input_data_4)
        .unwrap()
        .write(&input_data_5)
        .unwrap()
        .write(&input_data_6)
        .unwrap()
        .write(&input_data_7)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover
        .prove(env, HELLO_GUEST_ELF)
        .unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;
    //println!("receipt: {:?}", receipt);

    // TODO: Implement code for retrieving receipt journal here.

    // For example:
    //let output_data: NttLweBootstrapKey = bincode::deserialize(&receipt.journal.decode().unwrap());

    let output: LweCiphertextOwned<u64> = receipt.journal.decode().unwrap();

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    println!("Hello, world! I generated a proof of guest execution! {:?} is a public output from journal ", output);

    receipt
        .verify(HELLO_GUEST_ID)
        .unwrap();

    Ok(())
}