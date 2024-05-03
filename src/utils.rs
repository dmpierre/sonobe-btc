use std::time::Instant;

use crate::BTCBlockCheckerFCircuit;
use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_groth16::ProvingKey;
use ark_groth16::VerifyingKey as G16VerifierKey;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as G2};
use ark_light_bitcoin_client::utils::Block;
use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::rand;
use folding_schemes::folding::nova::decider_eth_circuit::DeciderEthCircuit;
use folding_schemes::folding::nova::Nova;
use folding_schemes::FoldingScheme;
use folding_schemes::{
    commitment::{
        kzg::{ProverKey as KZGProverKey, KZG},
        pedersen::Pedersen,
        CommitmentScheme,
    },
    folding::nova::{get_cs_params_len, ProverParams},
    frontend::FCircuit,
    transcript::poseidon::poseidon_test_config,
};
use num_traits::Zero;

pub fn init_test_prover_params<FC: FCircuit<Fr, Params = ()>>() -> (
    ProverParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>>,
    KZGVerifierKey<Bn254>,
) {
    let mut rng = ark_std::test_rng();
    let poseidon_config = poseidon_test_config::<Fr>();
    let f_circuit = FC::new(()).unwrap();
    let (cs_len, cf_cs_len) =
        get_cs_params_len::<G1, GVar, G2, GVar2, FC>(&poseidon_config, f_circuit).unwrap();
    let (kzg_pk, kzg_vk): (KZGProverKey<G1>, KZGVerifierKey<Bn254>) =
        KZG::<Bn254>::setup(&mut rng, cs_len).unwrap();
    let (cf_pedersen_params, _) = Pedersen::<G2>::setup(&mut rng, cf_cs_len).unwrap();
    let fs_prover_params = ProverParams::<G1, G2, KZG<Bn254>, Pedersen<G2>> {
        poseidon_config: poseidon_config.clone(),
        cs_params: kzg_pk.clone(),
        cf_cs_params: cf_pedersen_params,
    };
    (fs_prover_params, kzg_vk)
}

pub fn init_params<FC: FCircuit<Fr, Params = ()>>(
    z_0: Vec<Fr>,
) -> (
    ProverParams<G1, G2, KZG<'static, Bn254>, Pedersen<G2>>,
    KZGVerifierKey<Bn254>,
    ProvingKey<Bn254>,
    G16VerifierKey<Bn254>,
) {
    let mut rng = rand::rngs::OsRng;
    let start = Instant::now();
    let (fs_prover_params, kzg_vk) = init_test_prover_params::<FC>();
    println!("generated Nova folding params: {:?}", start.elapsed());
    let f_circuit = FC::new(()).unwrap();

    pub type NOVA<FC> = Nova<G1, GVar, G2, GVar2, FC, KZG<'static, Bn254>, Pedersen<G2>>;
    let nova = NOVA::init(&fs_prover_params, f_circuit, z_0.clone()).unwrap();

    let decider_circuit =
        DeciderEthCircuit::<G1, GVar, G2, GVar2, KZG<Bn254>, Pedersen<G2>>::from_nova::<FC>(
            nova.clone(),
        )
        .unwrap();
    let start = Instant::now();
    let (g16_pk, g16_vk) =
        Groth16::<Bn254>::circuit_specific_setup(decider_circuit.clone(), &mut rng).unwrap();
    println!(
        "generated G16 (Decider circuit) params: {:?}",
        start.elapsed()
    );
    (fs_prover_params, kzg_vk, g16_pk, g16_vk)
}
