use crate::BTCBlockCheckerFCircuit;
use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
use ark_poly_commit::kzg10::VerifierKey as KZGVerifierKey;
use folding_schemes::{
    commitment::{
        kzg::{ProverKey as KZGProverKey, KZG},
        pedersen::Pedersen,
        CommitmentScheme,
    },
    folding::nova::{get_cs_params_len, ProverParams},
    transcript::poseidon::poseidon_test_config,
};

pub fn setup(
    circuit: BTCBlockCheckerFCircuit<Fr>,
) -> (
    ProverParams<Projective, Projective2, KZG<'static, Bn254>, Pedersen<Projective2>>,
    PoseidonConfig<Fr>,
    KZGVerifierKey<Bn254>,
) {
    let mut rng = ark_std::test_rng();
    let poseidon_config = poseidon_test_config::<Fr>();

    let (cs_len, cf_cs_len) =
        get_cs_params_len::<Projective, GVar, Projective2, GVar2, BTCBlockCheckerFCircuit<Fr>>(
            &poseidon_config,
            circuit,
        )
        .unwrap();

    let (kzg_pk, kzg_vk): (KZGProverKey<Projective>, KZGVerifierKey<Bn254>) =
        KZG::<Bn254>::setup(&mut rng, cs_len).unwrap();
    let (cf_pedersen_params, _) = Pedersen::<Projective2>::setup(&mut rng, cf_cs_len).unwrap();

    (
        ProverParams::<Projective, Projective2, KZG<Bn254>, Pedersen<Projective2>> {
            poseidon_config: poseidon_config.clone(),
            cs_params: kzg_pk.clone(),
            cf_cs_params: cf_pedersen_params,
        },
        poseidon_config,
        kzg_vk,
    )
}
