use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
use ark_light_bitcoin_client::{
    gadgets::BTCBlockCheckerGadget,
    get_block_hash, get_target, read_blocks,
    utils::{Block, BlockVar},
};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{decider_eth::Decider, Nova},
    frontend::FCircuit,
};
use folding_schemes::{folding::nova::decider_eth::prepare_calldata, Decider as DeciderTrait};
use folding_schemes::{folding::nova::decider_eth_circuit::DeciderEthCircuit, FoldingScheme};
use num_bigint::BigUint;
use num_traits::Num;
use solidity_verifiers::{
    evm::{compile_solidity, save_solidity, Evm},
    get_decider_template_for_cyclefold_decider,
    utils::get_function_selector_for_nova_cyclefold_verifier,
};
use solidity_verifiers::{Groth16Data, KzgData, NovaCycleFoldData};
use std::{fs, marker::PhantomData, time::Instant};
use utils::setup;
mod utils;

#[derive(Clone, Debug)]
pub struct BTCBlockCheckerFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
    block: Vec<Block>,
}

impl<F: PrimeField> FCircuit<F> for BTCBlockCheckerFCircuit<F> {
    type Params = Vec<Block>;

    fn new(params: Self::Params) -> Self {
        Self {
            _f: PhantomData,
            block: params,
        }
    }

    fn state_len(&self) -> usize {
        1
    }

    fn step_native(&self, i: usize, z_i: Vec<F>) -> Result<Vec<F>, folding_schemes::Error> {
        let new_z_i = vec![z_i[0] + F::one()];

        // Check block hash
        let computed_block_hash = get_block_hash(&self.block[i].block_header);
        assert_eq!(computed_block_hash, self.block[i].block_hash);

        // Check prev_block_hash
        assert_eq!(
            self.block[i].prev_block_hash,
            hex::encode(&self.block[i].block_header[4..36].to_vec())
        );

        // Check pow
        let target = get_target(&self.block[i].block_header);
        let bigint_block_hash = BigUint::from_str_radix(&self.block[i].block_hash, 16).unwrap();
        assert!(BigUint::from_bytes_be(&bigint_block_hash.to_bytes_le()) < target);

        Ok(new_z_i)
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
    ) -> Result<Vec<ark_r1cs_std::fields::fp::FpVar<F>>, SynthesisError> {
        let new_z_i = vec![z_i[0].clone() + FpVar::new_constant(cs.clone(), F::one())?];
        let block_var = BlockVar::new_witness(cs.clone(), || Ok(self.block[i].clone()))?;
        let _ = BTCBlockCheckerGadget::check_block(cs.clone(), block_var.clone())?;
        Ok(new_z_i)
    }
}

fn main() {
    let file = include_str!("./data/btc-blocks.json");
    let (mut prev_block_hash, blocks) = read_blocks(100, 1, file);

    let mut blocks_prepared = vec![];
    for batch in blocks.iter() {
        let block_hashes =
            serde_json::from_value::<Vec<String>>(batch.get("blockHashes").unwrap().clone())
                .unwrap();
        let block_headers =
            serde_json::from_value::<Vec<Vec<u8>>>(batch.get("blockHeaders").unwrap().clone())
                .unwrap();
        for (block_hash, block_header) in block_hashes.iter().zip(block_headers) {
            let block = Block {
                block_header,
                block_hash: block_hash.to_string(),
                prev_block_hash,
            };
            blocks_prepared.push(block.clone());
            prev_block_hash = block_hash.to_string();
        }
    }

    type NOVA = Nova<
        Projective,
        GVar,
        Projective2,
        GVar2,
        BTCBlockCheckerFCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
    >;

    type DECIDER = Decider<
        Projective,
        GVar,
        Projective2,
        GVar2,
        BTCBlockCheckerFCircuit<Fr>,
        KZG<'static, Bn254>,
        Pedersen<Projective2>,
        Groth16<Bn254>,
        NOVA,
    >;

    let n_blocks_checked = blocks_prepared.len() / 20; // TMP rm '/20'
    let circuit = BTCBlockCheckerFCircuit::<Fr>::new(blocks_prepared.clone());
    let (fs_prover_params, kzg_vk) = setup(circuit.clone());
    let z_0 = vec![Fr::from(0)];
    let mut nova = NOVA::init(&fs_prover_params, circuit, z_0.clone()).unwrap();

    println!("Computing folds...");
    let start = Instant::now();
    for i in 0..n_blocks_checked {
        let current_state = nova.z_i[0].into_bigint();
        if i % 10 == 0 {
            println!("--- At block: {}/{} ---", current_state, n_blocks_checked);
        }
        nova.prove_step().unwrap();
    }
    println!(
        "Done folding. Checked {} blocks in: {:.2?}",
        n_blocks_checked,
        start.elapsed()
    );

    let decider_circuit = DeciderEthCircuit::<
        Projective,
        GVar,
        Projective2,
        GVar2,
        KZG<Bn254>,
        Pedersen<Projective2>,
    >::from_nova::<BTCBlockCheckerFCircuit<Fr>>(nova.clone())
    .unwrap();
    let mut rng = rand::rngs::OsRng;

    // decider setup
    println!("Starting setup...");
    let start = Instant::now();
    let (g16_pk, g16_vk) =
        Groth16::<Bn254>::circuit_specific_setup(decider_circuit.clone(), &mut rng).unwrap();
    println!("Setup done in: {:.2?}", start.elapsed());

    // decider proof generation
    println!("Generating proof...");
    let start = Instant::now();
    let decider_pp = (g16_pk, fs_prover_params.cs_params.clone());
    let proof = DECIDER::prove(decider_pp, rng, nova.clone()).unwrap();
    println!("Proof generated in: {:.2?}", start.elapsed());

    // decider proof verification
    println!("Verifying proof...");
    let verified = DECIDER::verify(
        (g16_vk.clone(), kzg_vk.clone()),
        nova.i,
        nova.z_0.clone(),
        nova.z_i.clone(),
        &nova.U_i,
        &nova.u_i,
        &proof,
    )
    .unwrap();
    assert!(verified);

    let g16_data = Groth16Data::from(g16_vk);
    let kzg_data = KzgData::from((
        kzg_vk,
        fs_prover_params.cs_params.powers_of_g[0..3].to_vec(),
    ));
    let nova_cyclefold_data = NovaCycleFoldData::from((g16_data, kzg_data, nova.z_0.len()));
    let function_selector =
        get_function_selector_for_nova_cyclefold_verifier(nova.z_0.len() * 2 + 1);

    let calldata: Vec<u8> = prepare_calldata(
        function_selector,
        nova.i,
        nova.z_0,
        nova.z_i,
        &nova.U_i,
        &nova.u_i,
        proof,
    )
    .unwrap();

    let decider_template = get_decider_template_for_cyclefold_decider(nova_cyclefold_data);

    // save smart contract
    save_solidity("./NovaLightBTCClientDecider.sol", &decider_template.clone());
    // save calldata
    fs::write("./solidity-calldata.calldata", calldata.clone()).unwrap();

    let nova_cyclefold_verifier_bytecode = compile_solidity(decider_template, "NovaDecider");

    let mut evm = Evm::default();
    let verifier_address = evm.create(nova_cyclefold_verifier_bytecode);

    let (_, output) = evm.call(verifier_address, calldata);
    println!("Output: {:?}", output);
    assert_eq!(*output.last().unwrap(), 1);
}
