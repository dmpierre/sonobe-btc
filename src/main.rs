use ark_bn254::{constraints::GVar, Bn254, Fr, G1Projective as Projective};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_grumpkin::{constraints::GVar as GVar2, Projective as Projective2};
use ark_light_bitcoin_client::{
    gadgets::{
        block_hash_eq_broken_hash::{BlockHashCompareBrokenHash, ComputeBrokenHash},
        block_header_hash_gadget::BlockHeaderHashGadget,
        calculate_target_gadget::BlockTargetGadget,
        BTCBlockCheckerGadget,
    },
    get_block_hash, get_block_hash_field_element, get_target, read_blocks,
    utils::{get_broken_hash, get_broken_hash_field_elements, Block, BlockVar},
};
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, R1CSVar, ToBytesGadget,
    ToConstraintFieldGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand;
use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::nova::{decider_eth::Decider as DeciderEth, Nova},
    frontend::FCircuit,
    Error,
};
use folding_schemes::{folding::nova::decider_eth::prepare_calldata, Decider as DeciderTrait};
use folding_schemes::{folding::nova::decider_eth_circuit::DeciderEthCircuit, FoldingScheme};
use num_bigint::BigUint;
use num_traits::Num;
use solidity_verifiers::{
    evm::Evm, g16::Groth16VerifierKey, kzg::KZG10VerifierKey, utils::get_formatted_calldata,
    NovaCycleFoldVerifierKey,
};
use solidity_verifiers::{
    evm::{compile_solidity, save_solidity},
    get_decider_template_for_cyclefold_decider,
    utils::get_function_selector_for_nova_cyclefold_verifier,
};
use std::{cmp::Ordering, fs, marker::PhantomData, time::Instant};

use crate::utils::init_params;
mod utils;

#[derive(Clone, Debug)]
pub struct BTCBlockCheckerFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for BTCBlockCheckerFCircuit<F> {
    type Params = ();

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn step_native(
        &self,
        i: usize,
        z_i: Vec<F>,
        external_inputs: Vec<F>,
    ) -> Result<Vec<F>, folding_schemes::Error> {
        // Compute block hash
        let computed_block_hash = get_block_hash_field_element(&external_inputs);

        let new_z_i = vec![
            z_i[0] + F::one(),
            computed_block_hash[0],
            computed_block_hash[1],
        ];

        Ok(new_z_i)
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Vec<FpVar<F>>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // check block (hash in header, compute block hash and check pow)
        let computed_block_hash = BTCBlockCheckerGadget::check_block_fpvars(
            cs.clone(),
            vec![z_i[1].clone(), z_i[2].clone()],
            external_inputs,
        )?;

        // output computed block hash as 2 FpVars
        let computed_block_hash_broken =
            ComputeBrokenHash::compute_broken_hash_from_digest(cs.clone(), computed_block_hash)?;

        let new_z_i = vec![
            z_i[0].clone() + FpVar::<F>::Constant(F::one()),
            computed_block_hash_broken[0].clone(),
            computed_block_hash_broken[1].clone(),
        ];

        Ok(new_z_i)
    }

    fn external_inputs_len(&self) -> usize {
        80
    }
}

fn main() {
    let file = include_str!("./data/btc-blocks.json");
    let (mut prev_block_hash, blocks) = read_blocks(3, 1, file);

    let mut blocks_prepared = vec![];
    for batch in blocks.iter() {
        let block_hashes =
            serde_json::from_value::<Vec<String>>(batch.get("blockHashes").unwrap().clone())
                .unwrap();
        let block_headers =
            serde_json::from_value::<Vec<Vec<u8>>>(batch.get("blockHeaders").unwrap().clone())
                .unwrap();
        for (block_hash, block_header) in block_hashes.iter().zip(block_headers) {
            let block_hash_str = block_hash.to_string();
            let block = Block {
                block_header,
                block_hash: block_hash_str.clone(),
                prev_block_hash,
            };
            blocks_prepared.push(block.clone());
            prev_block_hash = block_hash_str;
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

    pub type DeciderEthFcircuit = DeciderEth<
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

    let n_blocks_checked = blocks_prepared.len();
    let circuit = BTCBlockCheckerFCircuit::<Fr>::new(()).unwrap();
    let block_broken_hash = get_broken_hash(&blocks_prepared[0].prev_block_hash);
    let block_broken_hash_field_elements = get_broken_hash_field_elements::<Fr>(block_broken_hash);

    let z_0 = vec![
        Fr::from(0),
        block_broken_hash_field_elements[0],
        block_broken_hash_field_elements[1],
    ];

    let (fs_prover_params, kzg_vk, g16_pk, g16_vk) =
        init_params::<BTCBlockCheckerFCircuit<Fr>>(z_0.clone());

    let mut nova = NOVA::init(&fs_prover_params, circuit.clone(), z_0.clone()).unwrap();

    println!("Computing folds...");
    for (i, block) in blocks_prepared.iter().enumerate() {
        let current_state = nova.z_i[0].into_bigint();
        if i % 10 == 0 {
            println!("--- At block: {}/{} ---", current_state, n_blocks_checked);
        }
        // header is 80 field elements
        let mut header = vec![];
        for h in block.block_header.clone().into_iter() {
            header.push(Fr::from(h));
        }

        nova.prove_step(header).unwrap();
    }

    let rng = rand::rngs::OsRng;
    let start = Instant::now();
    let proof = DeciderEthFcircuit::prove(
        (g16_pk, fs_prover_params.cs_params.clone()),
        rng,
        nova.clone(),
    )
    .unwrap();
    println!("generated Decider proof: {:?}", start.elapsed());

    let verified = DeciderEthFcircuit::verify(
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
    println!("Decider proof verification: {}", verified);

    // Now, let's generate the Solidity code that verifies this Decider final proof
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

    // prepare the setup params for the solidity verifier
    let nova_cyclefold_vk = NovaCycleFoldVerifierKey::from((g16_vk, kzg_vk, circuit.state_len()));

    // generate the solidity code
    let decider_solidity_code = get_decider_template_for_cyclefold_decider(nova_cyclefold_vk);

    // verify the proof against the solidity code in the EVM
    let nova_cyclefold_verifier_bytecode = compile_solidity(&decider_solidity_code, "NovaDecider");
    let mut evm = Evm::default();
    let verifier_address = evm.create(nova_cyclefold_verifier_bytecode);
    let (_, output) = evm.call(verifier_address, calldata.clone());
    assert_eq!(*output.last().unwrap(), 1);

    // save smart contract and the calldata
    fs::write(
        "./BTCLightClientNovaVerifier.sol",
        decider_solidity_code.clone(),
    )
    .unwrap();
    fs::write("./solidity-calldata.calldata", calldata.clone()).unwrap();
    let s = solidity_verifiers::utils::get_formatted_calldata(calldata.clone());
    fs::write("./solidity-calldata.txt", s.join(",\n")).expect("");
}
