/**
 Developer 🏗️: @virjilakrum Baturalp Güvenç
 @title ZK File Transfer Smart Contract for SEI Blockchain
 @dev This contract enables secure file transfers using Zero-Knowledge proofs on the SEI blockchain
 
 @notice This contract allows users to record file transfers with ZK proofs, verify transfers, and manage fees
 
 @param file_transfers List of recorded file transfers
 @param admin Address of the contract administrator
 @param fee_percentage Percentage of transfer amount charged as fee (in basis points)
 
 @function instantiate Initializes the contract with an admin and fee percentage
 @function execute Handles incoming transactions (RecordTransfer, WithdrawFees, SetFeePercentage)
 @function query Handles read-only queries (GetFileTransfers, VerifyTransfer, GetContractBalance, GetFeePercentage)
 
 @dev To use on SEI:
 * 1. Compile the contract: cargo build --release --target wasm32-unknown-unknown
 * 2. Optimize the wasm binary (using cosmwasm-opt)
 * 3. Upload the optimized wasm to SEI blockchain using sei-cli
 * 4. Instantiate the contract with initial admin and fee percentage
 * 5. Interact with the contract using sei-cli or a compatible wallet
 
 @notice Ensure all required dependencies are properly set in Cargo.toml
 @notice This contract uses real ZK proof verification and should be thoroughly audited before production use
 */

 use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    StdError, Uint128, CosmosMsg, BankMsg, QueryRequest, BankQuery, BalanceResponse, Addr,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bls12_381::{Bls12, Scalar};
use rand::rngs::OsRng;

// ZK Proof implementation
mod zk_proof {
    use super::*;

    pub struct FileTransferCircuit {
        pub file_hash: Option<[u8; 32]>,
        pub recipient: Option<[u8; 32]>,
        pub secret: Option<[u8; 32]>,
    }

    impl Circuit<Bls12> for FileTransferCircuit {
        fn synthesize<CS: ConstraintSystem<Bls12>>(
            self,
            cs: &mut CS
        ) -> Result<(), SynthesisError> {
            let file_hash = cs.alloc_input(
                || "file hash",
                || {
                    self.file_hash.map(|h| Scalar::from_bytes(&h).unwrap())
                        .ok_or(SynthesisError::AssignmentMissing)
                }
            )?;

            let recipient = cs.alloc_input(
                || "recipient",
                || {
                    self.recipient.map(|r| Scalar::from_bytes(&r).unwrap())
                        .ok_or(SynthesisError::AssignmentMissing)
                }
            )?;

            let secret = cs.alloc(
                || "secret",
                || {
                    self.secret.map(|s| Scalar::from_bytes(&s).unwrap())
                        .ok_or(SynthesisError::AssignmentMissing)
                }
            )?;

            cs.enforce(
                || "secret constraint",
                |lc| lc + secret,
                |lc| lc + CS::one(),
                |lc| lc + file_hash + recipient,
            );

            Ok(())
        }
    }

    pub struct Proof(pub Vec<u8>);

    impl Proof {
        pub fn new(file_hash: [u8; 32], recipient: [u8; 32], secret: [u8; 32]) -> Self {
            use bellman::groth16::{
                create_random_proof, generate_random_parameters,
                prepare_verifying_key, verify_proof,
            };

            let params = {
                let c = FileTransferCircuit {
                    file_hash: Some(file_hash),
                    recipient: Some(recipient),
                    secret: Some(secret),
                };
                generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
            };

            let pvk = prepare_verifying_key(&params.vk);

            let c = FileTransferCircuit {
                file_hash: Some(file_hash),
                recipient: Some(recipient),
                secret: Some(secret),
            };

            let proof = create_random_proof(c, &params, &mut OsRng).unwrap();

            let mut proof_bytes = vec![];
            proof.write(&mut proof_bytes).unwrap();

            Proof(proof_bytes)
        }

        pub fn verify(&self, file_hash: &[u8], recipient: &[u8]) -> bool {
            use bellman::groth16::{prepare_verifying_key, verify_proof, Proof};

            let params = {
                let c = FileTransferCircuit {
                    file_hash: None,
                    recipient: None,
                    secret: None,
                };
                bellman::groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
            };

            let pvk = prepare_verifying_key(&params.vk);

            let proof = Proof::read(&mut &self.0[..]).unwrap();

            let inputs = [
                Scalar::from_bytes(&file_hash[..32].try_into().unwrap()).unwrap(),
                Scalar::from_bytes(&recipient[..32].try_into().unwrap()).unwrap(),
            ];

            verify_proof(&pvk, &proof, &inputs).is_ok()
        }
    }
}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Invalid ZK Proof")]
    InvalidProof {},

    #[error("File transfer already exists")]
    DuplicateTransfer {},

    #[error("Insufficient funds")]
    InsufficientFunds {},
}

// Contract state
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    file_transfers: Vec<FileTransfer>,
    admin: String,
    fee_percentage: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct FileTransfer {
    file_hash: String,
    sender: String,
    recipient: String,
    timestamp: u64,
    transfer_fee: Uint128,
}

// Messages that can be sent to the contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    RecordTransfer {
        file_hash: String,
        recipient: String,
        zk_proof: Vec<u8>,
    },
    WithdrawFees {
        amount: Uint128,
    },
    SetFeePercentage {
        percentage: Uint128,
    },
}

// Query messages
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetFileTransfers {},
    VerifyTransfer { file_hash: String, recipient: String },
    GetContractBalance {},
    GetFeePercentage {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub fee_percentage: Uint128,
}

// Contract instantiation
#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        file_transfers: vec![],
        admin: info.sender.to_string(),
        fee_percentage: msg.fee_percentage,
    };
    deps.storage.set(b"state", &to_json_binary(&state)?);
    Ok(Response::default())
}

// Contract execution
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RecordTransfer {
            file_hash,
            recipient,
            zk_proof,
        } => record_transfer(deps, env, info, file_hash, recipient, zk_proof),
        ExecuteMsg::WithdrawFees { amount } => withdraw_fees(deps, env, info, amount),
        ExecuteMsg::SetFeePercentage { percentage } => set_fee_percentage(deps, info, percentage),
    }
}

// Record file transfer function
fn record_transfer(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    file_hash: String,
    recipient: String,
    zk_proof: Vec<u8>,
) -> Result<Response, ContractError> {
    let mut state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();

    // Check if transfer already exists
    if state.file_transfers.iter().any(|t| t.file_hash == file_hash && t.recipient == recipient) {
        return Err(ContractError::DuplicateTransfer {});
    }

    // Verify ZK proof
    let proof = zk_proof::Proof(zk_proof);
    if !proof.verify(file_hash.as_bytes(), recipient.as_bytes()) {
        return Err(ContractError::InvalidProof {});
    }

    // Calculate transfer fee
    let transfer_amount = info.funds.iter().find(|c| c.denom == "usei").map(|c| c.amount).unwrap_or_default();
    let transfer_fee = transfer_amount * state.fee_percentage / Uint128::new(10000); // fee_percentage is in basis points

    let transfer = FileTransfer {
        file_hash: file_hash.clone(),
        sender: info.sender.to_string(),
        recipient: recipient.clone(),
        timestamp: env.block.time.seconds(),
        transfer_fee,
    };
    state.file_transfers.push(transfer);
    deps.storage.set(b"state", &to_json_binary(&state)?);

    Ok(Response::new()
        .add_attribute("action", "record_transfer")
        .add_attribute("file_hash", file_hash)
        .add_attribute("recipient", recipient)
        .add_attribute("transfer_fee", transfer_fee.to_string()))
}

// Withdraw fees function (admin only)
fn withdraw_fees(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> Result<Response, ContractError> {
    let state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();
    if info.sender != state.admin {
        return Err(ContractError::Unauthorized {});
    }

    let balance = query_balance(deps.as_ref(), &_env.contract.address)?;
    if balance < amount {
        return Err(ContractError::InsufficientFunds {});
    }

    let bank_msg = BankMsg::Send {
        to_address: info.sender.to_string(),
        amount: vec![cosmwasm_std::Coin {
            denom: "usei".to_string(),
            amount,
        }],
    };

    Ok(Response::new()
        .add_message(CosmosMsg::Bank(bank_msg))
        .add_attribute("action", "withdraw_fees")
        .add_attribute("amount", amount.to_string()))
}

// Set fee percentage (admin only)
fn set_fee_percentage(
    deps: DepsMut,
    info: MessageInfo,
    percentage: Uint128,
) -> Result<Response, ContractError> {
    let mut state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();
    if info.sender != state.admin {
        return Err(ContractError::Unauthorized {});
    }

    if percentage > Uint128::new(10000) {
        return Err(ContractError::Std(StdError::generic_err(
            "Fee percentage must be between 0 and 10000 (100.00%)",
        )));
    }

    state.fee_percentage = percentage;
    deps.storage.set(b"state", &to_json_binary(&state)?);

    Ok(Response::new()
        .add_attribute("action", "set_fee_percentage")
        .add_attribute("percentage", percentage.to_string()))
}

// Contract queries
#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetFileTransfers {} => to_json_binary(&query_file_transfers(deps)?),
        QueryMsg::VerifyTransfer { file_hash, recipient } => to_json_binary(&query_verify_transfer(deps, file_hash, recipient)?),
        QueryMsg::GetContractBalance {} => to_json_binary(&query_contract_balance(deps, _env)?),
        QueryMsg::GetFeePercentage {} => to_json_binary(&query_fee_percentage(deps)?),
    }
}

// Query function to get all file transfers
fn query_file_transfers(deps: Deps) -> StdResult<Vec<FileTransfer>> {
    let state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();
    Ok(state.file_transfers)
}

// Query function to verify a specific transfer
fn query_verify_transfer(deps: Deps, file_hash: String, recipient: String) -> StdResult<bool> {
    let state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();
    Ok(state
        .file_transfers
        .iter()
        .any(|t| t.file_hash == file_hash && t.recipient == recipient))
}

// Query function to get contract balance
fn query_contract_balance(deps: Deps, env: Env) -> StdResult<Uint128> {
    query_balance(deps, &env.contract.address)
}

// Query function to get fee percentage
fn query_fee_percentage(deps: Deps) -> StdResult<Uint128> {
    let state: State = deps.storage.get(b"state").and_then(|data| Ok(cosmwasm_std::from_json(data)?)).unwrap();
    Ok(state.fee_percentage)
}

// Helper function to query balance
fn query_balance(deps: Deps, address: &Addr) -> StdResult<Uint128> {
    let balance: BalanceResponse = deps.querier.query(&QueryRequest::Bank(BankQuery::Balance {
        address: address.to_string(),
        denom: "usei".to_string(),
    }))?;
    Ok(balance.amount.amount)
}