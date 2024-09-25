use cosmwasm_std::{
    entry_point, to_json_binary, from_json, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
    StdError, Uint128, CosmosMsg, BankMsg, Addr,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub fee_percentage: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    file_transfers: Vec<FileTransfer>,
    admin: Addr,
    fee_percentage: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct FileTransfer {
    file_hash: String,
    sender: Addr,
    recipient: Addr,
    timestamp: u64,
    transfer_fee: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    RecordTransfer {
        file_hash: String,
        recipient: String,
    },
    WithdrawFees {
        amount: Uint128,
    },
    SetFeePercentage {
        percentage: Uint128,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetFileTransfers {},
    VerifyTransfer { file_hash: String, recipient: String },
    GetContractBalance {},
    GetFeePercentage {},
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = State {
        file_transfers: vec![],
        admin: info.sender.clone(),
        fee_percentage: msg.fee_percentage,
    };
    deps.storage.set(b"state", &to_json_binary(&state)?);
    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::RecordTransfer { file_hash, recipient } => 
            record_transfer(deps, env, info, file_hash, recipient),
        ExecuteMsg::WithdrawFees { amount } => 
            withdraw_fees(deps, env, info, amount),
        ExecuteMsg::SetFeePercentage { percentage } => 
            set_fee_percentage(deps, info, percentage),
    }
}

fn record_transfer(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    file_hash: String,
    recipient: String,
) -> StdResult<Response> {
    let mut state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;

    let recipient = deps.api.addr_validate(&recipient)?;

    if state.file_transfers.iter().any(|t| t.file_hash == file_hash && t.recipient == recipient) {
        return Err(StdError::generic_err("File transfer already exists"));
    }

    let transfer_amount = info.funds.iter()
        .find(|c| c.denom == "usei")
        .map(|c| c.amount)
        .unwrap_or_default();
    let transfer_fee = transfer_amount * state.fee_percentage / Uint128::new(10000);

    let transfer = FileTransfer {
        file_hash: file_hash.clone(),
        sender: info.sender.clone(),
        recipient: recipient.clone(),
        timestamp: env.block.time.seconds(),
        transfer_fee,
    };
    state.file_transfers.push(transfer);
    deps.storage.set(b"state", &to_json_binary(&state)?);

    Ok(Response::new()
        .add_attribute("action", "record_transfer")
        .add_attribute("file_hash", file_hash)
        .add_attribute("recipient", recipient.to_string())
        .add_attribute("transfer_fee", transfer_fee.to_string()))
}

fn withdraw_fees(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    let state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;

    if info.sender != state.admin {
        return Err(StdError::generic_err("Unauthorized"));
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

fn set_fee_percentage(
    deps: DepsMut,
    info: MessageInfo,
    percentage: Uint128,
) -> StdResult<Response> {
    let mut state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;

    if info.sender != state.admin {
        return Err(StdError::generic_err("Unauthorized"));
    }

    if percentage > Uint128::new(10000) {
        return Err(StdError::generic_err("Fee percentage must be between 0 and 10000 (100.00%)"));
    }

    state.fee_percentage = percentage;
    deps.storage.set(b"state", &to_json_binary(&state)?);

    Ok(Response::new()
        .add_attribute("action", "set_fee_percentage")
        .add_attribute("percentage", percentage.to_string()))
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetFileTransfers {} => to_json_binary(&query_file_transfers(deps)?),
        QueryMsg::VerifyTransfer { file_hash, recipient } => 
            to_json_binary(&query_verify_transfer(deps, file_hash, recipient)?),
        QueryMsg::GetContractBalance {} => to_json_binary(&Uint128::zero()),
        QueryMsg::GetFeePercentage {} => to_json_binary(&query_fee_percentage(deps)?),
    }
}

fn query_file_transfers(deps: Deps) -> StdResult<Vec<FileTransfer>> {
    let state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;
    Ok(state.file_transfers)
}

fn query_verify_transfer(deps: Deps, file_hash: String, recipient: String) -> StdResult<bool> {
    let state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;
    let recipient = deps.api.addr_validate(&recipient)?;
    Ok(state.file_transfers.iter().any(|t| t.file_hash == file_hash && t.recipient == recipient))
}

fn query_fee_percentage(deps: Deps) -> StdResult<Uint128> {
    let state: State = from_json(&deps.storage.get(b"state")
        .ok_or(StdError::not_found("State"))?)?;
    Ok(state.fee_percentage)
}