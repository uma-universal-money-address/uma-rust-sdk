use serde::{Deserialize, Serialize};

/// UtxoWithAmount is a pair of utxo and amount transferred over that corresponding channel.
/// It can be used to register payment for KYT.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UtxoWithAmount {
    /// utxo The utxo of the channel over which the payment went through in the format of
    /// <transaction_hash>:<output_index>.
    pub utxo: String,

    /// Amount The amount of funds transferred in the payment in mSats.
    #[serde(rename = "amountMsats")]
    pub amount: i64,
}
