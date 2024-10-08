use ethers::prelude::*;
use ethers::utils::keccak256;
use hex;
use std::str::FromStr;

// Domain struct, analogous to Go's "Domain" struct
#[derive(Debug)]
struct Domain {
    name: String,
    version: String,
    chain_id: String,
    verifying_contract: String,
}

// Order struct analogous to Go's "Order" struct
#[derive(Debug)]
struct Order {
    // address prefixed with 0x; example 0x0000000000000000000000000000000000000001
    sender: String,
    // INTEGER string representation of the size in wei (need x10^18);
    // example: for 1.23 ETH we need to put "1230000000000000000"
    // We use string because int64 can't hold too large numbers
    size: String,
    // INTEGER string representation of the price in wei (need x10^18);
    // example: for 123.4 USDC we need to put "123400000000000000000"
    price: String,
    // should be ~ current nano timestamp; so using uint64 is enough
    nonce: u64,
    // BTC-1; ETH-2; etc; note that 0 is not a valid product index
    product_index: u8,
    // 0 for buy, 1 for sell
    side: u8,
}

// Function to manually sign the order, similar to ManuallySignOrder in Go
fn manually_sign_order(
    private_key: &str,
    domain: Domain,
    order: Order,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Convert the private key hex string to a private key object
    let private_key = LocalWallet::from_str(private_key)?;

    // Hash domain separator and order, similar to Go's logic
    let domain_separator = hash_typed_data_domain(&domain)?;
    println!("domainSeparator: {}", hex::encode(domain_separator));

    let typed_data_hash = hash_order(&order)?;
    println!("typedDataHash: {}", hex::encode(typed_data_hash));

    // Create data to be hashed: "\x19\x01" + domain separator + typed data hash
    let mut data = vec![0x19, 0x01];
    data.extend_from_slice(&domain_separator);
    data.extend_from_slice(&typed_data_hash);

    let final_hash = keccak256(&data);

    // Sign the final hash (no need for async/await here)
    let signature = private_key.sign_hash(H256::from(final_hash))?;

    let sig = signature.to_vec();

    // on Go, we need sig[64] += 27: add 27 to recovery id (v) to conform with the standard
    // but in Rust, it looks like the library did it for us; so we don't have to manually +=27 here
    // sig[64] += 27;

    Ok(sig)
}

// Hash domain data using EIP712 logic, similar to Go's hashTypedDataDomain
fn hash_typed_data_domain(domain: &Domain) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // this string is constant and derived from the EIP712 standard
    // we should not mess with it: adding new spaces, changing the order of the fields, changing the case of the letters, etc.
    // for better performance, we can precompute the hash of this string and use it in the future
    let domain_type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            .as_bytes(),
    );
    // Name and Version are string, we can just convert them to bytes and hash them directly
    let name_hash = keccak256(domain.name.as_bytes());
    let version_hash = keccak256(domain.version.as_bytes());

    // For big.Int, we need to use BigToHash to convert it to common.Hash
    let chain_id: u64 = domain.chain_id.parse()?;
    let chain_id_hash = H256::from_low_u64_be(chain_id).as_bytes().to_vec();

    // encode VerifyingContract (an address) as a 32 bytes array
    // An address is 20 bytes, so we need simply add 12 bytes of 0 to the left of the address
    let verifying_contract = H160::from_str(&domain.verifying_contract)?;
    let verifying_contract_hash = H256::from(verifying_contract).as_bytes().to_vec();

    // Concatenate all the hashes
    // the order of the fields is important, the same as the order in the domainTypeHash
    let mut encoded_data = vec![];
    encoded_data.extend_from_slice(&domain_type_hash);
    encoded_data.extend_from_slice(&name_hash);
    encoded_data.extend_from_slice(&version_hash);
    encoded_data.extend_from_slice(&chain_id_hash);
    encoded_data.extend_from_slice(&verifying_contract_hash);

    Ok(keccak256(&encoded_data))
}

// Hash order data using EIP712 logic, similar to Go's hashOrder
fn hash_order(order: &Order) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // Type hash for the Order type
    let order_type_hash = keccak256("Order(address sender,uint128 size,uint128 price,uint64 nonce,uint8 productIndex,uint8 orderSide)".as_bytes());

    // Hash the individual fields with proper padding
    let sender = H160::from_str(&order.sender)?;
    let sender_hash = H256::from(sender);

    let size_hash = int_string_to_32bytes(&order.size)?;
    let price_hash = int_string_to_32bytes(&order.price)?;

    let nonce_hash = pad_to_32_bytes(order.nonce.to_be_bytes().as_ref());
    let product_index_hash = pad_to_32_bytes(&[order.product_index]);
    let side_hash = pad_to_32_bytes(&[order.side]);

    // Concatenate all the fields (ordering is important)
    let mut encoded_data = vec![];
    encoded_data.extend_from_slice(&order_type_hash);
    encoded_data.extend_from_slice(sender_hash.as_bytes());
    encoded_data.extend_from_slice(&size_hash);
    encoded_data.extend_from_slice(&price_hash);
    encoded_data.extend_from_slice(&nonce_hash);
    encoded_data.extend_from_slice(&product_index_hash);
    encoded_data.extend_from_slice(&side_hash);

    // Final hash of the entire struct
    Ok(keccak256(&encoded_data))
}

// Helper function to convert a string representing an integer to a 32-byte padded array
fn int_string_to_32bytes(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let big_int = U256::from_dec_str(s)?;
    let mut bytes = [0u8; 32]; // Create a 32-byte array
    big_int.to_big_endian(&mut bytes); // Convert to big-endian representation
    Ok(bytes.to_vec())
}

// Helper function to pad bytes to 32 bytes
fn pad_to_32_bytes(input: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; 32];
    let input_len = input.len();
    padded[32 - input_len..].copy_from_slice(input);
    padded
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domain = Domain {
        name: "BSX Testnet".to_string(),
        version: "1".to_string(),
        chain_id: "8453".to_string(),
        verifying_contract: "0x0000000000000000000000000000000000000002".to_string(),
    };

    let order = Order {
        sender: "0x0000000000000000000000000000000000000001".to_string(),
        size: "1230000000000000000".to_string(),
        price: "123400000000000000000".to_string(),
        nonce: 1632816000000000000,
        product_index: 1,
        side: 0,
    };

    let private_key = "0000000000000000000000000000000000000000000000000000000000000001";

    let signature = manually_sign_order(private_key, domain, order)?;
    println!("Signature: {}", hex::encode(signature));

    // stdout:
    // domainSeparator: 452197ade50f91a3e8593509e6cbf206700b274eaa41dc959a141a499d1943ef
    // typedDataHash: fbea394814ee65e1fcdcd78ecef18fb69fb58f0ba604903b2eec33cd676c446e
    // Signature: 8cc51c73e31b54427e638fdc195601b1244e4db6be3d0af9661c058f697709ec5652fdb52ba7c8d7f808e05f7c509b3db7c7acb075164f993b1fb60da85596571c

    Ok(())
}
