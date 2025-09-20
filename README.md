# Flargo Ledger - Agricultural Supply Chain Blockchain

**FlargoLedger** is a tamper-proof blockchain ledger designed for agricultural supply chain transparency. It enables secure tracking of produce from farm to consumer using wallet-based digital signatures for transaction verification.

## What Does This Contract Do?

The FlargoLedger smart contract provides:

- **Immutable Record Keeping**: All transactions are cryptographically signed and stored permanently on the blockchain
- **Supply Chain Traceability**: Track agricultural products from farmer registration through to final orders
- **Wallet-Based Authentication**: Users sign transactions with their private keys to ensure authenticity
- **Role-Based Access Control**: Farmers, distributors, retailers, and customers have specific permissions
- **Data Integrity Verification**: Any party can verify that ledger entries haven't been tampered with

### Key Features

1. **User Registration**: Farmers, distributors, retailers register with wallet signatures
2. **Product Registration**: Only farmers can register agricultural products with price and category
3. **Order Creation**: Buyers create orders that are cryptographically signed and verified
4. **Status Updates**: Order status changes are recorded with signature verification
5. **Audit Trail**: Complete history of all transactions with tamper-proof verification

### Use Cases

- **Farmers**: Register products, confirm orders, update delivery status
- **Distributors/Retailers**: Place orders, track shipments, verify product authenticity
- **Consumers**: Verify product origin and supply chain history
- **Regulators**: Audit supply chain data for compliance and safety
