# Weave Security: Revenue Model & Treasury Setup

## How Protocol Fees Work

When users anchor threads to blockchain, they pay:
1. **Network Fee** - Goes to Solana/Ethereum validators
2. **Protocol Fee** - Goes to YOUR treasury wallet

### Fee Structure

| Chain | Network Fee | Protocol Fee | Your Revenue |
|-------|-------------|--------------|--------------|
| Solana | ~0.000005 SOL | 0.0001 SOL (~$0.02) | 100% of protocol fee |
| Ethereum | ~$2-10 (gas) | 5% of gas (~$0.10-0.50) | 100% of protocol fee |

## Setting Up Your Treasury

### Step 1: Create Wallet Addresses

**Solana Treasury:**
```bash
# Using Solana CLI
solana-keygen new --outfile treasury-solana.json

# Save the public key - this is your treasury address
solana-keygen pubkey treasury-solana.json
# Example: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
```

**Ethereum Treasury:**
```bash
# Using any wallet (MetaMask, Ledger, etc.)
# Just need an address you control
# Example: 0x742d35Cc6634C0532925a3b844Bc9e7595f8a2E1
```

### Step 2: Deploy Smart Contracts

**Solana Program (Anchor):**
```rust
// In contracts/solana/weave_protocol.rs
// Update the treasury address:
pub const TREASURY: Pubkey = pubkey!("YOUR_SOLANA_TREASURY_ADDRESS");
```

Deploy:
```bash
cd contracts/solana
anchor build
anchor deploy --provider.cluster mainnet

# Save the program ID
# Example: WeaveXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

**Ethereum Contract:**
```solidity
// In contracts/ethereum/WeaveProtocol.sol
// Deploy with your treasury address as constructor argument
constructor(address _treasury) {
    treasury = _treasury;  // Your Ethereum address
}
```

Deploy:
```bash
# Using Hardhat or Foundry
npx hardhat run scripts/deploy.js --network mainnet

# Or via Remix IDE
# Constructor arg: your Ethereum treasury address
```

### Step 3: Update Weave Configuration

In `domere/src/constants.ts`:
```typescript
export const DEFAULT_CONFIG = {
  anchoring: {
    // Your deployed program/contract addresses
    solana_program_id: 'YOUR_PROGRAM_ID',
    ethereum_contract: 'YOUR_CONTRACT_ADDRESS',
    
    // Public RPCs (or your own nodes)
    solana_rpc: 'https://api.mainnet-beta.solana.com',
    ethereum_rpc: 'https://mainnet.infura.io/v3/YOUR_KEY',
  }
};

export const PROTOCOL_FEES = {
  solana: {
    base_lamports: 100000,  // 0.0001 SOL
  },
  ethereum: {
    protocol_fee_bps: 500,  // 5% of gas
  }
};
```

## Monitoring Revenue

### Solana

**View Treasury Balance:**
```bash
solana balance YOUR_TREASURY_ADDRESS
```

**View Transaction History:**
- Solscan: https://solscan.io/account/YOUR_TREASURY_ADDRESS
- Solana Explorer: https://explorer.solana.com/address/YOUR_TREASURY_ADDRESS

**Set Up Alerts:**
```javascript
// Using Helius or similar
const webhook = await helius.createWebhook({
  accountAddresses: ['YOUR_TREASURY_ADDRESS'],
  webhookURL: 'https://your-server.com/treasury-webhook'
});
```

### Ethereum

**View Treasury Balance:**
- Etherscan: https://etherscan.io/address/YOUR_TREASURY_ADDRESS

**View Protocol Fee Events:**
```javascript
// Listen for ProtocolFeePaid events from your contract
const filter = contract.filters.ProtocolFeePaid();
contract.on(filter, (threadId, amount, timestamp) => {
  console.log(`Fee received: ${amount} wei`);
});
```

## Revenue Projections

### Conservative (1,000 companies, 100 anchors/day)

| Metric | Solana | Ethereum |
|--------|--------|----------|
| Daily anchors | 100,000 | 1,000 |
| Fee per anchor | $0.02 | $0.25 |
| Daily revenue | $2,000 | $250 |
| **Monthly** | **$60,000** | **$7,500** |
| **Annual** | **$730,000** | **$91,250** |

### Growth (10,000 companies, 500 anchors/day)

| Metric | Solana | Ethereum |
|--------|--------|----------|
| Daily anchors | 5,000,000 | 10,000 |
| Fee per anchor | $0.02 | $0.25 |
| Daily revenue | $100,000 | $2,500 |
| **Monthly** | **$3,000,000** | **$75,000** |
| **Annual** | **$36,500,000** | **$912,500** |

## Withdrawing Funds

### From Solana Treasury
```bash
# Transfer to your personal wallet or exchange
solana transfer \
  --from treasury-solana.json \
  --to YOUR_PERSONAL_WALLET \
  AMOUNT_IN_SOL
```

### From Ethereum Treasury
```javascript
// Using ethers.js with your treasury private key
const tx = await treasury.sendTransaction({
  to: personalWallet,
  value: ethers.parseEther('1.0')
});
```

## Tax Considerations

**Important:** Protocol fees are likely taxable income. Consult a crypto-savvy accountant.

Track:
- Each incoming transaction timestamp
- USD value at time of receipt
- Source (which thread/user)

Tools:
- Koinly, CoinTracker, or TokenTax for reporting
- Export Solscan/Etherscan CSV for records

## Security Best Practices

1. **Use Hardware Wallet** - Treasury keys should be on Ledger/Trezor
2. **Multi-sig** - Consider Squads (Solana) or Safe (Ethereum) for treasury
3. **Separate Hot/Cold** - Keep operational funds separate from reserves
4. **Regular Withdrawals** - Don't accumulate large balances on-chain
5. **Monitor Alerts** - Set up notifications for large transactions

## Alternative: No-Code Revenue Dashboard

If you want a simpler setup, consider:

1. **Dune Analytics** - Create custom dashboard
2. **Flipside Crypto** - SQL-based analytics
3. **Nansen** - Portfolio tracking

Example Dune query:
```sql
SELECT 
  date_trunc('day', block_time) as day,
  count(*) as anchor_count,
  sum(value/1e9) as protocol_fees_sol
FROM solana.transactions
WHERE program_id = 'YOUR_PROGRAM_ID'
GROUP BY 1
ORDER BY 1 DESC
```

## Questions?

The key insight: **You own the treasury.** 

The smart contracts are deployed with YOUR address hardcoded. Protocol fees go directly to you, not through any intermediary.

This is why the business model works:
- Open source = adoption
- Blockchain anchoring = value-add users will pay for
- Protocol fees = sustainable revenue without vendor lock-in
