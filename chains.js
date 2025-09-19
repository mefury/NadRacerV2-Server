import { defineChain } from 'viem';
import dotenv from 'dotenv';

dotenv.config();

const MONAD_RPC_URL = process.env.MONAD_RPC_URL || '';
const MONAD_BLOCK_EXPLORER_URL = process.env.MONAD_BLOCK_EXPLORER_URL || '';

export const monadTestnet = defineChain({
  id: 10143,
  name: 'Monad Testnet',
  network: 'monad-testnet',
  nativeCurrency: {
    decimals: 18,
    name: 'Monad',
    symbol: 'MON',
  },
  rpcUrls: {
    default: {
      http: MONAD_RPC_URL ? [MONAD_RPC_URL] : [],
    },
    public: {
      http: MONAD_RPC_URL ? [MONAD_RPC_URL] : [],
    },
  },
  blockExplorers: {
    default: { name: 'Monad Explorer', url: MONAD_BLOCK_EXPLORER_URL },
  },
  testnet: true,
});
