import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { createPublicClient, createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { monadTestnet } from './chains.js';
import { jwtVerify, createRemoteJWKSet } from 'jose';

// Load environment variables
dotenv.config();

// Polyfill crypto for Node.js compatibility with jose library
if (!globalThis.crypto) {
  if (!crypto.webcrypto) {
    console.error('❌ Node.js version does not support webcrypto. Please upgrade to Node.js 16+ for JWT authentication.');
    process.exit(1);
  }
  globalThis.crypto = crypto.webcrypto;
  console.log('✅ Crypto polyfill applied for jose library compatibility');
}

// Validate required environment variables
const requiredEnvVars = [
  'PRIVATE_KEY',
  'PRIVY_APP_ID',
  'MONAD_APP_ID',
  'GAME_ADDRESS',
  'MONAD_RPC_URL',
  'SCORE_HMAC_SECRET'
];

// Development mode flag
const isDevelopment = process.env.NODE_ENV !== 'production';

// Configurable Rate Limiting & Score Validation Settings
const RATE_LIMIT_GENERAL_WINDOW_MS = parseInt(process.env.RATE_LIMIT_GENERAL_WINDOW_MS) || 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_GENERAL_MAX = parseInt(process.env.RATE_LIMIT_GENERAL_MAX) || 100; // requests per window
const RATE_LIMIT_SCORE_WINDOW_MS = parseInt(process.env.RATE_LIMIT_SCORE_WINDOW_MS) || 60 * 1000; // 1 minute
const RATE_LIMIT_SCORE_MAX = parseInt(process.env.RATE_LIMIT_SCORE_MAX) || 10; // score submissions per window

// Score Validation Limits
const MAX_SCORE_LIMIT = parseInt(process.env.MAX_SCORE_LIMIT) || 1000000;
const MAX_TRANSACTIONS_LIMIT = parseInt(process.env.MAX_TRANSACTIONS_LIMIT) || 10000;
const MAX_REASONABLE_SCORE = parseInt(process.env.MAX_REASONABLE_SCORE) || 10000;
const SUSPICIOUS_SCORE_THRESHOLD = parseInt(process.env.SUSPICIOUS_SCORE_THRESHOLD) || 100000;

// Session/Nonce Security Settings
const SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS) || 10 * 60 * 1000; // 10 minutes
const NONCE_TTL_MS = parseInt(process.env.NONCE_TTL_MS) || 2 * 60 * 1000; // 2 minutes
const MAX_CLOCK_SKEW_MS = parseInt(process.env.MAX_CLOCK_SKEW_MS) || 2 * 60 * 1000; // 2 minutes
const MIN_NONCE_INTERVAL_MS = parseInt(process.env.MIN_NONCE_INTERVAL_MS) || 3000; // per session
const MIN_SUBMIT_INTERVAL_MS = parseInt(process.env.MIN_SUBMIT_INTERVAL_MS) || 3000; // per session
const QUEUE_BACKPRESSURE_RATIO = parseFloat(process.env.QUEUE_BACKPRESSURE_RATIO) || 0.8;
const SCORE_HMAC_SECRET = process.env.SCORE_HMAC_SECRET;

// Anti-Spam & Cheating Prevention (High Priority Fixes)
const MIN_SESSION_DURATION_MS = parseInt(process.env.MIN_SESSION_DURATION_MS) || 15000; // 15 seconds minimum gameplay
const MIN_TIME_TO_FIRST_COIN_MS = parseInt(process.env.MIN_TIME_TO_FIRST_COIN_MS) || 500; // 0.5 seconds before first coin (reasonable for racing games)
const MAX_SCORE_PER_SECOND = parseInt(process.env.MAX_SCORE_PER_SECOND) || 10; // max realistic score rate
const MAX_NONCES_PER_SESSION = parseInt(process.env.MAX_NONCES_PER_SESSION) || 5; // limit nonce requests per session
const START_GAME_RATE_WINDOW_MS = parseInt(process.env.START_GAME_RATE_WINDOW_MS) || 5 * 60 * 1000; // 5 minute window
const MAX_START_GAMES_PER_WINDOW = parseInt(process.env.MAX_START_GAMES_PER_WINDOW) || 10; // max game starts per wallet
const MIN_REALISTIC_COIN_INTERVAL_MS = parseInt(process.env.MIN_REALISTIC_COIN_INTERVAL_MS) || 100; // match client's 100ms timestamp rounding
const MAX_REALISTIC_COINS_PER_MIN = parseInt(process.env.MAX_REALISTIC_COINS_PER_MIN) || 200; // allow skilled players

// Event-proof validation parameters
const MIN_COIN_INTERVAL_MS = parseInt(process.env.MIN_COIN_INTERVAL_MS) || 250; // min gap between coin collects
const MAX_COINS_PER_MIN = parseInt(process.env.MAX_COINS_PER_MIN) || 180; // generous upper bound

// Per-Wallet Rate Limiting (Enhanced for Production)
const WALLET_SUBMISSIONS_PER_HOUR = parseInt(process.env.WALLET_SUBMISSIONS_PER_HOUR) || (isDevelopment ? 20 : 10);
const WALLET_RATE_RESET_MS = parseInt(process.env.WALLET_RATE_RESET_MS) || 60 * 60 * 1000; // 1 hour

// Session Management
const MAX_SESSION_AGE_MS = parseInt(process.env.MAX_SESSION_AGE_MS) || 30 * 60 * 1000; // 30 minutes
const SESSION_CLEANUP_AGE_MS = parseInt(process.env.SESSION_CLEANUP_AGE_MS) || 60 * 60 * 1000; // 1 hour

// Game session management for anti-cheat
const activeGameSessions = new Map(); // sessionId -> { walletAddress, startTime, exp, ipHash, uaHash, finalized, lastNonceAt, lastSubmitAt, idempotencyKeys:Set<string>, sessionSalt, nonceCount }
const recentSubmissions = new Map(); // walletAddress -> { lastSubmission, submissionCount }
const walletStartGameAttempts = new Map(); // walletAddress -> { attempts: [], lastCleanup }

// One-time nonce store for replay protection
const nonces = new Map(); // jti -> { sid, walletAddress, exp, used, ipHash, uaHash, createdAt }

// Queue system for score submissions
class ScoreSubmissionQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
    this.maxRetries = 3;
    this.processingInterval = 500; // Process every 0.5 seconds for faster testing
    this.maxQueueSize = 100; // Maximum queue size
    this.processingTimer = null;
    // Ensure we process one item at a time to avoid overlapping submissions
    this.isWorking = false;
    // Keep a short-lived record of completed items so clients can fetch final status/tx hash
    this.completedItems = new Map(); // id -> { id, status: 'completed'|'failed', transactionHash?, timestamp }
    this.completedRetentionMs = 10 * 60 * 1000; // Retain for 10 minutes
  }

  // Add score submission to queue
  async addSubmission(submission, queueIdOverride) {
    return new Promise((resolve, reject) => {
      if (this.queue.length >= this.maxQueueSize) {
        reject(new Error('Queue is full. Please try again later.'));
        return;
      }

      const queueItem = {
        id: queueIdOverride || `submission_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        submission,
        timestamp: Date.now(),
        retries: 0,
        status: 'queued',
        resolve,
        reject
      };

      this.queue.push(queueItem);
      console.log(`📋 Added to queue: ${queueItem.id}, Queue size: ${this.queue.length}`);

      // Start processing if not already running
      if (!this.processing) {
        this.startProcessing();
      }
    });
  }

  // Start processing queue
  startProcessing() {
    if (this.processing) return;

    this.processing = true;
    console.log('🚀 Starting score submission queue processing');

    this.processingTimer = setInterval(() => {
      this.processNextItem();
    }, this.processingInterval);
  }

  // Stop processing queue
  stopProcessing() {
    if (this.processingTimer) {
      clearInterval(this.processingTimer);
      this.processingTimer = null;
    }
    this.processing = false;
    console.log('⏹️ Stopped score submission queue processing');
  }

  // Process next item in queue
  async processNextItem() {
    // Prevent overlapping processing; handle one item at a time
    if (this.isWorking) return;
    if (this.queue.length === 0) {
      console.log('📋 Queue empty, stopping processing');
      this.stopProcessing();
      return;
    }

    this.isWorking = true;
    const item = this.queue.shift();
    item.status = 'processing';
    this.currentItem = item; // track currently processing item for status visibility
    console.log(`⚙️ Processing queue item: ${item.id}`);

    try {
      const submissionResult = await this.processSubmission(item);
      item.status = 'completed';
      item.result = submissionResult; // Store the result for access
      console.log(`✅ Queue item ${item.id} completed with TX hash:`, submissionResult?.transactionHash);

      // Save a short-lived record so clients can fetch status after completion
      this.completedItems.set(item.id, {
        id: item.id,
        status: 'completed',
        transactionHash: submissionResult?.transactionHash,
        timestamp: Date.now(),
      });

      item.resolve({
        success: true,
        queueId: item.id,
        transactionHash: submissionResult?.transactionHash,
        message: 'Score submitted successfully'
      });
    } catch (error) {
      console.error(`❌ Failed to process queue item ${item.id}:`, error.message);

      item.retries++;

      if (item.retries < this.maxRetries) {
        // Re-queue for retry
        item.status = 'retrying';
        this.queue.unshift(item); // Add back to front for immediate retry
        console.log(`🔄 Re-queuing item ${item.id} for retry (${item.retries}/${this.maxRetries})`);
      } else {
        // Max retries reached, fail permanently
        item.status = 'failed';
        // Record failure for visibility
        this.completedItems.set(item.id, {
          id: item.id,
          status: 'failed',
          transactionHash: undefined,
          timestamp: Date.now(),
        });
        item.reject(new Error(`Failed to submit score after ${this.maxRetries} attempts: ${error.message}`));
      }
    } finally {
      this.isWorking = false;
      // Clear current item tracker when done
      if (this.currentItem && this.currentItem.id === item.id) {
        this.currentItem = null;
      }
    }
  }

  // Process individual submission
  async processSubmission(item) {
    const { submission } = item;
    const { playerAddress, score, sessionId } = submission;

    console.log(`📤 Processing score submission: ${playerAddress}, Score: ${score}`);

    // Simulate blockchain submission (replace with actual logic)
    if (!walletClient) {
      throw new Error('Score submission not available - server wallet not configured');
    }

    if (!GAME_ADDRESS) {
      throw new Error('Game not registered yet');
    }

    // Get current accumulated score
    let currentTotalScore = 0;
    let currentTransactions = 0;
    try {
      const currentData = await publicClient.readContract({
        address: LEADERBOARD_CONTRACT,
        abi: LEADERBOARD_ABI,
        functionName: 'playerDataPerGame',
        args: [GAME_ADDRESS, playerAddress]
      });

      currentTotalScore = Number(currentData[0]);
      currentTransactions = Number(currentData[1]);
      console.log(`📊 Current total score for ${playerAddress}: ${currentTotalScore}, games played: ${currentTransactions}`);
    } catch (error) {
      console.log(`📊 No existing data found for ${playerAddress}, this will be their first game`);
    }

    // Submit score to blockchain
    let hash;
    try {
      hash = await walletClient.writeContract({
        address: LEADERBOARD_CONTRACT,
        abi: LEADERBOARD_ABI,
        functionName: 'updatePlayerData',
        args: [playerAddress, BigInt(score), BigInt(1)],
        gas: 200000n,
      });
      // Expose the tx hash early so clients polling during processing can see it
      item.result = { ...(item.result || {}), transactionHash: hash };
    } catch (contractError) {
      if (contractError.message && contractError.message.includes('Another transaction has higher priority')) {
        console.log('⚠️ Contract rate limiting detected - this is normal for frequent submissions');
        throw new Error('Score submission rate limited by contract');
      }

      if (contractError.message && contractError.message.includes('BigInt')) {
        console.log('⚠️ BigInt serialization error - this is a technical issue');
        throw new Error('Technical error with score submission');
      }

      throw contractError;
    }

    console.log(`📤 Transaction sent: ${hash}`);

    // Wait for transaction confirmation
    try {
      const receipt = await publicClient.waitForTransactionReceipt({
        hash: hash,
        timeout: 30000,
      });

      console.log(`✅ Transaction confirmed! Block: ${receipt.blockNumber}, Status: ${receipt.status}`);

      if (receipt.status !== 'success') {
        throw new Error('Transaction failed on-chain');
      }

      return {
        success: true,
        transactionHash: hash,
        blockNumber: Number(receipt.blockNumber),
        playerAddress,
        score,
        transactions: 1,
        submittedAt: new Date().toISOString()
      };

    } catch (waitError) {
      console.error('❌ Transaction confirmation timeout:', waitError);
      // Transaction was sent but confirmation timed out
      return {
        success: true,
        transactionHash: hash,
        playerAddress,
        score,
        transactions: 1,
        submittedAt: new Date().toISOString(),
        note: 'Transaction sent but confirmation timeout - score submitted to blockchain'
      };
    }
  }

  // Get queue status
  getStatus() {
    return {
      queueSize: this.queue.length,
      processing: this.processing,
      maxQueueSize: this.maxQueueSize,
      processingInterval: this.processingInterval,
      items: this.queue.map(item => ({
        id: item.id,
        status: item.status,
        retries: item.retries,
        timestamp: item.timestamp
      }))
    };
  }

  // Clean up old failed items
  cleanup() {
    const now = Date.now();
    this.queue = this.queue.filter(item => {
      // Remove items older than 5 minutes that have failed
      if (item.status === 'failed' && (now - item.timestamp) > 300000) {
        console.log(`🧹 Cleaned up failed queue item: ${item.id}`);
        return false;
      }
      return true;
    });

    // Clean up old completed/failed records from the completedItems map
    for (const [id, meta] of this.completedItems.entries()) {
      if ((now - meta.timestamp) > this.completedRetentionMs) {
        this.completedItems.delete(id);
      }
    }
  }
}

// Initialize queue system
const scoreQueue = new ScoreSubmissionQueue();

// Utility helpers (crypto, time, hashing, HMAC)
const nowMs = () => Date.now();
const sha256 = (input) => crypto.createHash('sha256').update(String(input)).digest('hex');
const hmac = (input) => crypto.createHmac('sha256', SCORE_HMAC_SECRET).update(String(input)).digest('hex');
const ipHashOf = (ip) => sha256(ip || '');
const uaHashOf = (ua) => sha256(ua || '');

// Canonical messages for wallet signatures
const startMessage = (wallet, ts) => `nad-racer:start|${wallet.toLowerCase()}|${ts}`;
const submitMessage = (sid, jti, score, ts) => `nad-racer:submit|${sid}|${jti}|${score}|${ts}`;

// Clean up queue every 5 minutes
setInterval(() => {
  scoreQueue.cleanup();
}, 300000);

// Clean up expired nonces and idempotency keys periodically
setInterval(() => {
  const now = nowMs();
  for (const [jti, meta] of nonces.entries()) {
    if (now > meta.exp + 60 * 1000) { // grace period after expiry
      nonces.delete(jti);
    }
  }
  for (const [sid, session] of activeGameSessions.entries()) {
    if (now > (session.exp || 0)) {
      activeGameSessions.delete(sid);
      continue;
    }
    // prune old idempotency keys (older than session start + TTL window)
    if (session.idempotencyKeys instanceof Map) {
      for (const [k, t] of session.idempotencyKeys.entries()) {
        if (now - t > SESSION_TTL_MS) session.idempotencyKeys.delete(k);
      }
    }
  }
}, 120000);

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars);
  console.error('Please check your .env file and ensure all required variables are set');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

// Lightweight requestId middleware for correlation (no extra deps)
app.use((req, res, next) => {
  const id = (crypto.randomUUID && crypto.randomUUID()) || `req_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
});

// Behind reverse proxies (e.g., Traefik) trust only the first hop (the proxy)
// Using a numeric hop count avoids overly-permissive trust that could weaken rate limiting
app.set('trust proxy', 1);

// Secure CORS configuration
// Parse CORS origins strictly from environment variables (no hardcoded links)
const getCorsOrigins = () => {
  const origins = [];

  // Primary frontend URL (single)
  if (process.env.FRONTEND_URL) {
    origins.push(process.env.FRONTEND_URL);
  }

  // Additional allowed origins (comma-separated)
  if (process.env.CORS_ALLOWED_ORIGINS) {
    const additional = process.env.CORS_ALLOWED_ORIGINS
      .split(',')
      .map(o => o.trim())
      .filter(Boolean);
    origins.push(...additional);
  }

  // Unique list
  return [...new Set(origins)];
};

const allowedOrigins = getCorsOrigins();
console.log('🔐 CORS allowed origins:', allowedOrigins);

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);

    // If no allow-list is configured, allow any origin (safe without cookies)
    if (allowedOrigins.length === 0) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn(`🚫 CORS blocked request from: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-monad-app-id']
}));

// Enhanced security headers - CSP disabled for Privy compatibility

app.use(helmet({
  contentSecurityPolicy: false, // Disabled for Privy compatibility
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Request size limits for security
app.use(express.json({
  limit: '10kb',  // Reduce from 10mb to 10kb for API endpoints
  strict: true    // Only accept arrays and objects
}));

app.use(express.urlencoded({
  extended: true,
  limit: '10kb'
}));

// Rate limiting - Enhanced for Production
const generalMaxRequests = isDevelopment ? RATE_LIMIT_GENERAL_MAX : Math.floor(RATE_LIMIT_GENERAL_MAX * 0.7);
const limiter = rateLimit({
  windowMs: RATE_LIMIT_GENERAL_WINDOW_MS,
  max: generalMaxRequests,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Stricter rate limiting for score submissions - Production gets tighter limits
const scoreMaxRequests = isDevelopment ? RATE_LIMIT_SCORE_MAX : Math.floor(RATE_LIMIT_SCORE_MAX * 0.5);
const scoreLimiter = rateLimit({
  windowMs: RATE_LIMIT_SCORE_WINDOW_MS,
  max: scoreMaxRequests,
  message: 'Too many score submissions, please try again later.'
});
app.use('/api/submit-score', scoreLimiter);

// Additional rate limiter for start-game endpoint
const startGameLimiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 2 minute window
  max: isDevelopment ? 30 : 15, // tighter in production
  message: 'Too many game start attempts, please wait.'
});
app.use('/api/start-game', startGameLimiter);

// Nonce endpoint rate limiter
const nonceLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: isDevelopment ? 20 : 10, // much tighter in production
  message: 'Too many nonce requests, please slow down.'
});
app.use('/api/session/:sid/nonce', nonceLimiter);

// Contract configuration
const LEADERBOARD_CONTRACT = '0xceCBFF203C8B6044F52CE23D914A1bfD997541A4';
const GAME_ADDRESS = process.env.GAME_ADDRESS; // Will be set after game registration

// API Configuration from environment (no hardcoded defaults)
const MONAD_APP_ID = process.env.MONAD_APP_ID;
const MONAD_USERNAME_API = process.env.MONAD_USERNAME_API;
const PRIVY_SECRET_KEY = process.env.PRIVY_SECRET_KEY; // Not needed for JWT verification but kept for compatibility

// Contract ABI
const LEADERBOARD_ABI = [
  {
    "inputs": [
      {"internalType": "address", "name": "player", "type": "address"},
      {"internalType": "uint256", "name": "scoreAmount", "type": "uint256"},
      {"internalType": "uint256", "name": "transactionAmount", "type": "uint256"}
    ],
    "name": "updatePlayerData",
    "outputs": [],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {"internalType": "address", "name": "", "type": "address"},
      {"internalType": "address", "name": "", "type": "address"}
    ],
    "name": "playerDataPerGame",
    "outputs": [
      {"internalType": "uint256", "name": "score", "type": "uint256"},
      {"internalType": "uint256", "name": "transactions", "type": "uint256"}
    ],
    "stateMutability": "view",
    "type": "function"
  },
  {
    "inputs": [{"internalType": "address", "name": "", "type": "address"}],
    "name": "totalScoreOfPlayer",
    "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
    "stateMutability": "view",
    "type": "function"
  }
];

// Initialize blockchain clients
let publicClient;
let walletClient;

try {
  // Public client for reading data (free)
publicClient = createPublicClient({
    chain: monadTestnet,
    transport: http(process.env.MONAD_RPC_URL)
  });

  // Wallet client for writing data (requires private key)
  if (process.env.PRIVATE_KEY) {
    const account = privateKeyToAccount(process.env.PRIVATE_KEY);
walletClient = createWalletClient({
      account,
      chain: monadTestnet,
      transport: http(process.env.MONAD_RPC_URL)
    });
    console.log('✅ Wallet client initialized for score submissions');
  } else {
    console.warn('⚠️ PRIVATE_KEY not found - score submissions will be disabled');
  }

  console.log('✅ Blockchain clients initialized');
} catch (error) {
  console.error('❌ Failed to initialize blockchain clients:', error);
  process.exit(1);
}

// Privy JWT verification using jose library with JWKS
const JWKS_CACHE_TTL = 3600000; // 1 hour
let privyJWKSet = null;
let jwksSetTime = 0;

// Create or get cached JWKS for Privy with enhanced logging
const getPrivyJWKSet = () => {
  const now = Date.now();
  
  // Return cached JWKS if still valid
  if (privyJWKSet && (now - jwksSetTime) < JWKS_CACHE_TTL) {
    const remainingMinutes = Math.floor((JWKS_CACHE_TTL - (now - jwksSetTime)) / 60000);
    console.log(`🔑 Using cached JWKS (valid for ${remainingMinutes} more minutes)`);
    return privyJWKSet;
  }
  
  // Create new remote JWKS
  const jwksUrl = `https://auth.privy.io/api/v1/apps/${process.env.PRIVY_APP_ID}/jwks.json`;
  console.log(`🔑 Creating fresh JWKS set from: ${jwksUrl}`);
  privyJWKSet = createRemoteJWKSet(new URL(jwksUrl));
  jwksSetTime = now;
  console.log(`🔑 ✅ JWKS cached until: ${new Date(now + JWKS_CACHE_TTL).toISOString()}`);
  
  return privyJWKSet;
};

// Complete JWT verification with cryptographic signature validation and comprehensive logging
const verifyPrivyJWT = async (token) => {
  try {
    console.log('🔐 Starting JWT verification process');
    const jwks = getPrivyJWKSet();
    
    // Log token structure for debugging (first few chars only)
    console.log('🔐 Token preview:', token.substring(0, 20) + '...' + token.slice(-20));
    
    // Verify JWT with full cryptographic validation
    const { payload } = await jwtVerify(token, jwks, {
      issuer: 'privy.io',
      audience: process.env.PRIVY_APP_ID,
      // Clock tolerance for slight time differences
      clockTolerance: 30 // 30 seconds
    });
    
    console.log('🔐 ✅ JWT verification successful');
    return payload;
  } catch (error) {
    console.error('🔐 ❌ JWT verification failed:', {
      code: error.code,
      message: error.message,
      claim: error.claim,
      reason: error.reason
    });
    
    // Enhanced error messages for debugging
    if (error.code === 'ERR_JWT_EXPIRED') {
      throw new Error('Access token has expired');
    } else if (error.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      throw new Error('Invalid token signature');
    } else if (error.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
      throw new Error(`Token claim validation failed: ${error.claim || 'unknown'} - ${error.reason || error.message}`);
    } else if (error.code === 'ERR_JWKS_NO_MATCHING_KEY') {
      throw new Error('No matching key found in JWKS for token verification');
    } else {
      throw new Error(`JWT verification failed: ${error.message}`);
    }
  }
};

// Enhanced Privy auth verification middleware with comprehensive JWT validation
const verifyPrivyAuth = async (req, res, next) => {
  const startTime = Date.now();
  
  try {
    const isLocalhost = (req.hostname === 'localhost' || req.hostname === '127.0.0.1' || req.ip === '::1');
    const authHeader = req.headers.authorization || '';

    // Unconditional dev/localhost bypass: never require bearer token in dev/local
    if (isDevelopment || isLocalhost) {
      const player = (req.body?.playerAddress || req.params?.playerAddress || '').toLowerCase();
      req.auth = { userId: isDevelopment ? 'dev' : 'dev-local', walletAddress: player };
      console.log(`[${req.requestId}] 🔓 Dev/localhost auth bypass for: ${player}`);
      return next();
    }

    if (!authHeader.startsWith('Bearer ')) {
      console.warn(`[${req.requestId}] 🚫 Missing bearer token from ${req.ip}`);
      return res.status(401).json({ error: 'Missing bearer token' });
    }
    const token = authHeader.slice(7);

    if (!process.env.PRIVY_APP_ID) {
      console.error(`[${req.requestId}] ❌ Privy app ID not configured`);
      return res.status(500).json({ error: 'Privy app ID not configured' });
    }

    console.log(`[${req.requestId}] 🔐 Verifying JWT token for app: ${process.env.PRIVY_APP_ID}`);

    // Verify JWT with complete cryptographic validation
    const payload = await verifyPrivyJWT(token);
    
    // For this app, we don't expect wallet info in JWT - wallet comes from request body
    // JWT is just for user authentication, not wallet binding
    console.log(`[${req.requestId}] 🐛 JWT verification successful for user: ${payload.sub || payload.user_id || 'unknown'}`);
    
    // Get wallet address from request body (this is how your app works)
    const walletAddress = (req.body?.playerAddress || req.params?.playerAddress || '').toLowerCase();
    
    if (!walletAddress || !/^0x[a-fA-F0-9]{40}$/.test(walletAddress)) {
      console.error(`[${req.requestId}] ❌ No valid wallet address in request body/params`);
      return res.status(400).json({ error: 'Missing or invalid playerAddress' });
    }
    
    console.log(`[${req.requestId}] 💰 Using wallet address from request: ${walletAddress}`);
    
    // TODO: Add additional security check to ensure the authenticated user 
    // has permission to use this wallet address (future enhancement)

    const authDuration = Date.now() - startTime;
    req.auth = { 
      userId: payload.sub || payload.user_id || payload.id || 'unknown', 
      walletAddress,
      tokenIssuer: 'privy'
    };
    
    console.log(`[${req.requestId}] ✅ Auth success: ${walletAddress} (${authDuration}ms)`);
    next();
  } catch (err) {
    const authDuration = Date.now() - startTime;
    console.error(`[${req.requestId}] ❌ Privy JWT auth failed (${authDuration}ms):`, err?.message || err);
    return res.status(401).json({ error: err.message || 'Auth verification failed' });
  }
};

// Validation middleware
const validateAddress = (req, res, next) => {
  // For GET requests, address comes from URL params
  // For POST requests, address comes from request body
  const playerAddress = req.params.playerAddress || req.body.playerAddress;

  if (!playerAddress || !/^0x[a-fA-F0-9]{40}$/.test(playerAddress)) {
    console.log('Address validation failed:', { playerAddress, isValid: /^0x[a-fA-F0-9]{40}$/.test(playerAddress || '') });
    return res.status(400).json({
      error: 'Invalid player address format'
    });
  }

  next();
};

const validateScoreSubmission = (req, res, next) => {
  const { playerAddress, score, transactions } = req.body;

  // Type validation
  if (!playerAddress || typeof score !== 'number' || typeof transactions !== 'number') {
    return res.status(400).json({
      error: 'Missing or invalid required fields: playerAddress, score, transactions'
    });
  }

  // Range validation
  if (score < 0 || transactions < 0) {
    return res.status(400).json({
      error: 'Score and transactions must be non-negative'
    });
  }

  // Reasonable limits validation
  if (score > MAX_SCORE_LIMIT || transactions > MAX_TRANSACTIONS_LIMIT) {
    return res.status(400).json({
      error: 'Score or transaction values too high'
    });
  }

  // Address format validation
  if (!/^0x[a-fA-F0-9]{40}$/.test(playerAddress)) {
    return res.status(400).json({
      error: 'Invalid wallet address format'
    });
  }

  // Additional security: Check for suspicious patterns
  if (score > SUSPICIOUS_SCORE_THRESHOLD && transactions === 1) {
    // Log suspicious activity
    console.warn(`⚠️ Suspicious score submission: ${score} points in single transaction from ${playerAddress}`);
  }

  next();
};

// API Routes

// Health check
app.get('/api/health', (req, res) => {
  const queueStatus = scoreQueue.getStatus();

  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    blockchain: publicClient ? 'connected' : 'disconnected',
    wallet: walletClient ? 'connected' : 'disconnected',
    queue: {
      active: queueStatus.processing,
      size: queueStatus.queueSize,
      maxSize: queueStatus.maxQueueSize,
      processingInterval: queueStatus.processingInterval
    },
    sessions: {
      active: activeGameSessions.size,
      totalSubmissions: Array.from(recentSubmissions.values()).reduce((sum, data) => sum + data.submissionCount, 0)
    }
  });
});

// Start game session (anti-cheat protection)
app.post('/api/start-game', verifyPrivyAuth, async (req, res) => {
  try {
    const { playerAddress } = req.body || {};
    const player = (playerAddress || '').toLowerCase();
    if (!player || !/^0x[a-fA-F0-9]{40}$/.test(player)) {
      return res.status(400).json({ error: 'Invalid player address format' });
    }

    // Bind to authenticated wallet
    if (!isDevelopment && req.auth?.walletAddress !== player) {
      return res.status(403).json({ error: 'Auth wallet mismatch' });
    }

    // Per-wallet start-game rate limiting (HIGH PRIORITY FIX #5)
    const now = nowMs();
    const walletAttempts = walletStartGameAttempts.get(player) || { attempts: [], lastCleanup: now };
    
    // Clean old attempts outside the window
    if (now - walletAttempts.lastCleanup > START_GAME_RATE_WINDOW_MS) {
      walletAttempts.attempts = walletAttempts.attempts.filter(t => now - t < START_GAME_RATE_WINDOW_MS);
      walletAttempts.lastCleanup = now;
    }
    
    // Check if wallet exceeds start-game rate limit
    if (walletAttempts.attempts.length >= MAX_START_GAMES_PER_WINDOW) {
      return res.status(429).json({ 
        error: 'Start-game rate limit exceeded', 
        message: `Too many game sessions started. Please wait before starting a new game.`,
        retryAfter: Math.ceil((walletAttempts.attempts[0] + START_GAME_RATE_WINDOW_MS - now) / 1000)
      });
    }
    
    // Record this attempt
    walletAttempts.attempts.push(now);
    walletStartGameAttempts.set(player, walletAttempts);

// Generate session id and bind context
const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
const ipHash = ipHashOf(req.ip);
const uaHash = uaHashOf(req.headers['user-agent'] || '');
const startTime = nowMs();
const exp = startTime + SESSION_TTL_MS;
const sessionSalt = crypto.randomBytes(16).toString('hex'); // 32-hex chars

const sessionData = {
  playerAddress: player,
  startTime,
  exp,
  gameState: 'active',
  ipHash,
  uaHash,
  finalized: false,
  lastNonceAt: 0,
  lastSubmitAt: 0,
  idempotencyKeys: new Map(), // key -> ts
  sessionSalt,
  nonceCount: 0, // HIGH PRIORITY FIX #6: Track nonce requests
};

    activeGameSessions.set(sessionId, sessionData);

    // Clean up expired sessions opportunistically
    for (const [id, session] of activeGameSessions.entries()) {
      if (nowMs() > (session.exp || 0)) {
        activeGameSessions.delete(id);
      }
    }

console.log(`[${req.requestId}] 🎮 Game session started: ${sessionId} for ${player}`);

res.json({ success: true, sessionId, sessionSalt, message: 'Game session started', requestId: req.requestId });
  } catch (error) {
    console.error('❌ Error starting game session:', error);
    res.status(500).json({ error: 'Failed to start game session' });
  }
});


// Get player data
app.get('/api/player/:playerAddress', validateAddress, async (req, res) => {
  try {
    const { playerAddress } = req.params;

    if (!GAME_ADDRESS) {
      return res.status(503).json({
        error: 'Game not registered yet'
      });
    }

    // Get player data for this game
    const gameData = await publicClient.readContract({
      address: LEADERBOARD_CONTRACT,
      abi: LEADERBOARD_ABI,
      functionName: 'playerDataPerGame',
      args: [GAME_ADDRESS, playerAddress]
    });

    // Get total score across all games
    const totalScore = await publicClient.readContract({
      address: LEADERBOARD_CONTRACT,
      abi: LEADERBOARD_ABI,
      functionName: 'totalScoreOfPlayer',
      args: [playerAddress]
    });

    res.json({
      playerAddress,
      gameScore: Number(gameData[0]), // score is first element in array
      gameTransactions: Number(gameData[1]), // transactions is second element in array
      totalScore: Number(totalScore),
      lastUpdated: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error fetching player data:', error);
    res.status(500).json({
      error: 'Failed to fetch player data'
    });
  }
});

// Nonce minting endpoint (one-time, short-lived)
// Note: This endpoint doesn't need playerAddress in body since it gets wallet from session
app.post('/api/session/:sid/nonce', async (req, res) => {
  // Custom auth for nonce endpoint that doesn't require playerAddress in body
  try {
    const isLocalhost = (req.hostname === 'localhost' || req.hostname === '127.0.0.1' || req.ip === '::1');
    const authHeader = req.headers.authorization || '';

    // Dev/localhost bypass
    if (isDevelopment || isLocalhost) {
      console.log(`[${req.requestId}] 🔓 Dev/localhost bypass for nonce endpoint`);
    } else {
      // Production auth - verify JWT but don't require playerAddress in body
      if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing bearer token' });
      }
      
      const token = authHeader.slice(7);
      const payload = await verifyPrivyJWT(token);
      console.log(`[${req.requestId}] 🔐 Nonce endpoint JWT verified for user: ${payload.sub || payload.user_id || 'unknown'}`);
    }
  } catch (err) {
    console.error(`[${req.requestId}] ❌ Nonce endpoint auth failed:`, err.message);
    return res.status(401).json({ error: err.message || 'Auth verification failed' });
  }
  
  // Nonce generation logic
  try {
    const { sid } = req.params;
    const session = activeGameSessions.get(sid);
    if (!session) return res.status(400).json({ error: 'Invalid or expired session' });
    if (session.finalized) return res.status(400).json({ error: 'Session finalized' });
    if (nowMs() > session.exp) {
      activeGameSessions.delete(sid);
      return res.status(400).json({ error: 'Session expired' });
    }

    // Context binding check
    const ipHash = ipHashOf(req.ip);
    const uaHash = uaHashOf(req.headers['user-agent'] || '');
    if (ipHash !== session.ipHash || uaHash !== session.uaHash) {
      return res.status(403).json({ error: 'Session context mismatch' });
    }

    // Per-session nonce pacing and count limiting (HIGH PRIORITY FIX #6)
    const now = nowMs();
    if (now - (session.lastNonceAt || 0) < MIN_NONCE_INTERVAL_MS) {
      return res.status(429).json({ error: 'Too many nonce requests' });
    }
    
    // Nonce count limit per session
    if ((session.nonceCount || 0) >= MAX_NONCES_PER_SESSION) {
      return res.status(429).json({ 
        error: 'Session nonce limit exceeded',
        message: 'Too many nonce requests for this session'
      });
    }
    
    session.lastNonceAt = now;
    session.nonceCount = (session.nonceCount || 0) + 1;

    // Mint jti and tokenSig
    const jti = `jti_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const exp = now + NONCE_TTL_MS;
    const payload = `${sid}|${session.playerAddress}|${jti}|${exp}|${session.ipHash}|${session.uaHash}`;
    const tokenSig = hmac(payload);

    nonces.set(jti, { sid, walletAddress: session.playerAddress, exp, used: false, ipHash: session.ipHash, uaHash: session.uaHash, createdAt: now });

console.log(`[${req.requestId}] 🔐 Nonce minted for ${session.playerAddress}: ${jti}`);
return res.json({ success: true, jti, exp, tokenSig, requestId: req.requestId });
  } catch (error) {
    console.error('❌ Nonce endpoint error:', error);
    return res.status(500).json({ error: 'Failed to mint nonce' });
  }
});

// Queue status endpoint
app.get('/api/queue/status', (req, res) => {
  try {
    const status = scoreQueue.getStatus();
    res.json({
      success: true,
      ...status,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Error getting queue status:', error);
    res.status(500).json({
      error: 'Failed to get queue status'
    });
  }
});

// Get specific queue item status
app.get('/api/queue/item/:queueId', (req, res) => {
  try {
    const { queueId } = req.params;

    // Try to find an active queue item first
    const queueItem = scoreQueue.queue.find(item => item.id === queueId);

    if (queueItem) {
      return res.json({
        success: true,
        queueId: queueItem.id,
        status: queueItem.status,
        transactionHash: queueItem.result?.transactionHash,
        timestamp: queueItem.timestamp,
        submittedAt: new Date().toISOString()
      });
    }

    // Check if the item is currently being processed
    if (scoreQueue.currentItem && scoreQueue.currentItem.id === queueId) {
      const current = scoreQueue.currentItem;
      return res.json({
        success: true,
        queueId: current.id,
        status: current.status || 'processing',
        transactionHash: current.result?.transactionHash,
        timestamp: current.timestamp,
        submittedAt: new Date().toISOString()
      });
    }

    // If not in active queue, check completed/failed items retention
    const completed = scoreQueue.completedItems.get(queueId);
    if (completed) {
      return res.json({
        success: true,
        queueId: completed.id,
        status: completed.status,
        transactionHash: completed.transactionHash,
        timestamp: completed.timestamp,
        submittedAt: new Date(completed.timestamp).toISOString()
      });
    }

    return res.status(404).json({
      error: 'Queue item not found'
    });
  } catch (error) {
    console.error('❌ Error getting queue item status:', error);
    res.status(500).json({
      error: 'Failed to get queue item status'
    });
  }
});

// Proxy endpoint for leaderboard API to avoid CORS issues
app.get('/api/proxy/leaderboard', async (req, res) => {
  try {
    const gameId = req.query.gameId || '21';

    if (!process.env.LEADERBOARD_API_URL) {
      return res.status(503).json({
        error: 'Leaderboard proxy not configured',
        message: 'Please set LEADERBOARD_API_URL in environment variables'
      });
    }

    const base = process.env.LEADERBOARD_API_URL.replace(/\/$/, '');
    const apiUrl = `${base}?gameId=${encodeURIComponent(gameId)}`;

    console.log('🔄 Proxying leaderboard request to:', apiUrl);

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'NadRacer-Backend/1.0',
        'Accept': 'application/json'
      },
      redirect: 'follow' // Follow redirects automatically
    });

    if (!response.ok) {
      throw new Error(`Leaderboard API returned ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    console.log('✅ Leaderboard data fetched via proxy:', data.data?.length || 0, 'entries');

    res.json(data);

  } catch (error) {
    console.error('❌ Leaderboard proxy error:', error.message);
    res.status(500).json({
      error: 'Failed to fetch leaderboard data',
      message: error.message
    });
  }
});


// Username API is working fine according to user - no proxy needed

// Submit player score (requires authentication and validation)
// Now uses queue system for reliable processing
app.post('/api/submit-score', verifyPrivyAuth, validateAddress, validateScoreSubmission, async (req, res) => {
  try {
    const { playerAddress, score, sessionId: sid, jti, tokenSig, walletSignature, clientTs, idempotencyKey, proof } = req.body || {};
    const player = (playerAddress || '').toLowerCase();

    // Session checks
    if (!sid) return res.status(400).json({ error: 'Missing sessionId' });
    const session = activeGameSessions.get(sid);
    if (!session) return res.status(400).json({ error: 'Invalid or expired game session' });
    if (session.finalized) return res.status(400).json({ error: 'Session finalized' });
    if (nowMs() > session.exp) {
      activeGameSessions.delete(sid);
      return res.status(400).json({ error: 'Session expired' });
    }
    
    // HIGH PRIORITY FIX #1: Minimum session duration check
    const sessionDuration = nowMs() - session.startTime;
    if (sessionDuration < MIN_SESSION_DURATION_MS) {
      return res.status(400).json({ 
        error: 'Session too short',
        message: `Minimum gameplay duration is ${MIN_SESSION_DURATION_MS / 1000} seconds`,
        required: Math.ceil((MIN_SESSION_DURATION_MS - sessionDuration) / 1000)
      });
    }

    // Context binding
    const ipHash = ipHashOf(req.ip);
    const uaHash = uaHashOf(req.headers['user-agent'] || '');
    if (ipHash !== session.ipHash || uaHash !== session.uaHash) {
      return res.status(403).json({ error: 'Session context mismatch' });
    }

    // Wallet binding
    if (session.playerAddress !== player) {
      return res.status(403).json({ error: 'Session wallet mismatch' });
    }

    // Per-session submit pacing
    const now = nowMs();
    if (now - (session.lastSubmitAt || 0) < MIN_SUBMIT_INTERVAL_MS) {
      return res.status(429).json({ error: 'Too many submissions' });
    }

    // Nonce validation (single use)
    if (!jti || !tokenSig) return res.status(400).json({ error: 'Missing nonce' });
    const nonce = nonces.get(jti);
    if (!nonce) return res.status(400).json({ error: 'Invalid or expired nonce' });
    if (nonce.used) return res.status(401).json({ error: 'Nonce already used' });
    if (nonce.sid !== sid || nonce.walletAddress !== player) return res.status(403).json({ error: 'Nonce/session mismatch' });
    if (now > nonce.exp) {
      nonces.delete(jti);
      return res.status(400).json({ error: 'Nonce expired' });
    }
    if (nonce.ipHash !== session.ipHash || nonce.uaHash !== session.uaHash) {
      return res.status(403).json({ error: 'Nonce context mismatch' });
    }
    // Verify HMAC over canonical payload
    const expected = hmac(`${sid}|${player}|${jti}|${nonce.exp}|${session.ipHash}|${session.uaHash}`);
    if (expected !== tokenSig) return res.status(401).json({ error: 'Invalid nonce signature' });

    // Timestamp sanity for submit message
    const ts = Number(clientTs);
    if (!Number.isFinite(ts) || Math.abs(now - ts) > MAX_CLOCK_SKEW_MS) {
      return res.status(400).json({ error: 'Invalid or skewed timestamp' });
    }

// Bind to authenticated wallet
    if (!isDevelopment && req.auth?.walletAddress !== player) {
      return res.status(403).json({ error: 'Auth wallet mismatch' });
    }

    // Idempotency: simple per-session memory (optional; nonce already ensures single processing)
    const idemKey = String(idempotencyKey || '');
    if (idemKey) {
      if (session.idempotencyKeys.has(idemKey)) {
        return res.status(200).json({ success: true, queued: true, duplicate: true });
      }
      session.idempotencyKeys.set(idemKey, now);
    }

    // Wallet global rate limiting (existing logic retained)
    const walletData = recentSubmissions.get(player) || { lastSubmission: 0, submissionCount: 0 };
    if (now - walletData.lastSubmission > WALLET_RATE_RESET_MS) walletData.submissionCount = 0;
    if (walletData.submissionCount >= WALLET_SUBMISSIONS_PER_HOUR) {
      return res.status(429).json({ error: 'Rate limit exceeded', message: 'Too many score submissions. Please wait before submitting again.' });
    }
    walletData.lastSubmission = now;
    walletData.submissionCount++;
    recentSubmissions.set(player, walletData);

// HIGH PRIORITY FIX #4: Duration-bound max score validation
const sessionDurationMs = nowMs() - session.startTime;
const sessionDurationSec = Math.max(sessionDurationMs / 1000, 1); // at least 1 second
const maxScoreForDuration = Math.floor(sessionDurationSec * MAX_SCORE_PER_SECOND);

if (score > maxScoreForDuration) {
  return res.status(400).json({ 
    error: 'Score exceeds time-based limit',
    message: `Score ${score} is too high for ${sessionDurationSec.toFixed(1)}s gameplay (max: ${maxScoreForDuration})`
  });
}

// Reasonable score check (keep, plus time-normalized soft gate)
if (score > MAX_REASONABLE_SCORE) {
  return res.status(400).json({ error: 'Score validation failed', message: 'Score appears to be invalid' });
}

// Proof-of-play validation (coin events)
if (score > 0) {
  if (!proof || !Array.isArray(proof.timestamps) || typeof proof.digest !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid gameplay proof' });
  }
  const tsArr = proof.timestamps;
  // Basic checks
  if (tsArr.length !== score) {
    return res.status(400).json({ error: 'Proof mismatch: count differs from score' });
  }
  
  // HIGH PRIORITY FIX #2: Minimum time to first coin check
  if (tsArr.length > 0) {
    const firstCoinDelay = tsArr[0] - session.startTime;
    if (firstCoinDelay < MIN_TIME_TO_FIRST_COIN_MS) {
      return res.status(400).json({ 
        error: 'First coin collected too quickly',
        message: `Minimum delay to first coin is ${MIN_TIME_TO_FIRST_COIN_MS / 1000} seconds`
      });
    }
  }
  
  // HIGH PRIORITY FIX #3: Tightened coin timing constraints
  let last = 0;
  for (let i = 0; i < tsArr.length; i++) {
    const t = Number(tsArr[i]);
    if (!Number.isFinite(t)) return res.status(400).json({ error: 'Invalid timestamp in proof' });
    if (i === 0) {
      last = t;
      continue;
    }
    const gap = t - last;
    if (gap < 0) {
      return res.status(400).json({ 
        error: 'Invalid timestamp order',
        message: 'Coin collection timestamps must be in chronological order'
      });
    }
    // Allow identical timestamps (due to client's 100ms rounding) but not negative gaps
    if (gap > 0 && gap < MIN_REALISTIC_COIN_INTERVAL_MS) {
      return res.status(400).json({ 
        error: 'Unrealistic coin collection timing',
        message: `Minimum interval between coins is ${MIN_REALISTIC_COIN_INTERVAL_MS}ms (gap was ${gap}ms)`
      });
    }
    last = t;
  }
  // HIGH PRIORITY FIX #3: Tightened coins per minute cap
  const durationMs = (tsArr[tsArr.length - 1] - tsArr[0]) || 1;
  const perMin = (tsArr.length * 60000) / Math.max(durationMs, 1);
  if (perMin > MAX_REALISTIC_COINS_PER_MIN) {
    return res.status(400).json({ 
      error: 'Unrealistic coin collection rate',
      message: `Rate of ${perMin.toFixed(1)} coins/min exceeds limit of ${MAX_REALISTIC_COINS_PER_MIN}`
    });
  }
  // Session window alignment
  if (tsArr[0] < session.startTime - MAX_CLOCK_SKEW_MS || tsArr[tsArr.length - 1] > now + MAX_CLOCK_SKEW_MS) {
    return res.status(400).json({ error: 'Proof invalid: timestamps out of session bounds' });
  }
  // Canonical digest recomputation: sid|salt|coin|t1,t2,...
  const salt = session.sessionSalt || '';
  const digestInput = `${sid}|${salt}|coin|${tsArr.join(',')}`;
  const expectedDigest = sha256(digestInput);
  if (expectedDigest !== proof.digest) {
    return res.status(400).json({ error: 'Proof invalid: digest mismatch' });
  }
}

    // Queue backpressure
    const threshold = Math.floor(scoreQueue.maxQueueSize * QUEUE_BACKPRESSURE_RATIO);
    if (scoreQueue.queue.length >= threshold) {
      return res.status(503).json({ error: 'Service temporarily unavailable', message: 'Submission queue is busy. Please try again shortly.' });
    }

    // Mark nonce used atomically (before enqueue)
    nonce.used = true;
    nonces.set(jti, nonce);
    session.lastSubmitAt = now;

    // Enqueue submission
try {
      const queueId = `submission_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      console.log(`[${req.requestId}] 🎯 SCORE_SUBMIT received: wallet=${player}, score=${score}, sid=${sid}, jti=${jti}`);
      scoreQueue.addSubmission({ playerAddress: player, score, sessionId: sid, ip: req.ip }, queueId)
        .then((result) => {
          console.log(`[${req.requestId}] 📋 Score processed: ${result.queueId}, TX: ${result.transactionHash}`);
        }).catch((error) => {
          console.error(`[${req.requestId}] ❌ Queue processing error:`, error);
        });

      // Finalize session after successful queueing (single-submit sessions)
      session.finalized = true;
      activeGameSessions.set(sid, session);
      // Purge any outstanding nonces tied to this session to prevent reuse
      for (const [njti, meta] of nonces.entries()) {
        if (meta.sid === sid) nonces.delete(njti);
      }

      return res.json({ success: true, queued: true, queueId, message: 'Score added to submission queue', requestId: req.requestId });
    } catch (queueError) {
      console.error('❌ Failed to queue score submission:', queueError);
      return res.status(500).json({ error: 'Failed to queue score submission', message: queueError.message });
    }
  } catch (error) {
    console.error('Error processing score submission:', error);
    return res.status(500).json({ error: 'Failed to process score submission', details: error.message });
  }
});

// Leaderboard functionality: frontend uses server proxy to Monad API


// Error handling middleware
app.use((error, req, res, next) => {
  const rid = req?.requestId || 'n/a';
  console.error(`[${rid}] Unhandled error:`, error);
  res.status(500).json({
    error: 'Internal server error',
    requestId: rid
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    requestId: req.requestId
  });
});

// Graceful shutdown handler
const gracefulShutdown = () => {
  console.log('🛑 Received shutdown signal, stopping gracefully...');

  // Stop queue processing
  scoreQueue.stopProcessing();

  // Close server
  server.close(() => {
    console.log('✅ Server closed successfully');
    process.exit(0);
  });

  // Force close after 10 seconds
  setTimeout(() => {
    console.error('❌ Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

// Handle shutdown signals
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const server = app.listen(PORT, () => {
  console.log(`🚀 Nad Racer Backend Server running on port ${PORT}`);
  console.log(`📊 Leaderboard Contract: ${LEADERBOARD_CONTRACT}`);
  console.log(`🎮 Game Address: ${GAME_ADDRESS || 'Not set - game not registered yet'}`);
  console.log(`💰 Score Submissions: ${walletClient ? 'Enabled' : 'Disabled (no private key)'}`);
  console.log(`📋 Queue System: ${scoreQueue ? 'Active' : 'Inactive'}`);
  console.log('');
  console.log('🔒 Security Configuration:');
  console.log(`   General Rate Limit: ${RATE_LIMIT_GENERAL_MAX} requests/${RATE_LIMIT_GENERAL_WINDOW_MS/1000}s`);
  console.log(`   Score Rate Limit: ${RATE_LIMIT_SCORE_MAX} submissions/${RATE_LIMIT_SCORE_WINDOW_MS/1000}s`);
  console.log(`   Wallet Rate Limit: ${WALLET_SUBMISSIONS_PER_HOUR} submissions/${WALLET_RATE_RESET_MS/1000/60}min`);
  console.log(`   Max Score: ${MAX_SCORE_LIMIT.toLocaleString()}`);
  console.log(`   Max Reasonable Score: ${MAX_REASONABLE_SCORE.toLocaleString()}`);
  console.log(`   Session Max Age: ${MAX_SESSION_AGE_MS/1000/60}min`);
});
