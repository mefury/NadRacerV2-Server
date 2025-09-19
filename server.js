import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createPublicClient, createWalletClient, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { monadTestnet } from './chains.js';

// Load environment variables
dotenv.config();

// Validate required environment variables
const requiredEnvVars = [
  'PRIVATE_KEY',
  'PRIVY_APP_ID',
  'MONAD_APP_ID',
  'GAME_ADDRESS',
  'API_KEY'
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

// Per-Wallet Rate Limiting
const WALLET_SUBMISSIONS_PER_HOUR = parseInt(process.env.WALLET_SUBMISSIONS_PER_HOUR) || 20;
const WALLET_RATE_RESET_MS = parseInt(process.env.WALLET_RATE_RESET_MS) || 60 * 60 * 1000; // 1 hour

// Session Management
const MAX_SESSION_AGE_MS = parseInt(process.env.MAX_SESSION_AGE_MS) || 30 * 60 * 1000; // 30 minutes
const SESSION_CLEANUP_AGE_MS = parseInt(process.env.SESSION_CLEANUP_AGE_MS) || 60 * 60 * 1000; // 1 hour

// Game session management for anti-cheat
const activeGameSessions = new Map(); // sessionId -> { walletAddress, startTime, gameState }
const recentSubmissions = new Map(); // walletAddress -> { lastSubmission, submissionCount }

// Queue system for score submissions
class ScoreSubmissionQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
    this.maxRetries = 3;
    this.processingInterval = 500; // Process every 0.5 seconds for faster testing
    this.maxQueueSize = 100; // Maximum queue size
    this.processingTimer = null;
  }

  // Add score submission to queue
  async addSubmission(submission) {
    return new Promise((resolve, reject) => {
      if (this.queue.length >= this.maxQueueSize) {
        reject(new Error('Queue is full. Please try again later.'));
        return;
      }

      const queueItem = {
        id: `submission_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
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
    if (this.queue.length === 0) {
      console.log('📋 Queue empty, stopping processing');
      this.stopProcessing();
      return;
    }

    const item = this.queue.shift();
    console.log(`⚙️ Processing queue item: ${item.id}`);

    try {
      const submissionResult = await this.processSubmission(item);
      item.status = 'completed';
      item.result = submissionResult; // Store the result for access
      console.log(`✅ Queue item ${item.id} completed with TX hash:`, submissionResult?.transactionHash);
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
        item.reject(new Error(`Failed to submit score after ${this.maxRetries} attempts: ${error.message}`));
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
  }
}

// Initialize queue system
const scoreQueue = new ScoreSubmissionQueue();

// Clean up queue every 5 minutes
setInterval(() => {
  scoreQueue.cleanup();
}, 300000);

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingVars);
  console.error('Please check your .env file and ensure all required variables are set');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

// Secure CORS configuration
const allowedOrigins = [
  'http://localhost:5173',  // Vite dev server
  'https://localhost:5173', // Vite dev server (HTTPS)
  'http://localhost:4173',  // Vite preview server
  'https://localhost:4173', // Vite preview server (HTTPS)
  process.env.FRONTEND_URL  // Production URL
].filter(Boolean); // Remove any undefined values

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`🚫 CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-monad-app-id', 'x-api-key']
}));

// Enhanced security headers - relaxed for development
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // For potential CSS
      scriptSrc: ["'self'", "'unsafe-inline'", "https://auth.privy.io", "https://*.privy.io"], // Allow Privy domains only
      scriptSrcElem: ["'self'", "'unsafe-inline'", "https://auth.privy.io", "https://*.privy.io"], // Block GTM explicitly
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://testnet-rpc.monad.xyz", "https://api.allorigins.win", "https://www.monadclip.fun", "https://*.privy.io"],
      // Explicitly block GTM domains
      scriptSrcAttr: ["'none'"]
    }
  },
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

// Rate limiting
const limiter = rateLimit({
  windowMs: RATE_LIMIT_GENERAL_WINDOW_MS,
  max: RATE_LIMIT_GENERAL_MAX,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Stricter rate limiting for score submissions
const scoreLimiter = rateLimit({
  windowMs: RATE_LIMIT_SCORE_WINDOW_MS,
  max: RATE_LIMIT_SCORE_MAX,
  message: 'Too many score submissions, please try again later.'
});
app.use('/api/submit-score', scoreLimiter);

// Contract configuration
const LEADERBOARD_CONTRACT = '0xceCBFF203C8B6044F52CE23D914A1bfD997541A4';
const GAME_ADDRESS = process.env.GAME_ADDRESS; // Will be set after game registration

// API Configuration from environment
const MONAD_APP_ID = process.env.MONAD_APP_ID || 'cmd8euall0037le0my79qpz42';
const MONAD_USERNAME_API = process.env.MONAD_USERNAME_API || 'https://www.monadclip.fun';

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
    transport: http('https://testnet-rpc.monad.xyz')
  });

  // Wallet client for writing data (requires private key)
  if (process.env.PRIVATE_KEY) {
    const account = privateKeyToAccount(process.env.PRIVATE_KEY);
    walletClient = createWalletClient({
      account,
      chain: monadTestnet,
      transport: http('https://testnet-rpc.monad.xyz')
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

// Known players tracking removed - not needed since leaderboard is handled by frontend

// Simple API Key Authentication Middleware (Hobby Project)
const authenticateApiKey = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];

    // Check for API key in header or authorization
    let providedKey = apiKey;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      // Support both API key and token formats
      providedKey = authHeader.substring(7);
    }

    if (!providedKey) {
      console.log('❌ No API key provided');
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Missing API key'
      });
    }

    // Validate API key
    if (providedKey !== process.env.API_KEY) {
      console.log('❌ Invalid API key provided');
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid API key'
      });
    }

    // DEVELOPMENT MODE: Create mock user for testing
    if (isDevelopment) {
      console.log('⚠️ DEVELOPMENT MODE: Using mock user authentication');

      req.user = {
        id: 'dev-user-123',
        email: 'dev@example.com',
        monadWalletAddress: null, // Will be validated from request body
        linkedAccounts: [],
        isDevelopment: true
      };

      console.log('✅ [DEV AUTH] Development authentication successful');
      return next();
    }

    // PRODUCTION MODE: Basic authentication successful
    console.log('✅ [AUTH] API key authentication successful');

    // For production, we'll validate wallet from request body
    // This provides basic protection while keeping it simple
    req.user = {
      id: 'authenticated-user',
      email: 'user@example.com',
      monadWalletAddress: null, // Will be set from request validation
      linkedAccounts: [],
      isAuthenticated: true
    };

    next();

  } catch (error) {
    console.error('❌ Authentication error:', error.message);
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Authentication error'
    });
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
app.post('/api/start-game', authenticateApiKey, (req, res) => {
  try {
    const { playerAddress } = req.body;

    if (!playerAddress || !/^0x[a-fA-F0-9]{40}$/.test(playerAddress)) {
      return res.status(400).json({
        error: 'Invalid player address format'
      });
    }

    // Generate session token
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const sessionData = {
      playerAddress: playerAddress.toLowerCase(),
      startTime: Date.now(),
      gameState: 'active',
      ip: req.ip
    };

    // Store session
    activeGameSessions.set(sessionId, sessionData);

    // Clean up old sessions
    for (const [id, session] of activeGameSessions.entries()) {
      if (Date.now() - session.startTime > SESSION_CLEANUP_AGE_MS) {
        activeGameSessions.delete(id);
      }
    }

    console.log(`🎮 Game session started: ${sessionId} for ${playerAddress}`);

    res.json({
      success: true,
      sessionId,
      message: 'Game session started'
    });

  } catch (error) {
    console.error('❌ Error starting game session:', error);
    res.status(500).json({
      error: 'Failed to start game session'
    });
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

    // Find the queue item
    const queueItem = scoreQueue.queue.find(item => item.id === queueId);

    if (!queueItem) {
      return res.status(404).json({
        error: 'Queue item not found'
      });
    }

    res.json({
      success: true,
      queueId: queueItem.id,
      status: queueItem.status,
      transactionHash: queueItem.result?.transactionHash,
      timestamp: queueItem.timestamp,
      submittedAt: new Date().toISOString()
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
    const apiUrl = `https://www.monadclip.fun/api/leaderboard?gameId=${gameId}`;

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
app.post('/api/submit-score', authenticateApiKey, validateAddress, validateScoreSubmission, async (req, res) => {
  try {
    const { playerAddress, score, sessionId } = req.body;
    const authenticatedUser = req.user;

    // ANTI-CHEAT: Validate session token
    if (!sessionId) {
      console.log('🚫 Missing session token');
      return res.status(400).json({
        error: 'Session validation failed',
        message: 'Missing game session token'
      });
    }

    const session = activeGameSessions.get(sessionId);
    if (!session) {
      console.log(`🚫 Invalid session token: ${sessionId}`);
      return res.status(400).json({
        error: 'Session validation failed',
        message: 'Invalid or expired game session'
      });
    }

    // ANTI-CHEAT: Validate session belongs to player
    if (session.playerAddress !== playerAddress.toLowerCase()) {
      console.log(`🚫 Session wallet mismatch: ${session.playerAddress} vs ${playerAddress}`);
      return res.status(403).json({
        error: 'Session validation failed',
        message: 'Session does not match player address'
      });
    }

    // ANTI-CHEAT: Check session age
    const sessionAge = Date.now() - session.startTime;
    if (sessionAge > MAX_SESSION_AGE_MS) {
      activeGameSessions.delete(sessionId);
      console.log(`😫 Session expired: ${sessionId}`);
      return res.status(400).json({
        error: 'Session validation failed',
        message: 'Game session has expired'
      });
    }

    // ANTI-CHEAT: Rate limiting per wallet
    const walletKey = playerAddress.toLowerCase();
    const now = Date.now();
    const walletData = recentSubmissions.get(walletKey) || { lastSubmission: 0, submissionCount: 0 };

    // Reset counter based on configured time window
    if (now - walletData.lastSubmission > WALLET_RATE_RESET_MS) {
      walletData.submissionCount = 0;
    }

    // Check wallet submission rate limit
    if (walletData.submissionCount >= WALLET_SUBMISSIONS_PER_HOUR) {
      console.log(`🚫 Rate limit exceeded for wallet: ${walletKey}`);
      return res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many score submissions. Please wait before submitting again.'
      });
    }

    // Update submission tracking
    walletData.lastSubmission = now;
    walletData.submissionCount++;
    recentSubmissions.set(walletKey, walletData);

    // ANTI-CHEAT: Validate score is reasonable (not suspiciously high)
    if (score > MAX_REASONABLE_SCORE) {
      console.log(`😫 Suspiciously high score: ${score} from ${playerAddress}`);
      return res.status(400).json({
        error: 'Score validation failed',
        message: 'Score appears to be invalid'
      });
    }

    // CRITICAL SECURITY CHECK: Verify the wallet address matches authenticated user
    if (!isDevelopment && playerAddress.toLowerCase() !== authenticatedUser.monadWalletAddress) {
      console.log(`🚫 WALLET MISMATCH: Request wallet ${playerAddress}, Auth wallet ${authenticatedUser.monadWalletAddress}`);
      return res.status(403).json({
        error: 'Wallet address mismatch',
        message: 'The provided wallet address does not match the authenticated user'
      });
    }

    // DEVELOPMENT MODE: Set wallet address from request for testing
    if (isDevelopment && !authenticatedUser.monadWalletAddress) {
      authenticatedUser.monadWalletAddress = playerAddress.toLowerCase();
      console.log(`⚠️ DEVELOPMENT MODE: Using wallet from request: ${playerAddress}`);
    }

    console.log(`✅ Wallet verification passed for user ${authenticatedUser.id}`);
    console.log(`🎯 [SCORE_SUBMIT] User: ${authenticatedUser.id}, Wallet: ${playerAddress}, Score: ${score}, IP: ${req.ip}`);

    console.log('🎯 ===== SCORE SUBMISSION RECEIVED =====');
    console.log('🎯 Player Address:', playerAddress);
    console.log('🎯 Score:', score);
    console.log('🎯 Request Body:', req.body);
    console.log('🎯 Request Headers:', req.headers);

    // Add to queue instead of processing immediately
    try {
      console.log(`📋 Adding score submission to queue: ${playerAddress}, Score: ${score}`);

      // Start processing but don't wait for completion - respond immediately
      scoreQueue.addSubmission({
        playerAddress,
        score,
        sessionId,
        authenticatedUser: authenticatedUser.id,
        ip: req.ip
      }).then((result) => {
        console.log(`📋 Score processed successfully: ${result.queueId}, TX: ${result.transactionHash}`);
      }).catch((error) => {
        console.error('❌ Queue processing error:', error);
      });

      console.log(`📋 Score queued successfully, Queue size: ${scoreQueue.queue.length}`);

      res.json({
        success: true,
        queued: true,
        queueId: `submission_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        message: 'Score added to submission queue',
        estimatedWaitTime: scoreQueue.queue.length * 2, // Rough estimate in seconds
        queuePosition: scoreQueue.queue.length
      });

    } catch (queueError) {
      console.error('❌ Failed to queue score submission:', queueError.message);
      console.error('❌ Queue error details:', queueError);

      if (queueError.message.includes('Queue is full')) {
        return res.status(503).json({
          error: 'Service temporarily unavailable',
          message: 'Submission queue is full. Please try again later.'
        });
      }

      return res.status(500).json({
        error: 'Failed to queue score submission',
        message: queueError.message
      });
    }

  } catch (error) {
    console.error('Error processing score submission:', error);

    res.status(500).json({
      error: 'Failed to process score submission',
      details: error.message
    });
  }
});

// Leaderboard functionality removed - handled by frontend using Monad API directly


// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found'
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
