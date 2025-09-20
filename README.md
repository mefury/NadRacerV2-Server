# NadRacer Server 🚀

The backend server for NadRacer - a 3D space racing game with blockchain integration and secure leaderboard system.

## 🎮 Features

- **Blockchain Integration**: Secure score submission using Monad blockchain via Viem
- **Web3 Authentication**: Privy-powered wallet authentication and verification
- **Advanced Anti-Cheat**: Multi-layered validation system with rate limiting
- **RESTful API**: Clean, documented endpoints for seamless game integration
- **Security-First**: Helmet security middleware, CORS protection, and input validation
- **Rate Limiting**: Comprehensive protection against spam, abuse, and cheating attempts
- **Session Management**: Secure game session tracking and validation

## 🛠️ Tech Stack

- **Node.js 18+** - Runtime environment
- **Express.js** - Web application framework
- **Viem** - Ethereum library for blockchain interactions
- **Helmet** - Security middleware collection
- **CORS** - Cross-origin resource sharing
- **Express Rate Limit** - API rate limiting and protection
- **dotenv** - Environment variable management

## 🚀 Quick Start

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- A Monad wallet with game admin privileges

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/mefury/NadRacerV2-Server.git
   cd NadRacerV2-Server
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   ```bash
   cp .env.example .env
   # Edit .env with your actual configuration values
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Test the server**
   - Health check: http://localhost:3001/health
   - API documentation: Check endpoints section below

## 📝 Scripts

```bash
npm run dev     # Start development server with nodemon
npm start       # Start production server
npm test        # Run tests (placeholder)
```

## 🔧 Environment Variables

Copy `.env.example` to `.env` and configure the following:

### Core Configuration
```env
PORT=3001                    # Server port
NODE_ENV=development         # Environment mode
FRONTEND_URL=http://localhost:5173  # Primary client URL for CORS
API_KEY=your_api_key_here    # Client authentication

# CORS Configuration
CORS_ALLOWED_ORIGINS=https://your-app.dokploy.com,https://your-domain.com
```

### Blockchain & Web3
```env
PRIVY_APP_ID=your_privy_app_id
PRIVY_SECRET_KEY=your_privy_secret_key
PRIVATE_KEY=your_wallet_private_key
GAME_ADDRESS=0x...           # Smart contract address
MONAD_RPC_URL=https://testnet-rpc.monad.xyz  # RPC endpoint
```

### Rate Limiting & Anti-Cheat
```env
RATE_LIMIT_GENERAL_WINDOW_MS=900000
RATE_LIMIT_GENERAL_MAX=100
MAX_REASONABLE_SCORE=10000
# See .env.example for complete configuration
```

## 🌐 External APIs

Optionally configure external API endpoints via env:
```env
# Leaderboard API base URL (no trailing slash needed in code)
LEADERBOARD_API_URL=https://www.monadclip.fun/api/leaderboard
```

## 📚 API Endpoints

### Health Check
```http
GET /health
Response: { status: "ok", timestamp: "..." }
```

### Leaderboard
```http
GET /api/leaderboard?limit=10&offset=0
Response: { success: true, data: [...], total: 100 }
```

### Score Submission
```http
POST /api/submit-score
Headers: 
  x-api-key: your_api_key
  x-privy-token: user_privy_token
Body: {
  score: 1000,
  walletAddress: "0x...",
  transactions: 50,
  username: "player1"
}
```

### User Stats
```http
GET /api/user/:walletAddress
Response: { success: true, data: { ... } }
```

## 🔒 Security Features

- **Multi-layer Rate Limiting**: Per-IP and per-wallet limits
- **Score Validation**: Advanced anti-cheat algorithms
- **Session Management**: Secure game session tracking
- **Input Sanitization**: All inputs validated and sanitized
- **Flexible CORS Protection**: Environment-configurable allowed origins
- **Security Headers**: Helmet middleware for enhanced security

### CORS & CSP Configuration

The server supports flexible CORS configuration through environment variables:

- `FRONTEND_URL`: Primary client URL (e.g., production domain)
- `CORS_ALLOWED_ORIGINS`: Additional allowed origins (comma-separated)
- Cookies are not used and CORS credentials are disabled. If both variables are left empty,
  the server will allow any origin. This is acceptable because authentication uses API keys
  (headers), not cookies.

Examples:
```env
# Strict (recommended for prod):
FRONTEND_URL=https://game.example.com
CORS_ALLOWED_ORIGINS=https://preview.example.com

# Permissive (ok when no cookies):
FRONTEND_URL=
CORS_ALLOWED_ORIGINS=
```

### CSP via Environment Variables

Provide comma-separated values (include quotes for tokens like 'self'):
```env
CSP_DEFAULT_SRC='self'
CSP_STYLE_SRC='self','unsafe-inline'
CSP_SCRIPT_SRC='self','unsafe-inline'
CSP_SCRIPT_SRC_ELEM='self','unsafe-inline'
CSP_IMG_SRC='self',data:,https:
CSP_CONNECT_SRC='self'
```

**Default allowed origins:**
- `http://localhost:5173` (Vite dev server)
- `https://localhost:5173` (Vite dev server HTTPS)
- `http://localhost:4173` (Vite preview server)
- `https://localhost:4173` (Vite preview server HTTPS)

## 📊 Anti-Cheat System

- Score range validation
- Transaction count verification  
- Rate limiting per wallet and IP
- Session duration tracking
- Suspicious activity logging
- Configurable thresholds via environment variables

## 🚢 Deployment

### Recommended Platforms
- **Railway**: Connect GitHub repo for auto-deployment
- **Render**: Easy Node.js hosting with environment variables
- **Heroku**: Classic platform with add-on ecosystem
- **DigitalOcean App Platform**: Scalable container deployment
- **AWS/GCP/Azure**: Enterprise-grade cloud deployment

### Deployment Checklist
- ✅ Set all environment variables
- ✅ Configure production URLs (FRONTEND_URL, etc.)
- ✅ Set NODE_ENV=production
- ✅ Ensure wallet has proper blockchain permissions
- ✅ Configure domain/SSL if using custom domain

## 🧪 Development

### Local Development
1. Ensure you have a test wallet with Monad testnet funds
2. Configure `.env` with development values
3. Run `npm run dev` for hot-reload development
4. Use tools like Postman or curl to test API endpoints

### Adding New Features
1. Follow Express.js best practices
2. Add appropriate rate limiting to new endpoints
3. Implement proper error handling
4. Update API documentation

## 📄 Documentation

For detailed rate limiting and anti-cheat configuration, see:
- `RATE_LIMITING.md` - Comprehensive rate limiting guide
- `.env.example` - All environment variables explained

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under UNLICENSED.

## 👨‍💻 Author

**MEFURY**

---

**Happy Racing! 🏁**