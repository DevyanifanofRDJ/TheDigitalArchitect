Build With Decency | Devyani Tyagi
The Digital Architect's Portfolio A Full Stack Portfolio featuring a secure, interactive, and futuristic "Dark Mode" interface.

🚀 Live Demo
https://the-decent-engineer.onrender.com

⚠️ Deployment Limitation: Email Services
Note regarding the Sign-Up Flow: While the email verification and OTP flow function perfectly in the local development environment, email delivery is currently restricted in the live deployment.

Reason: Production-grade email delivery requires a verified/owned domain to establish trust (DKIM/SPF records). Since this project relies on free hosting and does not currently utilize a custom verified domain, outgoing verification emails are blocked by providers (like Gmail/Resend) to strictly prevent spam and abuse.

✨ Key Features
🔐 Security & Authentication
Hybrid Auth Flow: Supports both Traditional Email/Password and Google OAuth 2.0.

Stateless Architecture: Uses cookie-session for secure OAuth handshakes without server-side memory storage, followed by JWT issuance.

Secure Auth Flow: JWT-based login with HTTP-Only cookies.

OTP Verification: Two-step verification during signup using Nodemailer (Email) and Redis (TTL caching).

Password Recovery: Secure "Forgot Password" flow with token generation and Redis Blacklisting to prevent replay attacks.

Role-Based Access Control (RBAC): Distinction between standard User and Admin roles.

🛡️ Advanced Defense Patterns
No-Cache Headers: Prevents sensitive pages from being viewed via the browser "Back" button after logout.

Rate Limiting: Protects against brute-force attacks on Login, Signup, OTP, and Message endpoints.

Input Sanitization: Uses mongo-sanitize to prevent NoSQL Injection attacks.

Nuclear Logout: Implements the Clear-Site-Data header to wipe client-side storage instantly.

🎨 Futuristic UI/UX
Interactive Visuals: Custom particle physics simulation using Three.js.

Glassmorphism: Modern, translucent UI elements with neon cyan accents.

Optimized Assets: Uses inline SVGs for logos and icons to ensure zero network blocking and instant loading.

Admin Dashboard: A protected interface for the site owner to view and manage incoming messages.

🛠️ Tech Stack
Frontend: HTML5, CSS3, JavaScript, Three.js.

Templating: EJS (Embedded JavaScript).

Backend: Node.js, Express.js.

Authentication: Passport.js (Google Strategy), JWT, Bcrypt.

Database: MongoDB Atlas (Mongoose).

Caching/Session: Redis, Cookie-Session.

Security Tools: Dotenv, Express-Rate-Limit, Mongo-Sanitize.

⚙️ Local Setup
Clone the repo

Bash

git clone https://github.com/YOUR_USERNAME/TheDigitalArchitect.git
cd TheDigitalArchitect
Install dependencies

Bash

npm install
Configure Environment Create a .env file in the root directory. You will need credentials from MongoDB, Redis, Google Cloud Console, and Gmail.

Code snippet

# Database
MONGO_URL=mongodb+srv://<your_connection_string>

# Security
SECRET_KEY=<your_super_long_random_string>

# Email Configuration (Nodemailer)
EMAIL=your_email@gmail.com
EMAIL_PASS=your_gmail_app_password

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=  # Leave empty if using local default

# Google OAuth 2.0
GOOGLE_CLIENT_ID=<your_google_client_id>
GOOGLE_CLIENT_SECRET=<your_google_client_secret>
CALLBACK_URL=http://localhost:5000/auth/google/callback

# App Config
PORT=5000
NODE_ENV=development
BASE_URL=http://localhost:5000
Run the server

Bash

# Run in production mode
npm start

# Run in development mode (with Nodemon)
npm run dev
👤 Admin Setup
By default, all new users are standard users. To access the Admin Dashboard:

Sign up normally on the website (or via Google Login).

Manually update your user document in MongoDB: set role to "admin".

Log out and log back in to access the /viewMessage route.

📬 Contact
Email: devyani0096@gmail.com

LinkedIn: Devyani Tyagi

Built with code, secured with logic.