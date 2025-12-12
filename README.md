# Build With Decency | Devyani Tyagi

**The Digital Architect's Portfolio**
A Full Stack Portfolio featuring a secure, interactive, and futuristic "Dark Mode" interface.

## 🚀 Live Demo
[Insert your deployed link here later]

## ✨ Key Features

### 🔐 Security & Authentication
* **Secure Auth Flow:** JWT-based login with HTTP-Only cookies.
* **OTP Verification:** Two-step verification during signup using Nodemailer (Email) and Redis (TTL caching).
* **Password Recovery:** Secure "Forgot Password" flow with token generation and **Redis Blacklisting** to prevent replay attacks.
* **Role-Based Access Control (RBAC):** Distinction between standard `User` and `Admin` roles.

### 🛡️ Advanced Defense Patterns
* **No-Cache Headers:** Prevents sensitive pages from being viewed via the browser "Back" button after logout.
* **Rate Limiting:** Protects against brute-force attacks on Login, Signup, and Message endpoints.
* **Input Sanitization:** Uses `mongo-sanitize` to prevent NoSQL Injection attacks.
* **Nuclear Logout:** Implements the `Clear-Site-Data` header to wipe client-side storage instantly.

### 🎨 Futuristic UI/UX
* **Interactive Visuals:** Custom particle physics simulation using **Three.js**.
* **Glassmorphism:** Modern, translucent UI elements with neon cyan accents.
* **Admin Dashboard:** A protected interface for the site owner to view and manage incoming messages.

## 🛠️ Tech Stack
* **Frontend:** HTML5, CSS3, JavaScript, Three.js.
* **Templating:** EJS (Embedded JavaScript).
* **Backend:** Node.js, Express.js.
* **Database:** MongoDB Atlas (Mongoose).
* **Caching/Session:** Redis.
* **Security Tools:** Bcrypt, JWT, Dotenv, Express-Rate-Limit.

## ⚙️ Local Setup

1.  **Clone the repo**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/devyani-portfolio.git](https://github.com/YOUR_USERNAME/devyani-portfolio.git)
    cd devyani-portfolio
    ```

2.  **Install dependencies**
    ```bash
    npm install
    ```

3.  **Configure Environment**
    Create a `.env` file in the root directory. You will need a MongoDB Atlas URI, a Redis instance (local or cloud), and Gmail App Password.
    
    ```env
    MONGO_URL=mongodb+srv://<your_connection_string>
    SECRET_KEY=<your_super_long_random_string>
    
    # Email Configuration (Nodemailer)
    EMAIL=your_email@gmail.com
    EMAIL_PASS=your_gmail_app_password
    
    # Redis Configuration
    REDIS_HOST=localhost
    REDIS_PORT=6379
    REDIS_PASSWORD=  # Leave empty if using local default
    
    PORT=5000
    ```

4.  **Run the server**
    ```bash
    # Run in production mode
    npm start
    
    # Run in development mode (with Nodemon)
    npm run dev
    ```

## 👤 Admin Setup
By default, all new users are standard users. To access the **Admin Dashboard**:
1.  Sign up normally on the website.
2.  Manually update your user document in MongoDB: set `role` to `"admin"`.
3.  Log out and log back in to access the `/viewMessage` route.

## 📬 Contact
* **Email:** devyani0096@gmail.com
* **LinkedIn:** [Devyani Tyagi](https://linkedin.com/in/devyani-tyagi-713591257)

---
*Built with code, secured with logic.*