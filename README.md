# Login Authentication System

## Overview
A complete, modern, and client-side authentication system built using HTML5, CSS3, and Vanilla JavaScript. The application allows users to register accounts with robust password validation and dynamic strength indication, securely stores credentials with SHA-256 hashing via the browser's Web Crypto API, prevents duplicate registrations, authenticates user logins, enforces access control on a protected dashboard, and manages active sessions.

Designed with a clean, modern SaaS aesthetic featuring blue-to-purple gradients, glassmorphism cards, responsive layouts, smooth animations, and zero external framework dependencies.

---

## Features
- **User Registration**: Register new accounts with full field validation.
- **Login Validation**: Verify user credentials against stored records.
- **Password Validation**:
  - Minimum 8 characters
  - At least one numerical digit
  - Password and confirm-password matching
- **SHA-256 Password Hashing**: Utilizes the native browser `crypto.subtle` Web Crypto API to hash passwords before storing. Plaintext passwords are never saved.
- **Dynamic Password Strength Indicator**: Visual real-time strength meter (Weak / Medium / Strong) that updates as the user types.
- **Password Visibility Toggles**: Interactive eye icons to view or hide password inputs.
- **Duplicate Detection**: Prevents registering with an existing username or email address (case-insensitive).
- **Session Management**: Tracks active authentication state using `sessionStorage` (with optional "Remember me" persistence in `localStorage`).
- **Protected Dashboard**: JavaScript route guard verifies session state upon loading `dashboard.html`. Unauthenticated attempts are immediately redirected to `index.html`.
- **User Profile Display**: Dynamically presents the authenticated user's name, email, account creation date, and cryptographic hash verification signature.
- **Logout Functionality**: Completely clears active session identifiers and securely returns to the login page.
- **Responsive Layout**: Adapts cleanly across mobile, tablet, laptop, and desktop screens with custom CSS media queries.
- **Inline User Feedback**: Clear, non-intrusive alert messages for errors and successes without using jarring `alert()` popups.

---

## Technologies
- **HTML5**: Semantic markup, accessible labels, ARIA attributes, and SVG icons.
- **CSS3**: Custom properties (CSS variables), glassmorphism effects, flexbox/grid layout, smooth keyframe transitions, and media queries.
- **Vanilla JavaScript (ES6+)**: Pure client-side logic, async/await, DOM APIs, and event handling without third-party frameworks.
- **Web Crypto API (`crypto.subtle.digest`)**: Asynchronous cryptographic SHA-256 hashing algorithm.
- **Browser `localStorage`**: Client-side persistence for registered user accounts.
- **Browser `sessionStorage`**: Session-scoped storage for tracking currently authenticated users.

---

## Project Structure
```text
.
├── index.html        # Login page (welcome back, credentials form, session redirect)
├── register.html     # Registration page (validation, strength meter, duplicate check)
├── dashboard.html    # Protected dashboard (accessible only after authenticated login)
├── style.css         # Unified responsive styling and glassmorphism design system
├── script.js         # Core authentication logic, cryptographic hashing, and routing
└── README.md         # Comprehensive project documentation and security guide
```

---

## How to Run

### Option 1: Direct File Opening (No Server Required)
Because this application is built with standard HTML5, CSS3, and Vanilla JavaScript without backend or node dependencies:
1. Download or clone the project folder onto your local machine.
2. Double-click `index.html` or right-click and choose **Open with → Google Chrome** (or any modern web browser like Firefox, Edge, or Safari).
3. The application will run immediately!

### Option 2: Live Server or Local Dev Server
You can also preview the project using any static web server:
- **VS Code Live Server**: Right-click `index.html` and select **Open with Live Server**.
- **Python**: Run `python3 -m http.server 3000` in the project directory and visit `http://localhost:3000`.
- **Node.js / Vite**: Run `npm run dev` to start Vite on port `3000`.

---

## Authentication Flow

```text
[ Registration (register.html) ]
              │
              ▼
   Form Input & Validation
   (Non-empty, Email format, 8+ chars, Number check, Match check)
              │
              ▼
   Duplicate Account Check
   (Ensures username and email are unique in localStorage)
              │
              ▼
   Web Crypto SHA-256 Hashing
   crypto.subtle.digest("SHA-256", password) → Hex String
              │
              ▼
   Store User Record in localStorage
   { id, username, email, passwordHash, createdAt }
              │
              ▼
       [ Redirect to Login ]
              │
              ▼
[ Login Verification (index.html) ]
              │
              ▼
   Look up User by Username or Email
              │
              ▼
   Compute SHA-256 Hash of Entered Password
              │
              ▼
   Compare Generated Hash with Stored Hash
   ┌──────────┴──────────┐
   │ Match               │ Mismatch
   ▼                     ▼
Create Session        Show Generic Error:
sessionStorage        "Invalid username/email or password."
   │
   ▼
[ Protected Dashboard (dashboard.html) ]
   - Verify active session exists (if not, redirect to index.html)
   - Display username, email, registration date, and status
              │
              ▼
[ Logout ]
   - Clear sessionStorage & remembered user
   - Redirect to index.html
```

---

## Security Note & Production Guidance

> **Important Educational Disclaimer**:
> This project is designed as an educational, client-side authentication demonstration for an internship assignment. Client-side authentication using `localStorage` and `sessionStorage` is suitable **strictly for demonstration and learning purposes**. It is **NOT** suitable for production systems.

### Key differences for Production Systems:
1. **Server-Side Verification**: Real authentication must be verified and enforced on an authoritative backend server. Client-side storage (`localStorage`) can be read and inspected by scripts executing in the browser or via browser Developer Tools.
2. **Password Hashing Algorithms**: Fast cryptographic hash functions like basic SHA-256 are susceptible to high-speed brute force and GPU rainbow table attacks when used without salts. Production authentication should always employ slow, salted password-hashing algorithms designed specifically for credential security, such as:
   - **Argon2** (Argon2id recommended by OWASP)
   - **bcrypt** (with an appropriate work factor)
   - **scrypt**
   - **PBKDF2**
3. **Transport Security (HTTPS)**: All communications must be encrypted in transit using TLS/HTTPS to prevent interception.
4. **Session Tokens**: Production sessions should use cryptographically signed JSON Web Tokens (JWT) or server-stored session IDs delivered via `HttpOnly`, `Secure`, and `SameSite` cookies to mitigate Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF).
