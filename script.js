/**
 * Login Authentication System
 * Core Authentication & Application Logic (Vanilla JavaScript)
 * 
 * Demonstrates client-side authentication using Web Crypto API (SHA-256),
 * localStorage persistence, and sessionStorage session handling.
 */

// Storage Keys
const STORAGE_KEYS = {
  USERS: "registeredUsers",
  SESSION: "loggedInUser",
  REMEMBER: "rememberedUser",
  LAST_IDENTIFIER: "lastEnteredIdentifier"
};

/* ==========================================================================
   Security & Password Hashing (Web Crypto API SHA-256)
   ========================================================================== */

/**
 * Hashes a plaintext password string using SHA-256 via the browser Web Crypto API.
 * Converts the resulting binary ArrayBuffer into a safe hexadecimal string.
 * Passwords are NEVER stored or transmitted in plain text.
 * 
 * @param {string} password - The plaintext password to hash
 * @returns {Promise<string>} Hexadecimal SHA-256 hash representation
 */
async function hashPassword(password) {
  if (typeof password !== "string") {
    throw new Error("Invalid password input for hashing.");
  }
  
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  
  // Convert ArrayBuffer to hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hexString = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return hexString;
}

/* ==========================================================================
   User Storage & Persistence (localStorage)
   ========================================================================== */

/**
 * Retrieves the list of registered users from localStorage.
 * Handles parsing errors and returns an empty array on failure.
 * 
 * @returns {Array<Object>} List of user records
 */
function getUsers() {
  try {
    const rawData = localStorage.getItem(STORAGE_KEYS.USERS);
    if (!rawData) return [];
    const parsed = JSON.parse(rawData);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error("Error reading users from localStorage:", error);
    return [];
  }
}

/**
 * Persists the list of registered users to localStorage.
 * 
 * @param {Array<Object>} users - Array of user objects to store
 */
function saveUsers(users) {
  try {
    localStorage.setItem(STORAGE_KEYS.USERS, JSON.stringify(users));
  } catch (error) {
    console.error("Error saving users to localStorage:", error);
  }
}

/* ==========================================================================
   Validation Logic
   ========================================================================== */

/**
 * Validates registration fields against requirements:
 * - Username: required, at least 3 characters
 * - Email: required, valid email format
 * - Password: required, at least 8 characters, at least 1 number
 * - Confirm Password: required, must match password
 * 
 * @param {string} username 
 * @param {string} email 
 * @param {string} password 
 * @param {string} confirmPassword 
 * @returns {Object} { isValid: boolean, errors: Object }
 */
function validateRegistration(username, email, password, confirmPassword) {
  const errors = {};
  
  // Username validation
  const cleanUsername = username ? username.trim() : "";
  if (!cleanUsername) {
    errors.username = "Please enter a username.";
  } else if (cleanUsername.length < 3) {
    errors.username = "Username must be at least 3 characters.";
  } else if (!/^[a-zA-Z0-9_-]+$/.test(cleanUsername)) {
    errors.username = "Username can only contain letters, numbers, hyphens, and underscores.";
  }

  // Email validation
  const cleanEmail = email ? email.trim() : "";
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!cleanEmail) {
    errors.email = "Please enter a valid email address.";
  } else if (!emailRegex.test(cleanEmail)) {
    errors.email = "Please enter a valid email address.";
  }

  // Password validation
  if (!password) {
    errors.password = "Password must contain at least 8 characters.";
  } else if (password.length < 8) {
    errors.password = "Password must contain at least 8 characters.";
  } else if (!/\d/.test(password)) {
    errors.password = "Password must contain at least one number.";
  }

  // Confirm password validation
  if (!confirmPassword) {
    errors.confirmPassword = "Passwords do not match.";
  } else if (password !== confirmPassword) {
    errors.confirmPassword = "Passwords do not match.";
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors: errors
  };
}

/**
 * Evaluates password strength and updates UI meter dynamically.
 * Rules:
 * - Less than 8 characters -> Weak
 * - 8+ characters with limited complexity -> Medium
 * - 8+ characters with numbers AND variety (uppercase, lowercase, or symbol) -> Strong
 * 
 * @param {string} password 
 */
function updatePasswordStrength(password) {
  const container = document.getElementById("password-strength-container");
  const valueEl = document.getElementById("password-strength-value");
  if (!container || !valueEl) return;

  if (!password) {
    container.className = "strength-container";
    valueEl.textContent = "None";
    return;
  }

  let strength = "weak";
  const len = password.length;
  const hasNumber = /\d/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  const varietyCount = [hasNumber, hasLower, hasUpper, hasSpecial].filter(Boolean).length;

  if (len < 8) {
    strength = "weak";
  } else if (varietyCount >= 3 || (hasNumber && hasSpecial && len >= 8)) {
    strength = "strong";
  } else {
    strength = "medium";
  }

  container.className = `strength-container strength-${strength}`;
  valueEl.textContent = strength.charAt(0).toUpperCase() + strength.slice(1);
}

/* ==========================================================================
   UI Helpers & Feedback
   ========================================================================== */

/**
 * Displays an accessible, smooth inline message (success or error).
 * Safe DOM manipulation using textContent to prevent XSS.
 * 
 * @param {string} elementId - ID of alert box element
 * @param {string} text - Message text
 * @param {string} type - "error" | "success"
 * @param {boolean} autoDismiss - Whether to dismiss after 4s
 */
function showMessage(elementId, text, type = "error", autoDismiss = false) {
  const alertBox = document.getElementById(elementId);
  if (!alertBox) return;

  // Clear existing classes
  alertBox.className = `alert-box alert-${type} visible`;
  
  // Set icon and message text safely
  const textSpan = alertBox.querySelector(".alert-message-text");
  if (textSpan) {
    textSpan.textContent = text;
  } else {
    alertBox.textContent = text;
  }

  if (autoDismiss) {
    setTimeout(() => {
      alertBox.classList.remove("visible");
    }, 4500);
  }
}

/**
 * Hides an alert box.
 * 
 * @param {string} elementId 
 */
function hideMessage(elementId) {
  const alertBox = document.getElementById(elementId);
  if (alertBox) {
    alertBox.classList.remove("visible");
  }
}

/**
 * Displays field-level inline validation errors safely.
 * 
 * @param {string} fieldId - ID of input element
 * @param {string|null} errorMessage - Error text or null to clear
 */
function setFieldError(fieldId, errorMessage) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  
  const group = field.closest(".form-group");
  if (!group) return;

  const errorEl = group.querySelector(".field-error-message");
  if (errorMessage) {
    group.classList.add("has-error");
    if (errorEl) errorEl.textContent = errorMessage;
  } else {
    group.classList.remove("has-error");
    if (errorEl) errorEl.textContent = "";
  }
}

/**
 * Clears all field errors on a form.
 * 
 * @param {HTMLFormElement} formElement 
 */
function clearAllFieldErrors(formElement) {
  if (!formElement) return;
  const groups = formElement.querySelectorAll(".form-group");
  groups.forEach(g => {
    g.classList.remove("has-error");
    const err = g.querySelector(".field-error-message");
    if (err) err.textContent = "";
  });
}

/**
 * Toggles visibility between password and plaintext for password inputs.
 * Updates the SVG icon and accessible aria-label.
 * 
 * @param {string} inputId - ID of password input
 * @param {string} buttonId - ID of toggle button
 */
function togglePasswordVisibility(inputId, buttonId) {
  const input = document.getElementById(inputId);
  const btn = document.getElementById(buttonId);
  if (!input || !btn) return;

  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  btn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");

  // SVG Eye vs Eye-Off icon
  if (isPassword) {
    // Eye-Off Icon
    btn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/>
        <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/>
        <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/>
        <line x1="2" x2="22" y1="2" y2="22"/>
      </svg>`;
  } else {
    // Eye Icon
    btn.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>`;
  }
}

/* ==========================================================================
   Session Management
   ========================================================================== */

/**
 * Creates an authenticated session for the user.
 * Stores user identifier in sessionStorage (and localStorage if rememberMe is enabled).
 * 
 * @param {Object} user - User object
 * @param {boolean} rememberMe - Whether to persist session across browser restarts
 */
function createSession(user, rememberMe = false) {
  if (!user || !user.id) return;

  // Active session in sessionStorage
  sessionStorage.setItem(STORAGE_KEYS.SESSION, user.id);

  if (rememberMe) {
    localStorage.setItem(STORAGE_KEYS.REMEMBER, user.id);
    localStorage.setItem(STORAGE_KEYS.LAST_IDENTIFIER, user.username);
  } else {
    localStorage.removeItem(STORAGE_KEYS.REMEMBER);
  }
}

/**
 * Retrieves the currently authenticated user from session.
 * 
 * @returns {Object|null} The logged-in user object or null
 */
function getCurrentUser() {
  const userId = sessionStorage.getItem(STORAGE_KEYS.SESSION) || localStorage.getItem(STORAGE_KEYS.REMEMBER);
  if (!userId) return null;

  const users = getUsers();
  const user = users.find(u => u.id === userId);
  return user || null;
}

/**
 * Enforces route protection based on current authentication state.
 * 
 * @param {boolean} requireAuth - True if page requires authentication (e.g. dashboard)
 * @param {string} redirectUrl - Fallback destination url
 */
function checkAuthentication(requireAuth, redirectUrl) {
  const currentUser = getCurrentUser();

  if (requireAuth && !currentUser) {
    // Unauthenticated user attempting to access protected dashboard -> redirect to login
    window.location.replace(redirectUrl || "index.html");
    return false;
  }

  if (!requireAuth && currentUser) {
    // Already authenticated user visiting login or register -> redirect to dashboard
    window.location.replace("dashboard.html");
    return false;
  }

  return true;
}

/**
 * Logs out the current user, clears active sessions, and redirects to login page.
 */
function logoutUser() {
  sessionStorage.removeItem(STORAGE_KEYS.SESSION);
  localStorage.removeItem(STORAGE_KEYS.REMEMBER);
  window.location.replace("index.html");
}

/* ==========================================================================
   User Registration Flow (register.html)
   ========================================================================== */

/**
 * Handles the registration form submission.
 * Validates inputs, checks duplicates, computes SHA-256 hash, and saves user.
 * 
 * @param {Event} event 
 */
async function registerUser(event) {
  event.preventDefault();
  
  const form = event.target;
  const usernameInput = document.getElementById("reg-username");
  const emailInput = document.getElementById("reg-email");
  const passwordInput = document.getElementById("reg-password");
  const confirmPasswordInput = document.getElementById("reg-confirm-password");
  const alertId = "register-alert";

  hideMessage(alertId);
  clearAllFieldErrors(form);

  const username = usernameInput ? usernameInput.value.trim() : "";
  const email = emailInput ? emailInput.value.trim() : "";
  const password = passwordInput ? passwordInput.value : "";
  const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : "";

  // 1. Field validation
  const validation = validateRegistration(username, email, password, confirmPassword);
  if (!validation.isValid) {
    if (validation.errors.username) setFieldError("reg-username", validation.errors.username);
    if (validation.errors.email) setFieldError("reg-email", validation.errors.email);
    if (validation.errors.password) setFieldError("reg-password", validation.errors.password);
    if (validation.errors.confirmPassword) setFieldError("reg-confirm-password", validation.errors.confirmPassword);
    
    // Focus first invalid field
    const firstInvalid = Object.keys(validation.errors)[0];
    const fieldMap = {
      username: "reg-username",
      email: "reg-email",
      password: "reg-password",
      confirmPassword: "reg-confirm-password"
    };
    const elementToFocus = document.getElementById(fieldMap[firstInvalid]);
    if (elementToFocus) elementToFocus.focus();

    return;
  }

  // 2. Duplicate user check
  const normalizedEmail = email.toLowerCase();
  const normalizedUsername = username.toLowerCase();
  const existingUsers = getUsers();

  const isDuplicate = existingUsers.some(u => 
    u.username.toLowerCase() === normalizedUsername || 
    u.email.toLowerCase() === normalizedEmail
  );

  if (isDuplicate) {
    showMessage(alertId, "An account with this username or email already exists.", "error");
    return;
  }

  // Disable button while processing
  const submitBtn = form.querySelector("button[type='submit']");
  const originalBtnText = submitBtn ? submitBtn.textContent : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Creating Account...";
  }

  try {
    // 3. Cryptographic Password Hashing (SHA-256)
    const passwordHash = await hashPassword(password);

    // 4. Construct user record (NEVER storing plaintext password)
    const newUser = {
      id: "user_" + Date.now() + "_" + Math.random().toString(36).substring(2, 8),
      username: username,
      email: normalizedEmail,
      passwordHash: passwordHash,
      createdAt: new Date().toISOString()
    };

    existingUsers.push(newUser);
    saveUsers(existingUsers);

    // 5. Success Feedback
    showMessage(alertId, "✓ Registration successful! You can now log in.", "success");
    form.reset();
    updatePasswordStrength("");

    // Automatically transition to login after 1.6 seconds
    setTimeout(() => {
      window.location.href = "index.html?registered=true";
    }, 1600);

  } catch (err) {
    console.error("Registration error:", err);
    showMessage(alertId, "An unexpected error occurred during registration. Please try again.", "error");
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalBtnText;
    }
  }
}

/* ==========================================================================
   User Login Flow (index.html)
   ========================================================================== */

/**
 * Handles the login form submission.
 * Validates inputs, looks up user, computes SHA-256 hash, compares, and creates session.
 * 
 * @param {Event} event 
 */
async function loginUser(event) {
  event.preventDefault();

  const form = event.target;
  const identifierInput = document.getElementById("login-identifier");
  const passwordInput = document.getElementById("login-password");
  const rememberCheckbox = document.getElementById("remember-me");
  const alertId = "login-alert";

  hideMessage(alertId);
  clearAllFieldErrors(form);

  const identifier = identifierInput ? identifierInput.value.trim() : "";
  const password = passwordInput ? passwordInput.value : "";
  const rememberMe = rememberCheckbox ? rememberCheckbox.checked : false;

  // 1. Check empty fields
  let hasEmpty = false;
  if (!identifier) {
    setFieldError("login-identifier", "Please enter your username or email.");
    hasEmpty = true;
  }
  if (!password) {
    setFieldError("login-password", "Please enter your password.");
    hasEmpty = true;
  }

  if (hasEmpty) {
    showMessage(alertId, "Please fill in all required fields.", "error");
    return;
  }

  // Disable button while processing
  const submitBtn = form.querySelector("button[type='submit']");
  const originalBtnText = submitBtn ? submitBtn.textContent : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Signing In...";
  }

  try {
    // 2. Find user in localStorage
    const normalizedIdentifier = identifier.toLowerCase();
    const users = getUsers();
    const matchedUser = users.find(u => 
      u.username.toLowerCase() === normalizedIdentifier || 
      u.email.toLowerCase() === normalizedIdentifier
    );

    // 3. Compute hash and compare
    const enteredHash = await hashPassword(password);

    // Constant: generic error message to not reveal user existence vs password error
    const genericErrorMessage = "Invalid username/email or password.";

    if (!matchedUser || matchedUser.passwordHash !== enteredHash) {
      showMessage(alertId, genericErrorMessage, "error");
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalBtnText;
      }
      return;
    }

    // 4. Successful Authentication -> Create Session
    createSession(matchedUser, rememberMe);
    showMessage(alertId, "✓ Login successful! Redirecting...", "success");

    setTimeout(() => {
      window.location.replace("dashboard.html");
    }, 600);

  } catch (err) {
    console.error("Login error:", err);
    showMessage(alertId, "An error occurred while logging in. Please try again.", "error");
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = originalBtnText;
    }
  }
}

/* ==========================================================================
   Dashboard Population (dashboard.html)
   ========================================================================== */

/**
 * Initializes and populates the protected dashboard.
 * Formats timestamps and binds the logout action.
 */
function initDashboard() {
  // 1. Enforce protection: if not logged in, redirect immediately
  const user = getCurrentUser();
  if (!user) {
    window.location.replace("index.html");
    return;
  }

  // 2. Populate user fields safely via textContent
  const welcomeTitle = document.getElementById("dash-welcome-title");
  const welcomeSubtitle = document.getElementById("dash-welcome-subtitle");
  const userNavName = document.getElementById("dash-nav-username");
  const userNavAvatar = document.getElementById("dash-nav-avatar");

  const statAccount = document.getElementById("stat-account");
  const statStatus = document.getElementById("stat-status");
  const statMemberSince = document.getElementById("stat-member-since");

  const detailUsername = document.getElementById("detail-username");
  const detailEmail = document.getElementById("detail-email");
  const detailCreated = document.getElementById("detail-created");
  const detailHash = document.getElementById("detail-hash");

  // Format date
  let formattedDate = "N/A";
  let fullDate = "N/A";
  if (user.createdAt) {
    try {
      const d = new Date(user.createdAt);
      formattedDate = d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
      fullDate = d.toLocaleString(undefined, { 
        year: "numeric", 
        month: "long", 
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });
    } catch {
      formattedDate = user.createdAt;
      fullDate = user.createdAt;
    }
  }

  if (welcomeTitle) welcomeTitle.textContent = `Welcome, ${user.username}! 👋`;
  if (welcomeSubtitle) welcomeSubtitle.textContent = "You have successfully logged in.";
  if (userNavName) userNavName.textContent = user.username;
  if (userNavAvatar) userNavAvatar.textContent = user.username.charAt(0).toUpperCase();

  if (statAccount) statAccount.textContent = "Active";
  if (statStatus) statStatus.textContent = "Authenticated";
  if (statMemberSince) statMemberSince.textContent = formattedDate;

  if (detailUsername) detailUsername.textContent = user.username;
  if (detailEmail) detailEmail.textContent = user.email;
  if (detailCreated) detailCreated.textContent = fullDate;
  if (detailHash && user.passwordHash) {
    // Truncate hash with ellipsis for visual proof
    detailHash.textContent = `${user.passwordHash.substring(0, 16)}...${user.passwordHash.substring(user.passwordHash.length - 8)}`;
  }

  // 3. Bind logout button
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", (e) => {
      e.preventDefault();
      logoutUser();
    });
  }
}

/* ==========================================================================
   Page Router & Event Wiring
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  const pageType = document.body.dataset.page;

  // ------------------------------------------------------------------------
  // Login Page Initialization
  // ------------------------------------------------------------------------
  if (pageType === "login") {
    // Redirect if already logged in
    if (!checkAuthentication(false, "dashboard.html")) return;

    // Check if redirected from registration
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("registered") === "true") {
      showMessage("login-alert", "✓ Registration successful! You can now log in.", "success", true);
    }

    // Auto-fill last remembered identifier if exists
    const remembered = localStorage.getItem(STORAGE_KEYS.LAST_IDENTIFIER);
    const identifierInput = document.getElementById("login-identifier");
    if (remembered && identifierInput) {
      identifierInput.value = remembered;
      const rememberCheckbox = document.getElementById("remember-me");
      if (rememberCheckbox) rememberCheckbox.checked = true;
    }

    // Bind form
    const loginForm = document.getElementById("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", loginUser);
    }

    // Password toggle
    const toggleBtn = document.getElementById("toggle-login-password");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        togglePasswordVisibility("login-password", "toggle-login-password");
      });
    }

    // Clear field error on input
    const inputs = loginForm ? loginForm.querySelectorAll(".input-field") : [];
    inputs.forEach(input => {
      input.addEventListener("input", () => {
        const group = input.closest(".form-group");
        if (group) group.classList.remove("has-error");
      });
    });
  }

  // ------------------------------------------------------------------------
  // Registration Page Initialization
  // ------------------------------------------------------------------------
  if (pageType === "register") {
    // Redirect if already logged in
    if (!checkAuthentication(false, "dashboard.html")) return;

    const registerForm = document.getElementById("register-form");
    if (registerForm) {
      registerForm.addEventListener("submit", registerUser);
    }

    // Password strength listener
    const passwordInput = document.getElementById("reg-password");
    if (passwordInput) {
      passwordInput.addEventListener("input", (e) => {
        updatePasswordStrength(e.target.value);
      });
    }

    // Password toggle buttons
    const togglePassBtn = document.getElementById("toggle-reg-password");
    if (togglePassBtn) {
      togglePassBtn.addEventListener("click", () => {
        togglePasswordVisibility("reg-password", "toggle-reg-password");
      });
    }

    const toggleConfirmPassBtn = document.getElementById("toggle-reg-confirm-password");
    if (toggleConfirmPassBtn) {
      toggleConfirmPassBtn.addEventListener("click", () => {
        togglePasswordVisibility("reg-confirm-password", "toggle-reg-confirm-password");
      });
    }

    // Clear field errors dynamically on user input
    const inputs = registerForm ? registerForm.querySelectorAll(".input-field") : [];
    inputs.forEach(input => {
      input.addEventListener("input", () => {
        const group = input.closest(".form-group");
        if (group) group.classList.remove("has-error");
      });
    });
  }

  // ------------------------------------------------------------------------
  // Dashboard Page Initialization
  // ------------------------------------------------------------------------
  if (pageType === "dashboard") {
    initDashboard();
  }
});
