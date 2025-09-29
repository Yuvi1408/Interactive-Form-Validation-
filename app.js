document.addEventListener("DOMContentLoaded", () => {
  const API_BASE = "http://localhost:3000/api";

  // --- DOM Element Selection ---
  const form = document.getElementById("registrationForm");
  const inputs = form.querySelectorAll("input[required]");
  const allInputs = form.querySelectorAll("input");
  const progressBar = document.getElementById("progressBar");
  const submitBtn = document.getElementById("submitBtn");
  const formMessage = document.getElementById("formMessage");
  const themeToggle = document.getElementById("themeToggle");
  const password = document.getElementById("password");
  const confirmPassword = document.getElementById("confirmPassword");
  const meterFill = document.getElementById("meterFill");
  const strengthText = document.getElementById("password-strength-text");
  const forgotPasswordLink = document.getElementById("forgotPasswordLink"); // Added for Phase 4

  // --- Validation Logic ---
  const validators = {
    username: (v) => /^[a-zA-Z0-9_]{3,20}$/.test(v) || "3–20 chars, letters/numbers/_ only",
    fullName: (v) => /^[A-Za-z\s]{3,}$/.test(v) || "Enter a valid name",
    email: (v) => /^\S+@\S+\.\S+$/.test(v) || "Please enter a valid email",
    phone: (v) => /^\+?[0-9]{7,15}$/.test(v) || "Please enter a valid phone number",
    password: (v) => v.length >= 8 || "Password must be at least 8 characters",
    confirmPassword: (v) => v === password.value || "Passwords do not match",
    website: (v) => !v || /^https?:\/\/.+\..+/.test(v) || "Please enter a valid URL",
    birthdate: (v) => {
      if (!v) return "Date of birth is required";
      const age = (Date.now() - new Date(v).getTime()) / (31557600000);
      return age >= 13 || "You must be at least 13 years old";
    },
    terms: (v) => v || "You must accept the terms and conditions",
  };

  // --- Functions ---
  function debounce(fn, delay = 500) {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => fn.apply(this, args), delay);
    };
  }

  const checkUsername = debounce(async (usernameValue) => {
    const usernameInput = document.getElementById('username');
    if (validators.username(usernameValue) !== true) return;
    try {
      const res = await fetch(`${API_BASE}/validate-username`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: usernameValue }),
      });
      const data = await res.json();
      if (!data.available) {
        setInvalid(usernameInput, "Username is already taken");
      }
    } catch (err) {
      console.error("Server unavailable for username check");
    }
  });

  function validateInput(el) {
    const validatorFn = validators[el.name];
    if (!validatorFn) return true;

    const value = el.type === "checkbox" ? el.checked : el.value.trim();
    const result = validatorFn(value);

    if (result !== true) {
      setInvalid(el, result);
      return false;
    } else {
      setValid(el);
      if (el.name === "username") checkUsername(value);
      return true;
    }
  }

  function setInvalid(el, message) {
    const errorEl = document.getElementById(`${el.id}-error`);
    el.classList.add("invalid");
    el.classList.remove("valid");
    el.setAttribute("aria-invalid", "true");
    errorEl.textContent = message;
  }

  function setValid(el) {
    const errorEl = document.getElementById(`${el.id}-error`);
    el.classList.remove("invalid");
    el.classList.add("valid");
    el.setAttribute("aria-invalid", "false");
    errorEl.textContent = "";
  }

  function updatePasswordStrength(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    score = Math.min(score, 4);

    const strengthLevels = ["Weak", "Medium", "Strong", "Very Strong"];
    const colors = ["#dc3545", "#fd7e14", "#ffc107", "#28a745"];

    const pct = (score / 4) * 100;
    meterFill.style.width = `${pct}%`;
    meterFill.style.backgroundColor = colors[score - 1] || "#eee";
    strengthText.textContent = `Strength: ${strengthLevels[score - 1] || "None"}`;
  }

  function updateProgress() {
    const filled = Array.from(inputs).filter(i => (i.type === "checkbox" ? i.checked : i.value)).length;
    const pct = Math.round((filled / inputs.length) * 100);
    progressBar.style.width = `${pct}%`;
    progressBar.setAttribute("aria-valuenow", pct);
    
    const allValid = Array.from(inputs).every(el => validateInput(el));
    submitBtn.disabled = !allValid;
  }
  
  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    themeToggle.setAttribute("aria-pressed", theme === "dark");
  }

  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    const newTheme = currentTheme === "light" ? "dark" : "light";
    localStorage.setItem("theme", newTheme);
    applyTheme(newTheme);
  }

  // --- Event Listeners ---
  form.addEventListener("input", (e) => {
    const target = e.target;
    if(target.matches('input')) {
        validateInput(target);
        if (target.id === "password") updatePasswordStrength(target.value);
        if (target.id === "confirmPassword") validateInput(target);
        updateProgress();
    }
  });

  document.getElementById("togglePassword").addEventListener("click", () => {
    const isPassword = password.type === "password";
    password.type = isPassword ? "text" : "password";
    confirmPassword.type = isPassword ? "text" : "password";
  });

  themeToggle.addEventListener("click", toggleTheme);

  // ADDED: Forgot Password Logic
  forgotPasswordLink.addEventListener("click", (e) => {
    e.preventDefault();
    const email = prompt("Please enter your email to reset your password:");
    if (email && validators.email(email) === true) {
      // In a real app, this would call the backend API
      formMessage.textContent = `A password reset link has been sent to ${email}.`;
      formMessage.style.color = "var(--primary)";
    } else if (email) {
      alert("You entered an invalid email address.");
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    let isFormValid = true;
    let firstInvalidElement = null;

    allInputs.forEach(el => {
      // Validate only if the element is required or has a value
      if(el.required || (el.value && el.type !== 'checkbox')) {
        if (!validateInput(el)) {
          isFormValid = false;
          if (!firstInvalidElement) firstInvalidElement = el; // Capture the first invalid element
        }
      }
    });

    if (!isFormValid) {
      formMessage.textContent = "Please correct the errors in the form.";
      formMessage.style.color = "var(--danger)";
      firstInvalidElement?.focus(); // Focus on the first invalid element
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="spinner"></span>Registering...`;
    formMessage.textContent = "";
    
    const formData = Object.fromEntries(new FormData(form).entries());

    try {
      const res = await fetch(`${API_BASE}/submit-form`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const data = await res.json();

      if (!res.ok) {
        const message = data.errors ? data.errors[0].msg : (data.message || "An unknown error occurred.");
        throw new Error(message);
      }
      
      formMessage.textContent = data.message;
      formMessage.style.color = "var(--success)";
      console.log('Successfully registered user:', data.user); // Log the returned user object
      form.reset();
      allInputs.forEach(el => {
        el.classList.remove('valid', 'invalid');
        el.setAttribute('aria-invalid', 'false');
      });
      updateProgress();
      updatePasswordStrength('');

    } catch (err) {
      formMessage.textContent = err.message || "Server error. Please try again later.";
      formMessage.style.color = "var(--danger)";
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerHTML = "Register";
    }
  });

  // --- Initialization ---
  const savedTheme = localStorage.getItem("theme") || "light";
  applyTheme(savedTheme);
  updateProgress();
});