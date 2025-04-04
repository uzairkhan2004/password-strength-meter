import streamlit as st
import re
import random
import string

# Password Strength Criteria
MIN_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL_CHAR = True
SPECIAL_CHARS = "!@#$%^&*"

# Blacklist common passwords
COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein"]

def check_password_strength(password):
    """Evaluate the strength of a password based on security rules."""
    score = 0
    feedback = []

    # Check length
    if len(password) >= MIN_LENGTH:
        score += 1
    else:
        feedback.append(f"Password should be at least {MIN_LENGTH} characters long.")

    # Check for uppercase letters
    if REQUIRE_UPPERCASE and re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Password should include at least one uppercase letter.")

    # Check for lowercase letters
    if REQUIRE_LOWERCASE and re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Password should include at least one lowercase letter.")

    # Check for digits
    if REQUIRE_DIGIT and re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Password should include at least one digit.")

    # Check for special characters
    if REQUIRE_SPECIAL_CHAR and re.search(f"[{re.escape(SPECIAL_CHARS)}]", password):
        score += 1
    else:
        feedback.append(f"Password should include at least one special character ({SPECIAL_CHARS}).")

    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("Password is too common and easily guessable.")

    # Determine strength level
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, feedback

def generate_strong_password(length=12):
    """Generate a strong password that meets all criteria."""
    characters = string.ascii_letters + string.digits + SPECIAL_CHARS
    while True:
        password = "".join(random.choice(characters) for _ in range(length))
        strength, _ = check_password_strength(password)
        if strength == "Strong":
            return password

def main():
    """Main function to run the Streamlit app."""
    st.title("Password Strength Meter 🔒")

    # Input password
    password = st.text_input("Enter your password:", type="password")

    if password:
        # Check password strength
        strength, feedback