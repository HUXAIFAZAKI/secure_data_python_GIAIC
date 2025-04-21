import streamlit as st
import hashlib
import uuid
from cryptography.fernet import Fernet

if 'cipher_key' not in st.session_state:
    st.session_state.cipher_key = Fernet.generate_key()
cipher = Fernet(st.session_state.cipher_key)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  
    st.session_state.failed_attempts = 0
if 'page' not in st.session_state:
    st.session_state.page = "Home"

# ---------- Utility Functions ----------

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(entry_id: str, passkey: str):
    if entry_id not in st.session_state.stored_data:
        return "NOT_FOUND"
    
    entry = st.session_state.stored_data[entry_id]
    hashed_input = hash_passkey(passkey)

    if hashed_input != entry['passkey']:
        st.session_state.failed_attempts += 1
        return None

    try:
        decrypted = cipher.decrypt(entry['encrypted_text'].encode()).decode()
        st.session_state.failed_attempts = 0
        return decrypted
    except Exception:
        st.session_state.failed_attempts += 1
        return None

# ---------- UI Navigation ----------

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))

# ---------- Pages ----------

if choice == "Home":
    st.session_state.page = "Home"
    col1, col2, col3 = st.columns([0.5, 3, 0.5])
    with col2:
        st.markdown("<h1 style='text-align: center; color: #4A90E2;'>🛡️ Secure Data Vault</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-size: 18px;'>Store your sensitive data safely with end-to-end encryption.</p>", unsafe_allow_html=True)
        st.markdown("### 🔐 Features\n\n- 🔏 Encryption using Fernet\n- 🧪 Passkey-based security\n- 🚫 Auto-lock after 3 failed attempts\n- 🧠 In-memory storage (no database needed)")      
        st.divider()

        # Navigation Buttons
        colA, colB = st.columns(2)
        with colA:
            if st.button("📂 Store New Data"):
                st.session_state.page = "Store Data"
                st.rerun()
        with colB:
            if st.button("🔍 Retrieve Stored Data"):
                st.session_state.page = "Retrieve Data"
                st.rerun()
        
        st.divider()
        st.markdown("<p style='text-align: center; color: gray;'>Built using Python + Streamlit</p>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: gray;'>Built by HUXAIFA</p>", unsafe_allow_html=True)

elif choice == "Store Data":
    st.session_state.page = "Store Data"
    st.title("📂 Store Data Securely")

    user_data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            data_id = str(uuid.uuid4())[:8]
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)

            st.session_state.stored_data[data_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }

            st.success("✅ Data stored securely!")
            st.balloons()
            st.code(f"Your Data ID: {data_id}", language="text")
        else:
            st.error("⚠️ Please fill in both fields.")

elif choice == "Retrieve Data":
    st.session_state.page = "Retrieve Data"
    st.title("🔍 Retrieve Stored Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts. Please log in to continue.")
        st.session_state.page = "Login"
        st.rerun()

    entry_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt"):
        if entry_id and passkey:
            result = decrypt_data(entry_id, passkey)
            if result == "NOT_FOUND":
                st.error("❌ Data ID not found.")
            elif result is None:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Redirecting to Login Page...")
                    st.session_state.page = "Login"
                    st.rerun()
            else:
                st.success("✅ Decryption Successful:")
                st.code(result, language="text")
        else:
            st.error("⚠️ Please fill in both fields.")

elif choice == "Login":
    st.session_state.page = "Login"
    st.title("🔑 Reauthorize to Continue")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.success("✅ Login Successful! You may now retry.")
            st.session_state.failed_attempts = 0
            st.session_state.page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect admin password.")