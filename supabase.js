var SUPABASE_URL = 'https://ymupssdhzvrdasvlyujs.supabase.co';
var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InltdXBzc2RoenZyZGFzdmx5dWpzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4MTEyNDcsImV4cCI6MjA4OTM4NzI0N30.7CRqqNzHsD0jwojTiazvEpfW4dK2x7hePR5PSIOVHso';

var supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Utility: Hash password using SHA-256 natively in Browser (Asymmetric Frontend Hashing)
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// -------------------------------------------------------------
// CORE AUTHENTICATION FUNCTIONS
// -------------------------------------------------------------

async function registerUser(phone, password) {
    if (!phone || password.length < 4) {
        throw new Error('Phone required and password must be at least 4 characters');
    }
    const hash = await hashPassword(password);

    // Call secure DB function
    const { data, error } = await supabase.rpc('secure_register_user', {
        p_phone: phone,
        p_password_hash: hash
    });

    if (error) {
        if (error.message.includes('User already exists')) {
            throw new Error('User already exists');
        }
        throw new Error('Server error: ' + error.message);
    }
    return data;
}

async function loginUser(phone, password) {
    if (!phone || !password) throw new Error('Phone and password required');
    const hash = await hashPassword(password);

    // Call secure DB function
    const { data, error } = await supabase.rpc('secure_login_user', {
        p_phone: phone,
        p_password_hash: hash
    });

    if (error) {
        if (error.message.includes('Invalid login') || error.message.includes('0 rows')) {
            throw new Error('Invalid login');
        }
        throw new Error('Server error: ' + error.message);
    }

    // Set Session payload (Now injecting the hash locally so RPC calls can securely write data without Auth)
    const sessionPayload = {
        id: data.id,
        phone: data.phone,
        password_hash: hash,
        is_superadmin: data.is_superadmin
    };
    
    localStorage.setItem('digital_menu_session', JSON.stringify(sessionPayload));
    return sessionPayload;
}

function logoutUser() {
    localStorage.removeItem('digital_menu_session');
    window.location.href = 'login.html';
}

function getCurrentUser() {
    const user = localStorage.getItem('digital_menu_session');
    return user ? JSON.parse(user) : null;
}

// -------------------------------------------------------------
// SESSION / ACCESS CONTROL 
// -------------------------------------------------------------

function requireAuth(allowSuperAdmin = false) {
    const user = getCurrentUser();
    if (!user) {
        window.location.href = 'login.html';
        return null;
    }
    
    const isSuperPath = window.location.pathname.includes('superadmin');
    if (user.is_superadmin) {
        if (!allowSuperAdmin && !isSuperPath) {
            window.location.href = 'superadmin.html';
        }
    } else {
        if (isSuperPath) {
            window.location.href = 'admin.html';
        }
    }
    return user;
}

// Common error display helper
function showNotification(msg, type = 'error') {
    const el = document.getElementById('notification');
    if (el) {
        el.textContent = msg;
        el.className = `notification ${type}`;
        el.style.display = 'block';
        setTimeout(() => el.style.display = 'none', 3000);
    } else {
        alert(msg);
    }
}
