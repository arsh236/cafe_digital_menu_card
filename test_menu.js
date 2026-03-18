const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const SUPABASE_URL = 'https://ymupssdhzvrdasvlyujs.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InltdXBzc2RoenZyZGFzdmx5dWpzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM4MTEyNDcsImV4cCI6MjA4OTM4NzI0N30.7CRqqNzHsD0jwojTiazvEpfW4dK2x7hePR5PSIOVHso';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

function hashPassword(password) {
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    return hash;
}

async function runTest() {
    try {
        console.log("1. Hashing password...");
        const hash = hashPassword('1234');
        
        console.log("2. Logging in as '1234'...");
        const { data: user, error: loginErr } = await supabase.rpc('secure_login_user', {
            p_phone: '1234',
            p_password_hash: hash
        });
        
        if (loginErr) throw loginErr;
        console.log("User logged in! ID:", user.id);

        console.log("3. Fetching Cafe...");
        const { data: cafes, error: cafeErr } = await supabase
            .from('cafes')
            .select('*')
            .eq('owner_id', user.id);
            
        if (cafeErr) throw cafeErr;
        if (!cafes || cafes.length === 0) {
            console.log("No cafes found for this user!");
            return;
        }
        
        const cafe = cafes[0];
        console.log("Cafe Data:", cafe);
        
        const now = new Date();
        const expiry = new Date(cafe.expiry_date);
        console.log("Is active?", cafe.is_active);
        console.log("Now:", now.toISOString(), "Expiry:", expiry.toISOString());
        console.log("Is expired?", now > expiry);

        console.log("4. Fetching Menu Items...");
        const { data: items, error: itemsErr } = await supabase
            .from('menu_items')
            .select('*')
            .eq('cafe_id', cafe.id)
            .eq('is_active', true)
            .order('category', { ascending: true });
            
        if (itemsErr) throw itemsErr;
        
        console.log(`Found ${items ? items.length : 0} active menu items!`);
        console.log(items);
        
    } catch(e) {
        console.error("DEBUG ERROR CRASH:");
        console.error(e);
    }
}

runTest();
