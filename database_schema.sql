-- 1. Create Tables
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_superadmin BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- 1.5. Force Add Missing Columns & Defaults (If your tables already existed before this step)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT false;
ALTER TABLE users ALTER COLUMN id SET DEFAULT gen_random_uuid();

CREATE TABLE IF NOT EXISTS cafes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    plan TEXT NOT NULL,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS menu_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cafe_id UUID REFERENCES cafes(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price NUMERIC NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Apply final column patches for cafes and menu_items (if created before this script)
ALTER TABLE cafes ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE menu_items ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE menu_items ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

-- 2. Enable Row Level Security (RLS)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE cafes ENABLE ROW LEVEL SECURITY;
ALTER TABLE menu_items ENABLE ROW LEVEL SECURITY;

-- 3. RLS Policies
-- Security Concept: We disable all write/delete public APIs cleanly. Read APIs are restricted properly.
-- ALL edits/creates/deletes run through isolated SECURITY DEFINER functions.

DROP POLICY IF EXISTS "Deny all public access to users" ON users;
CREATE POLICY "Deny all public access to users" ON users FOR ALL USING (false);

DROP POLICY IF EXISTS "Allow public select on cafes" ON cafes;
CREATE POLICY "Allow public select on cafes" ON cafes FOR SELECT USING (true);
DROP POLICY IF EXISTS "Deny direct public inserts/updates on cafes" ON cafes;
CREATE POLICY "Deny direct public inserts on cafes" ON cafes FOR INSERT WITH CHECK (false);
DROP POLICY IF EXISTS "Deny direct public updates on cafes" ON cafes;
CREATE POLICY "Deny direct public updates on cafes" ON cafes FOR UPDATE USING (false);
DROP POLICY IF EXISTS "Deny direct public deletes on cafes" ON cafes;
CREATE POLICY "Deny direct public deletes on cafes" ON cafes FOR DELETE USING (false);

DROP POLICY IF EXISTS "Allow public select on menu_items" ON menu_items;
CREATE POLICY "Allow public select on menu_items" ON menu_items FOR SELECT USING (true);
DROP POLICY IF EXISTS "Deny direct public modifications on menu_items" ON menu_items;
CREATE POLICY "Deny direct public modifications on menu_items" ON menu_items FOR INSERT WITH CHECK (false);
DROP POLICY IF EXISTS "Deny direct public updates on menu_items" ON menu_items;
CREATE POLICY "Deny direct public updates on menu_items" ON menu_items FOR UPDATE USING (false);
DROP POLICY IF EXISTS "Deny direct public deletes on menu_items" ON menu_items;
CREATE POLICY "Deny direct public deletes on menu_items" ON menu_items FOR DELETE USING (false);


-- 4. SECURE RPC FUNCTIONS FOR AUTHENTICATION
CREATE OR REPLACE FUNCTION secure_register_user(p_phone TEXT, p_password_hash TEXT)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    new_user_id UUID;
    v_is_superadmin BOOLEAN;
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE phone = p_phone) THEN
        RAISE EXCEPTION 'User already exists';
    END IF;
    
    -- Auto-grant superadmin to the legendary 7994 phone!
    IF p_phone = '7994' THEN
        v_is_superadmin := true;
    ELSE
        v_is_superadmin := false;
    END IF;

    INSERT INTO users (phone, password_hash, is_superadmin) VALUES (p_phone, p_password_hash, v_is_superadmin) RETURNING id INTO new_user_id;
    RETURN json_build_object('id', new_user_id, 'phone', p_phone, 'is_superadmin', v_is_superadmin);
END;
$$;

CREATE OR REPLACE FUNCTION secure_login_user(p_phone TEXT, p_password_hash TEXT)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    user_record RECORD;
BEGIN
    SELECT id, phone, is_superadmin INTO user_record FROM users WHERE phone = p_phone AND password_hash = p_password_hash;
    IF user_record IS NULL THEN
        RAISE EXCEPTION 'Invalid login';
    END IF;
    RETURN json_build_object('id', user_record.id, 'phone', user_record.phone, 'is_superadmin', user_record.is_superadmin);
END;
$$;

-- 5. SECURE RPC FUNCTIONS FOR DATA MANAGEMENT
CREATE OR REPLACE FUNCTION secure_upsert_cafe(p_user_id UUID, p_password_hash TEXT, p_cafe_id UUID, p_name TEXT, p_plan TEXT, p_expiry_date TIMESTAMP WITH TIME ZONE)
RETURNS json
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    cafe_record RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_password_hash) THEN
        RAISE EXCEPTION 'Unauthorized';
    END IF;

    IF p_cafe_id IS NULL THEN
        INSERT INTO cafes (owner_id, name, plan, expiry_date, is_active) 
        VALUES (p_user_id, p_name, p_plan, p_expiry_date, true) RETURNING * INTO cafe_record;
    ELSE
        UPDATE cafes SET name = p_name WHERE id = p_cafe_id AND owner_id = p_user_id RETURNING * INTO cafe_record;
    END IF;
    
    RETURN row_to_json(cafe_record);
END;
$$;

CREATE OR REPLACE FUNCTION secure_upsert_menu_item(p_user_id UUID, p_password_hash TEXT, p_item_id UUID, p_cafe_id UUID, p_name TEXT, p_category TEXT, p_price NUMERIC, p_desc TEXT, p_is_active BOOLEAN)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_password_hash) THEN
        RAISE EXCEPTION 'Unauthorized';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cafes WHERE id = p_cafe_id AND owner_id = p_user_id) THEN
        RAISE EXCEPTION 'Unauthorized cafe access';
    END IF;
    IF p_item_id IS NULL THEN
        INSERT INTO menu_items (cafe_id, name, category, price, description, is_active) VALUES (p_cafe_id, p_name, p_category, p_price, p_desc, p_is_active);
    ELSE
        UPDATE menu_items SET name = p_name, category = p_category, price = p_price, description = p_desc, is_active = p_is_active WHERE id = p_item_id AND cafe_id = p_cafe_id;
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION secure_delete_menu_item(p_user_id UUID, p_password_hash TEXT, p_item_id UUID, p_cafe_id UUID)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_password_hash) THEN
        RAISE EXCEPTION 'Unauthorized';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM cafes WHERE id = p_cafe_id AND owner_id = p_user_id) THEN
        RAISE EXCEPTION 'Unauthorized cafe access';
    END IF;
    DELETE FROM menu_items WHERE id = p_item_id AND cafe_id = p_cafe_id;
END;
$$;

-- 6. SECURE RPC FUNCTIONS FOR SUPERADMIN
CREATE OR REPLACE FUNCTION secure_superadmin_update_cafe(p_user_id UUID, p_password_hash TEXT, p_cafe_id UUID, p_is_active BOOLEAN, p_expiry_date TIMESTAMP WITH TIME ZONE, p_plan TEXT)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users WHERE id = p_user_id AND password_hash = p_password_hash AND is_superadmin = true) THEN
        RAISE EXCEPTION 'Unauthorized superadmin access';
    END IF;
    IF p_is_active IS NOT NULL THEN
        UPDATE cafes SET is_active = p_is_active WHERE id = p_cafe_id;
    END IF;
    IF p_expiry_date IS NOT NULL THEN
        UPDATE cafes SET expiry_date = p_expiry_date WHERE id = p_cafe_id;
    END IF;
    IF p_plan IS NOT NULL THEN
        UPDATE cafes SET plan = p_plan WHERE id = p_cafe_id;
    END IF;
END;
$$;

-- 7. GRANT PERMISSIONS TO ANON ROLE
-- This forces Supabase PostgREST to allow the anon key to trigger these functions!
GRANT EXECUTE ON FUNCTION secure_register_user(TEXT, TEXT) TO anon;
GRANT EXECUTE ON FUNCTION secure_login_user(TEXT, TEXT) TO anon;
GRANT EXECUTE ON FUNCTION secure_upsert_cafe(UUID, TEXT, UUID, TEXT, TEXT, TIMESTAMP WITH TIME ZONE) TO anon;
GRANT EXECUTE ON FUNCTION secure_upsert_menu_item(UUID, TEXT, UUID, UUID, TEXT, TEXT, NUMERIC, TEXT, BOOLEAN) TO anon;
GRANT EXECUTE ON FUNCTION secure_delete_menu_item(UUID, TEXT, UUID, UUID) TO anon;
GRANT EXECUTE ON FUNCTION secure_superadmin_update_cafe(UUID, TEXT, UUID, BOOLEAN, TIMESTAMP WITH TIME ZONE, TEXT) TO anon;

-- 7.5 GRANT TABLE PERMISSIONS TO ANON
-- Without this, the 'anon' role cannot even pass through the table gateway to reach the RLS policy!
GRANT SELECT ON cafes TO anon;
GRANT SELECT ON menu_items TO anon;

-- 8. RELOAD SCHEMA CACHE
-- Forces Supabase PostgREST API to instantly recognize the new functions.
NOTIFY pgrst, 'reload schema';
