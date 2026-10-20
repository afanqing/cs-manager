use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

pub fn hash_password(plain: &str) -> String {
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).expect("salt");
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .expect("hash")
        .to_string()
}

pub fn verify_password(plain: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

#[derive(Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub must_change_password: bool,
}

pub fn ensure_admin(conn: &Connection, admin_password: &Option<String>) -> anyhow::Result<()> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM users WHERE role='admin'", [], |r| r.get(0))?;
    if count == 0 {
        let (pw, must_change) = match admin_password {
            Some(p) => (p.clone(), 0i64),
            None => (generate_temp_password(), 1i64),
        };
        let hash = hash_password(&pw);
        conn.execute(
            "INSERT INTO users (username, password_hash, role, must_change_password, created_at)
             VALUES ('admin', ?1, 'admin', ?2, unixepoch())",
            params![hash, must_change],
        )?;
        if admin_password.is_none() {
            eprintln!("==========================================");
            eprintln!("已创建 admin 账户");
            eprintln!("用户名: admin");
            eprintln!("临时密码: {}", pw);
            eprintln!("首次登录后请立即修改密码");
            eprintln!("==========================================");
        }
    }
    Ok(())
}

pub fn generate_temp_password() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn create_session(conn: &Connection, user_id: i64, kind: &str) -> anyhow::Result<String> {
    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token: String = token_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let now = now_unix();
    let ttl = if kind == "pending_reset" { 3600 } else { 86400 * 7 };
    conn.execute(
        "INSERT INTO sessions (token, user_id, kind, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token, user_id, kind, now, now + ttl],
    )?;
    Ok(token)
}

pub fn load_session(
    conn: &Connection,
    token: &str,
) -> anyhow::Result<Option<(User, String)>> {
    let row = conn
        .query_row(
            "SELECT u.id, u.username, u.role, u.must_change_password, s.kind
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token = ?1 AND s.expires_at > ?2",
            params![token, now_unix()],
            |r| {
                Ok((
                    User {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        role: r.get(2)?,
                        must_change_password: r.get::<_, i64>(3)? != 0,
                    },
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    Ok(row)
}

pub fn delete_session(conn: &Connection, token: &str) -> anyhow::Result<()> {
    conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
    Ok(())
}

pub fn delete_user_sessions(conn: &Connection, user_id: i64) -> anyhow::Result<()> {
    conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
    Ok(())
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}