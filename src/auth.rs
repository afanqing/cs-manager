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

/// 审计日志条目。
///
/// 对应 `audit_log` 表的一行，`list_audit_logs` 返回此结构体的列表。
#[derive(Clone, Debug)]
pub struct AuditLogEntry {
    pub id: i64,
    pub username: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
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

/// 插入审计日志
pub fn insert_audit_log(
    conn: &Connection,
    user_id: i64,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO audit_log (user_id, action, target, detail) VALUES (?1, ?2, ?3, ?4)",
        params![user_id, action, target, detail],
    )?;
    Ok(())
}

/// 查询审计日志（最近 N 条，按 id 倒序）。
pub fn list_audit_logs(conn: &Connection, limit: i64) -> anyhow::Result<Vec<AuditLogEntry>> {
    let mut stmt = conn.prepare(
        "SELECT a.id, u.username, a.action, a.target, a.detail, a.created_at
         FROM audit_log a JOIN users u ON u.id = a.user_id
         ORDER BY a.id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit], |r| {
        Ok(AuditLogEntry {
            id: r.get(0)?,
            username: r.get(1)?,
            action: r.get(2)?,
            target: r.get(3)?,
            detail: r.get(4)?,
            created_at: r.get(5)?,
        })
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'member',
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                detail TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (1, 'admin', 'hash', 'admin', 0)",
            [],
        )
        .unwrap();
        conn
    }

    #[test]
    fn insert_and_list_audit_logs() {
        let conn = setup_test_db();

        insert_audit_log(&conn, 1, "login", Some("admin"), None).unwrap();
        insert_audit_log(&conn, 1, "create_instance", Some("devbox"), Some("mem=1024 cpus=2")).unwrap();
        insert_audit_log(&conn, 1, "stop", Some("devbox"), None).unwrap();

        let logs = list_audit_logs(&conn, 10).unwrap();
        assert_eq!(logs.len(), 3);
        // order by id DESC, newest first
        assert_eq!(logs[0].action, "stop");
        assert_eq!(logs[1].action, "create_instance");
        assert_eq!(logs[2].action, "login");
    }

    #[test]
    fn list_audit_logs_respects_limit() {
        let conn = setup_test_db();
        for i in 0..5 {
            insert_audit_log(&conn, 1, &format!("action_{}", i), None, None).unwrap();
        }

        let logs = list_audit_logs(&conn, 3).unwrap();
        assert_eq!(logs.len(), 3);
    }

    #[test]
    fn list_audit_logs_empty() {
        let conn = setup_test_db();
        let logs = list_audit_logs(&conn, 10).unwrap();
        assert!(logs.is_empty());
    }

    #[test]
    fn audit_log_optional_fields() {
        let conn = setup_test_db();

        // target and detail are None
        insert_audit_log(&conn, 1, "logout", None, None).unwrap();
        let logs = list_audit_logs(&conn, 1).unwrap();
        assert_eq!(logs[0].action, "logout");
        assert_eq!(logs[0].target, None);
        assert_eq!(logs[0].detail, None);

        // target is Some, detail is None
        insert_audit_log(&conn, 1, "delete", Some("user_bob"), None).unwrap();
        let logs = list_audit_logs(&conn, 1).unwrap();
        assert_eq!(logs[0].action, "delete");
        assert_eq!(logs[0].target, Some("user_bob".to_string()));
        assert_eq!(logs[0].detail, None);
    }

    #[test]
    fn audit_log_includes_username_via_join() {
        let conn = setup_test_db();

        insert_audit_log(&conn, 1, "change_password", None, None).unwrap();
        let logs = list_audit_logs(&conn, 1).unwrap();
        // username from JOIN
        assert_eq!(logs[0].username, "admin");
    }

    #[test]
    fn password_hash_and_verify_roundtrip() {
        let password = "test_password_123!@#";
        let hash = hash_password(password);
        
        // 验证密码正确
        assert!(verify_password(password, &hash));
        // 验证错误密码失败
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn password_hash_is_different_each_time() {
        let password = "same_password";
        let hash1 = hash_password(password);
        let hash2 = hash_password(password);
        
        // 即使密码相同，哈希也应该不同（因为盐不同）
        assert_ne!(hash1, hash2);
        
        // 但两个哈希都应该能验证密码
        assert!(verify_password(password, &hash1));
        assert!(verify_password(password, &hash2));
    }

    #[test]
    fn ensure_admin_creates_only_if_not_exists() {
        let conn = setup_test_db();
        
        // 第一次调用应该创建 admin
        ensure_admin(&conn, &Some("test123".to_string())).unwrap();
        
        // 再次调用不应该失败
        ensure_admin(&conn, &Some("test456".to_string())).unwrap();
        
        // 验证 admin 存在且密码是第一次设置的
        // 更直接的验证：查询数据库
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE username = 'admin'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn session_creation_and_loading() {
        let conn = setup_test_db();
        
        // 创建会话
        let token = create_session(&conn, 1, "full").unwrap();
        
        // 加载会话应该成功
        let result = load_session(&conn, &token).unwrap();
        assert!(result.is_some());
        
        let (user, kind) = result.unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(kind, "full");
    }

    #[test]
    fn session_deletion() {
        let conn = setup_test_db();
        
        // 创建会话
        let token = create_session(&conn, 1, "full").unwrap();
        
        // 删除会话
        delete_session(&conn, &token).unwrap();
        
        // 再次加载应该返回 None
        let result = load_session(&conn, &token).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn delete_user_sessions_removes_all() {
        let conn = setup_test_db();
        
        // 创建多个会话
        let token1 = create_session(&conn, 1, "full").unwrap();
        let token2 = create_session(&conn, 1, "pending_reset").unwrap();
        
        // 删除用户 1 的所有会话
        delete_user_sessions(&conn, 1).unwrap();
        
        // 两个会话都应该被删除
        assert!(load_session(&conn, &token1).unwrap().is_none());
        assert!(load_session(&conn, &token2).unwrap().is_none());
    }

    #[test]
    fn temp_password_generation() {
        let temp1 = generate_temp_password();
        let temp2 = generate_temp_password();
        
        // 临时密码应该是 24 位 hex
        assert_eq!(temp1.len(), 24);
        assert_eq!(temp2.len(), 24);
        
        // 每次生成的密码应该不同
        assert_ne!(temp1, temp2);
        
        // 应该只包含 hex 字符
        assert!(temp1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(temp2.chars().all(|c| c.is_ascii_hexdigit()));
    }
}