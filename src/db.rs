use rusqlite::{Connection, Result};

/// 镜像模板信息
pub struct Image {
    pub id: i64,
    pub name: String,
    pub image: String,
    pub description: Option<String>,
    pub is_default: bool,
    pub created_at: String,
}

/// 初始化 SQLite 数据库。
///
/// - 自动创建父目录
/// - 开启 WAL 模式、外键约束、busy_timeout
/// - 创建 `users`、`sessions`、`audit_log`、`images` 表（如不存在）
pub fn init(path: &str) -> Result<Connection> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;

         CREATE TABLE IF NOT EXISTS users (
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

         CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

         -- 创建 audit_log 表
         CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );

         -- 创建 images 表（镜像模板管理）
         CREATE TABLE IF NOT EXISTS images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            image TEXT NOT NULL UNIQUE,
            description TEXT,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
         );
        ",
    )?;
    Ok(conn)
}

/// 列出所有镜像模板
pub fn list_images(conn: &Connection) -> Result<Vec<Image>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, image, description, is_default, created_at FROM images ORDER BY is_default DESC, created_at DESC"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(Image {
            id: row.get(0)?,
            name: row.get(1)?,
            image: row.get(2)?,
            description: row.get(3)?,
            is_default: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
        })
    })?;
    rows.collect()
}

/// 创建新镜像模板
pub fn create_image(
    conn: &Connection,
    name: &str,
    image: &str,
    description: Option<&str>,
    is_default: bool,
) -> Result<i64> {
    // 如果设置为默认，先清除其他默认标记
    if is_default {
        conn.execute("UPDATE images SET is_default = 0", [])?;
    }
    conn.execute(
        "INSERT INTO images (name, image, description, is_default) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, image, description, is_default as i32],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 删除镜像模板
pub fn delete_image(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM images WHERE id = ?1", rusqlite::params![id])?;
    Ok(())
}

/// 设置默认镜像
pub fn set_default_image(conn: &Connection, id: i64) -> Result<()> {
    conn.execute_batch(&format!(
        "UPDATE images SET is_default = 0; UPDATE images SET is_default = 1 WHERE id = {};",
        id
    ))?;
    Ok(())
}

/// 获取默认镜像
pub fn get_default_image(conn: &Connection) -> Result<Option<Image>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, image, description, is_default, created_at FROM images WHERE is_default = 1 LIMIT 1"
    )?;
    let mut rows = stmt.query_map([], |row| {
        Ok(Image {
            id: row.get(0)?,
            name: row.get(1)?,
            image: row.get(2)?,
            description: row.get(3)?,
            is_default: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
        })
    })?;
    match rows.next() {
        Some(Ok(img)) => Ok(Some(img)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// 根据 ID 获取镜像
pub fn get_image_by_id(conn: &Connection, id: i64) -> Result<Option<Image>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, image, description, is_default, created_at FROM images WHERE id = ?1 LIMIT 1"
    )?;
    let mut rows = stmt.query_map(rusqlite::params![id], |row| {
        Ok(Image {
            id: row.get(0)?,
            name: row.get(1)?,
            image: row.get(2)?,
            description: row.get(3)?,
            is_default: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
        })
    })?;
    match rows.next() {
        Some(Ok(img)) => Ok(Some(img)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// 初始化默认镜像（从环境变量 CS_IMAGE 读取）
pub fn ensure_default_image(conn: &Connection, default_image: &str) -> Result<()> {
    let images = list_images(conn)?;
    if images.is_empty() {
        // 没有镜像，插入默认镜像
        create_image(
            conn,
            "默认镜像",
            default_image,
            Some("系统默认镜像，从 CS_IMAGE 环境变量读取"),
            true,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                image TEXT NOT NULL UNIQUE,
                description TEXT,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );"
        ).unwrap();
        conn
    }

    #[test]
    fn test_create_and_list_images() {
        let conn = setup_test_db();
        
        // 创建两个镜像
        let id1 = create_image(&conn, "默认镜像", "codercom/code-server:latest", Some("系统默认"), true).unwrap();
        let id2 = create_image(&conn, "Python 环境", "python:3.11", Some("Python 开发环境"), false).unwrap();
        
        assert!(id1 > 0);
        assert!(id2 > 0);
        
        // 列出所有镜像
        let images = list_images(&conn).unwrap();
        assert_eq!(images.len(), 2);
        
        // 默认镜像应该排在第一位
        assert!(images[0].is_default);
        assert_eq!(images[0].name, "默认镜像");
        assert_eq!(images[0].image, "codercom/code-server:latest");
        
        // 第二个镜像不是默认
        assert!(!images[1].is_default);
        assert_eq!(images[1].name, "Python 环境");
    }

    #[test]
    fn test_set_default_image() {
        let conn = setup_test_db();
        
        let id1 = create_image(&conn, "镜像1", "image1:latest", None, true).unwrap();
        let id2 = create_image(&conn, "镜像2", "image2:latest", None, false).unwrap();
        
        // 初始状态：id1 是默认
        let default = get_default_image(&conn).unwrap().unwrap();
        assert_eq!(default.id, id1);
        
        // 设置 id2 为默认
        set_default_image(&conn, id2).unwrap();
        
        // 现在 id2 应该是默认
        let default = get_default_image(&conn).unwrap().unwrap();
        assert_eq!(default.id, id2);
        
        // id1 不再是默认
        let images = list_images(&conn).unwrap();
        let img1 = images.iter().find(|i| i.id == id1).unwrap();
        assert!(!img1.is_default);
    }

    #[test]
    fn test_delete_image() {
        let conn = setup_test_db();
        
        let id = create_image(&conn, "测试镜像", "test:latest", None, false).unwrap();
        assert_eq!(list_images(&conn).unwrap().len(), 1);
        
        delete_image(&conn, id).unwrap();
        assert_eq!(list_images(&conn).unwrap().len(), 0);
    }

    #[test]
    fn test_get_image_by_id() {
        let conn = setup_test_db();
        
        let id = create_image(&conn, "测试镜像", "test:latest", Some("描述"), false).unwrap();
        
        let img = get_image_by_id(&conn, id).unwrap().unwrap();
        assert_eq!(img.id, id);
        assert_eq!(img.name, "测试镜像");
        assert_eq!(img.image, "test:latest");
        assert_eq!(img.description, Some("描述".to_string()));
        assert!(!img.is_default);
        
        // 查询不存在的 ID
        let none = get_image_by_id(&conn, 999).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn test_ensure_default_image() {
        let conn = setup_test_db();
        
        // 初始为空
        assert_eq!(list_images(&conn).unwrap().len(), 0);
        
        // 确保默认镜像存在
        ensure_default_image(&conn, "codercom/code-server:latest").unwrap();
        
        let images = list_images(&conn).unwrap();
        assert_eq!(images.len(), 1);
        assert!(images[0].is_default);
        assert_eq!(images[0].image, "codercom/code-server:latest");
        
        // 再次调用不会创建重复
        ensure_default_image(&conn, "other:latest").unwrap();
        assert_eq!(list_images(&conn).unwrap().len(), 1);
    }

    #[test]
    fn test_duplicate_image_fails() {
        let conn = setup_test_db();
        
        create_image(&conn, "镜像1", "test:latest", None, false).unwrap();
        
        // 重复插入相同 image 应该失败
        let result = create_image(&conn, "镜像2", "test:latest", None, false);
        assert!(result.is_err());
    }
}