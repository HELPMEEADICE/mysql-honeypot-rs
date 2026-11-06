// SPDX-License-Identifier: GPL-3.0-only
//! The static half of the fake instance: schemas, tables, columns, seeded rows,
//! system variables and the generated `information_schema` relations.
//!
//! Nothing here is mutated at runtime. A session's writes live in
//! [`super::state::SessionState`]; when that overlay is non-empty the
//! `information_schema` relations are regenerated from the *combined* view so
//! the catalog never contradicts what the session just did.

use crate::protocol::response::column_type;

use super::{FakeColumn, FakeSchema, FakeTable, TableEntry};

/// Build one owned row from string slices.
pub fn row(values: &[&str]) -> Vec<Option<String>> {
    values
        .iter()
        .map(|value| Some((*value).to_string()))
        .collect()
}

fn table(
    name: &str,
    engine: &str,
    comment: &str,
    columns: Vec<FakeColumn>,
    rows: Vec<Vec<Option<String>>>,
) -> FakeTable {
    FakeTable {
        name: name.to_string(),
        engine: engine.to_string(),
        comment: comment.to_string(),
        columns,
        rows,
    }
}

/// Every schema the base catalog advertises, in `SHOW DATABASES` order.
pub fn base_schemas() -> Vec<FakeSchema> {
    vec![
        FakeSchema {
            name: "information_schema".to_string(),
            tables: information_schema_tables(),
        },
        mysql_schema(),
        performance_schema(),
        sys_schema(),
        app_prod_schema(),
        backup_schema(),
    ]
}

/// Session and global variables reported by `SHOW VARIABLES` and `@@name`.
pub fn variables(version: &str) -> Vec<(String, String)> {
    let entries: &[(&str, &str)] = &[
        ("version", version),
        ("version_comment", "MySQL Community Server - GPL"),
        ("version_compile_os", "Linux"),
        ("version_compile_machine", "x86_64"),
        ("protocol_version", "10"),
        ("hostname", "db-prod-01"),
        ("port", "3306"),
        ("socket", "/var/lib/mysql/mysql.sock"),
        ("datadir", "/var/lib/mysql/"),
        ("basedir", "/usr/"),
        ("tmpdir", "/tmp"),
        ("innodb_version", version),
        ("character_set_server", "utf8mb4"),
        ("character_set_client", "utf8mb4"),
        ("character_set_connection", "utf8mb4"),
        ("character_set_results", "utf8mb4"),
        ("collation_server", "utf8mb4_0900_ai_ci"),
        ("collation_connection", "utf8mb4_0900_ai_ci"),
        ("max_connections", "151"),
        ("max_allowed_packet", "67108864"),
        ("max_connect_errors", "100"),
        ("wait_timeout", "28800"),
        ("interactive_timeout", "28800"),
        ("net_write_timeout", "60"),
        ("net_read_timeout", "30"),
        (
            "sql_mode",
            "ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,\
             ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION",
        ),
        ("lower_case_table_names", "0"),
        ("system_time_zone", "UTC"),
        ("time_zone", "SYSTEM"),
        ("transaction_isolation", "REPEATABLE-READ"),
        ("tx_isolation", "REPEATABLE-READ"),
        ("autocommit", "ON"),
        ("have_ssl", "DISABLED"),
        ("have_openssl", "DISABLED"),
        ("license", "GPL"),
        ("server_id", "1"),
        ("auto_increment_increment", "1"),
        ("auto_increment_offset", "1"),
        ("default_storage_engine", "InnoDB"),
        ("secure_auth", "ON"),
        ("local_infile", "OFF"),
        ("skip_networking", "OFF"),
        ("pid_file", "/var/run/mysqld/mysqld.pid"),
        ("log_error", "/var/log/mysql/error.log"),
        ("performance_schema", "ON"),
        ("innodb_buffer_pool_size", "134217728"),
        ("default_authentication_plugin", "caching_sha2_password"),
    ];
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// Values reported by `SHOW STATUS`.
pub fn status_variables() -> Vec<(String, String)> {
    let entries: &[(&str, &str)] = &[
        ("Uptime", "864000"),
        ("Threads_connected", "3"),
        ("Threads_running", "1"),
        ("Threads_created", "12"),
        ("Connections", "1842"),
        ("Aborted_connects", "7"),
        ("Questions", "91234"),
        ("Slow_queries", "0"),
        ("Queries_per_second_avg", "0.105"),
        ("Bytes_received", "8842133"),
        ("Bytes_sent", "192834771"),
        ("Innodb_buffer_pool_reads", "1283"),
        ("Innodb_rows_read", "99213"),
        ("Com_select", "81233"),
        ("Com_insert", "412"),
        ("Com_update", "98"),
        ("Com_delete", "21"),
        ("Open_tables", "112"),
        ("Opened_tables", "1533"),
        ("Table_locks_waited", "0"),
        ("Ssl_cipher", ""),
    ];
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

/// The `information_schema` relations, with column definitions and no rows.
pub fn information_schema_tables() -> Vec<FakeTable> {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    vec![
        table(
            "SCHEMATA",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CATALOG_NAME", "varchar(512)", string),
                FakeColumn::new("SCHEMA_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_COLLATION_NAME", "varchar(64)", string),
                FakeColumn::new("SQL_PATH", "varchar(512)", string),
                FakeColumn::new("DEFAULT_ENCRYPTION", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "TABLES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("TABLE_TYPE", "varchar(64)", string),
                FakeColumn::new("ENGINE", "varchar(64)", string),
                FakeColumn::new("VERSION", "int", number),
                FakeColumn::new("ROW_FORMAT", "varchar(10)", string),
                FakeColumn::new("TABLE_ROWS", "bigint unsigned", number),
                FakeColumn::new("AVG_ROW_LENGTH", "bigint unsigned", number),
                FakeColumn::new("DATA_LENGTH", "bigint unsigned", number),
                FakeColumn::new("MAX_DATA_LENGTH", "bigint unsigned", number),
                FakeColumn::new("INDEX_LENGTH", "bigint unsigned", number),
                FakeColumn::new("DATA_FREE", "bigint unsigned", number),
                FakeColumn::new("AUTO_INCREMENT", "bigint unsigned", number),
                FakeColumn::new("CREATE_TIME", "datetime", string),
                FakeColumn::new("UPDATE_TIME", "datetime", string),
                FakeColumn::new("CHECK_TIME", "datetime", string),
                FakeColumn::new("TABLE_COLLATION", "varchar(64)", string),
                FakeColumn::new("CHECKSUM", "bigint", number),
                FakeColumn::new("CREATE_OPTIONS", "varchar(256)", string),
                FakeColumn::new("TABLE_COMMENT", "text", string),
            ],
            Vec::new(),
        ),
        table(
            "COLUMNS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("ORDINAL_POSITION", "bigint unsigned", number),
                FakeColumn::new("COLUMN_DEFAULT", "text", string),
                FakeColumn::new("IS_NULLABLE", "varchar(3)", string),
                FakeColumn::new("DATA_TYPE", "varchar(64)", string),
                FakeColumn::new("CHARACTER_MAXIMUM_LENGTH", "bigint", number),
                FakeColumn::new("CHARACTER_OCTET_LENGTH", "bigint", number),
                FakeColumn::new("NUMERIC_PRECISION", "bigint unsigned", number),
                FakeColumn::new("NUMERIC_SCALE", "bigint unsigned", number),
                FakeColumn::new("DATETIME_PRECISION", "int unsigned", number),
                FakeColumn::new("CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("COLLATION_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_TYPE", "text", string),
                FakeColumn::new("COLUMN_KEY", "varchar(3)", string),
                FakeColumn::new("EXTRA", "varchar(256)", string),
                FakeColumn::new("PRIVILEGES", "varchar(154)", string),
                FakeColumn::new("COLUMN_COMMENT", "text", string),
                FakeColumn::new("GENERATION_EXPRESSION", "text", string),
            ],
            Vec::new(),
        ),
        table(
            "STATISTICS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("NON_UNIQUE", "int", number),
                FakeColumn::new("INDEX_SCHEMA", "varchar(64)", string),
                FakeColumn::new("INDEX_NAME", "varchar(64)", string),
                FakeColumn::new("SEQ_IN_INDEX", "bigint unsigned", number),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("COLLATION", "varchar(1)", string),
                FakeColumn::new("CARDINALITY", "bigint", number),
                FakeColumn::new("SUB_PART", "bigint", number),
                FakeColumn::new("PACKED", "varchar(10)", string),
                FakeColumn::new("NULLABLE", "varchar(3)", string),
                FakeColumn::new("INDEX_TYPE", "varchar(16)", string),
                FakeColumn::new("COMMENT", "varchar(16)", string),
            ],
            Vec::new(),
        ),
        table(
            "ENGINES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("ENGINE", "varchar(64)", string),
                FakeColumn::new("SUPPORT", "varchar(8)", string),
                FakeColumn::new("COMMENT", "varchar(80)", string),
                FakeColumn::new("TRANSACTIONS", "varchar(3)", string),
                FakeColumn::new("XA", "varchar(3)", string),
                FakeColumn::new("SAVEPOINTS", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "PROCESSLIST",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("ID", "bigint unsigned", number),
                FakeColumn::new("USER", "varchar(32)", string),
                FakeColumn::new("HOST", "varchar(261)", string),
                FakeColumn::new("DB", "varchar(64)", string),
                FakeColumn::new("COMMAND", "varchar(16)", string),
                FakeColumn::new("TIME", "int", number),
                FakeColumn::new("STATE", "varchar(64)", string),
                FakeColumn::new("INFO", "longtext", string),
            ],
            Vec::new(),
        ),
        table(
            "USER_PRIVILEGES",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("GRANTEE", "varchar(292)", string),
                FakeColumn::new("TABLE_CATALOG", "varchar(512)", string),
                FakeColumn::new("PRIVILEGE_TYPE", "varchar(64)", string),
                FakeColumn::new("IS_GRANTABLE", "varchar(3)", string),
            ],
            Vec::new(),
        ),
        table(
            "CHARACTER_SETS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CHARACTER_SET_NAME", "varchar(64)", string),
                FakeColumn::new("DEFAULT_COLLATE_NAME", "varchar(64)", string),
                FakeColumn::new("DESCRIPTION", "varchar(60)", string),
                FakeColumn::new("MAXLEN", "int", number),
            ],
            Vec::new(),
        ),
        table(
            "KEY_COLUMN_USAGE",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("CONSTRAINT_CATALOG", "varchar(64)", string),
                FakeColumn::new("CONSTRAINT_SCHEMA", "varchar(64)", string),
                FakeColumn::new("CONSTRAINT_NAME", "varchar(64)", string),
                FakeColumn::new("TABLE_CATALOG", "varchar(64)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("COLUMN_NAME", "varchar(64)", string),
                FakeColumn::new("ORDINAL_POSITION", "bigint unsigned", number),
                FakeColumn::new("POSITION_IN_UNIQUE_CONSTRAINT", "bigint unsigned", number),
                FakeColumn::new("REFERENCED_TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("REFERENCED_TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("REFERENCED_COLUMN_NAME", "varchar(64)", string),
            ],
            Vec::new(),
        ),
        table(
            "VIEWS",
            "MEMORY",
            "",
            vec![
                FakeColumn::new("TABLE_CATALOG", "varchar(64)", string),
                FakeColumn::new("TABLE_SCHEMA", "varchar(64)", string),
                FakeColumn::new("TABLE_NAME", "varchar(64)", string),
                FakeColumn::new("VIEW_DEFINITION", "longtext", string),
            ],
            Vec::new(),
        ),
    ]
}

/// Regenerate the rows of one `information_schema` relation from the current
/// catalog view (`schemas` plus `tables`, overlay included).
pub fn information_schema_rows(
    relation: &str,
    schemas: &[&str],
    tables: &[TableEntry<'_>],
    username: &str,
) -> Option<Vec<Vec<Option<String>>>> {
    match relation {
        "SCHEMATA" => Some(
            schemas
                .iter()
                .map(|name| row(&["def", name, "utf8mb4", "utf8mb4_0900_ai_ci", "", "NO"]))
                .collect(),
        ),
        "TABLES" => {
            let mut rows = Vec::new();
            for entry in tables {
                rows.push(row(&[
                    "def",
                    entry.schema,
                    &entry.table.name,
                    "BASE TABLE",
                    &entry.table.engine,
                    "10",
                    "Dynamic",
                    &(8 + entry.table.rows.len() * 3).to_string(),
                    "16384",
                    "16384",
                    "0",
                    "0",
                    "0",
                    "16",
                    "2024-01-01 00:00:00",
                    "",
                    "",
                    "utf8mb4_0900_ai_ci",
                    "0",
                    "",
                    &entry.table.comment,
                ]));
            }
            Some(rows)
        }
        "COLUMNS" => {
            let mut rows = Vec::new();
            for entry in tables {
                for (index, column) in entry.table.columns.iter().enumerate() {
                    rows.push(row(&[
                        "def",
                        entry.schema,
                        &entry.table.name,
                        &column.name,
                        &(index + 1).to_string(),
                        column.default.as_deref().unwrap_or("NULL"),
                        if column.nullable { "YES" } else { "NO" },
                        &column.data_type,
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                        "utf8mb4",
                        "utf8mb4_0900_ai_ci",
                        &column.data_type,
                        &column.key,
                        &column.extra,
                        "select,insert,update,references",
                        "",
                        "",
                    ]));
                }
            }
            Some(rows)
        }
        "STATISTICS" => {
            let mut rows = Vec::new();
            for entry in tables {
                for column in entry.table.columns.iter().filter(|c| !c.key.is_empty()) {
                    rows.push(row(&[
                        "def",
                        entry.schema,
                        &entry.table.name,
                        "0",
                        entry.schema,
                        "PRIMARY",
                        "1",
                        &column.name,
                        "A",
                        "0",
                        "NULL",
                        "",
                        "YES",
                        "BTREE",
                        "",
                    ]));
                }
            }
            Some(rows)
        }
        "KEY_COLUMN_USAGE" => {
            let mut rows = Vec::new();
            for entry in tables {
                for column in entry.table.columns.iter().filter(|c| !c.key.is_empty()) {
                    rows.push(row(&[
                        "def",
                        entry.schema,
                        "PRIMARY",
                        "def",
                        entry.schema,
                        &entry.table.name,
                        &column.name,
                        "1",
                        "NULL",
                        "",
                        "",
                        "",
                    ]));
                }
            }
            Some(rows)
        }
        "USER_PRIVILEGES" => {
            let owner = crate::util::clip(username, 64);
            let grantee = format!("'{owner}'@'%'");
            Some(
                [
                    "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "FILE",
                ]
                .iter()
                .map(|privilege| row(&[grantee.as_str(), "def", privilege, "NO"]))
                .collect(),
            )
        }
        "PROCESSLIST" => {
            let owner = crate::util::clip(username, 64);
            Some(vec![row(&[
                "1",
                owner.as_str(),
                "localhost:3306",
                "app_prod",
                "Sleep",
                "0",
                "",
                "",
            ])])
        }
        "ENGINES" => Some(vec![
            row(&[
                "InnoDB",
                "DEFAULT",
                "Supports transactions, row-level locking, and foreign keys",
                "YES",
                "YES",
                "YES",
            ]),
            row(&["MyISAM", "YES", "MyISAM storage engine", "NO", "NO", "NO"]),
            row(&[
                "MEMORY",
                "YES",
                "Hash based, stored in memory, useful for temporary tables",
                "NO",
                "NO",
                "NO",
            ]),
            row(&["CSV", "YES", "CSV storage engine", "NO", "NO", "NO"]),
        ]),
        "CHARACTER_SETS" => Some(vec![
            row(&["utf8mb4", "utf8mb4_0900_ai_ci", "UTF-8 Unicode", "4"]),
            row(&["utf8mb3", "utf8mb3_general_ci", "UTF-8 Unicode", "3"]),
            row(&["latin1", "latin1_swedish_ci", "cp1252 West European", "1"]),
            row(&["binary", "binary", "Binary pseudo charset", "1"]),
        ]),
        "VIEWS" => Some(Vec::new()),
        _ => None,
    }
}

/// The account name a session's privilege views should mention.
fn _unused_owner_removed() {}

fn mysql_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "mysql".to_string(),
        tables: vec![
            table(
                "user",
                "InnoDB",
                "Users and global privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string).not_null(),
                    FakeColumn::new("User", "char(32)", string).not_null(),
                    FakeColumn::new("Select_priv", "enum('N','Y')", string),
                    FakeColumn::new("Insert_priv", "enum('N','Y')", string),
                    FakeColumn::new("Update_priv", "enum('N','Y')", string),
                    FakeColumn::new("Delete_priv", "enum('N','Y')", string),
                    FakeColumn::new("Create_priv", "enum('N','Y')", string),
                    FakeColumn::new("Drop_priv", "enum('N','Y')", string),
                    FakeColumn::new("plugin", "char(64)", string),
                    FakeColumn::new("authentication_string", "text", string),
                ],
                vec![
                    row(&[
                        "localhost",
                        "root",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "caching_sha2_password",
                        "$A$005$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                    ]),
                    row(&[
                        "%",
                        "root",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "Y",
                        "caching_sha2_password",
                        "$A$005$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                    ]),
                    row(&[
                        "%",
                        "app",
                        "Y",
                        "Y",
                        "Y",
                        "N",
                        "N",
                        "N",
                        "mysql_native_password",
                        "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
                    ]),
                ],
            ),
            table(
                "db",
                "InnoDB",
                "Database privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Select_priv", "enum('N','Y')", string),
                    FakeColumn::new("Insert_priv", "enum('N','Y')", string),
                ],
                vec![
                    row(&["%", "app_prod", "app", "Y", "Y"]),
                    row(&["%", "backup", "app", "Y", "N"]),
                ],
            ),
            table(
                "tables_priv",
                "InnoDB",
                "Table privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Table_name", "char(64)", string),
                    FakeColumn::new(
                        "Table_priv",
                        "set('Select','Insert','Update','Delete')",
                        string,
                    ),
                ],
                vec![row(&[
                    "%",
                    "app_prod",
                    "app",
                    "users",
                    "Select,Insert,Update",
                ])],
            ),
            table(
                "columns_priv",
                "InnoDB",
                "Column privileges",
                vec![
                    FakeColumn::new("Host", "char(255)", string),
                    FakeColumn::new("Db", "char(64)", string),
                    FakeColumn::new("User", "char(32)", string),
                    FakeColumn::new("Table_name", "char(64)", string),
                    FakeColumn::new("Column_name", "char(64)", string),
                ],
                Vec::new(),
            ),
            table(
                "proc",
                "InnoDB",
                "Stored procedures",
                vec![
                    FakeColumn::new("db", "char(64)", string),
                    FakeColumn::new("name", "char(64)", string),
                    FakeColumn::new("type", "enum('FUNCTION','PROCEDURE')", string),
                ],
                Vec::new(),
            ),
            table(
                "func",
                "InnoDB",
                "User defined functions",
                vec![
                    FakeColumn::new("name", "char(64)", string),
                    FakeColumn::new("ret", "tinyint", number),
                ],
                Vec::new(),
            ),
        ],
    }
}

fn performance_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "performance_schema".to_string(),
        tables: vec![
            table(
                "threads",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("THREAD_ID", "bigint unsigned", number),
                    FakeColumn::new("NAME", "varchar(128)", string),
                    FakeColumn::new("TYPE", "varchar(10)", string),
                    FakeColumn::new("PROCESSLIST_ID", "bigint unsigned", number),
                    FakeColumn::new("PROCESSLIST_USER", "varchar(32)", string),
                    FakeColumn::new("PROCESSLIST_HOST", "varchar(261)", string),
                    FakeColumn::new("PROCESSLIST_DB", "varchar(64)", string),
                ],
                vec![
                    row(&[
                        "1",
                        "thread/sql/main",
                        "BACKGROUND",
                        "NULL",
                        "NULL",
                        "NULL",
                        "NULL",
                    ]),
                    row(&[
                        "42",
                        "thread/sql/one_connection",
                        "FOREGROUND",
                        "9",
                        "app",
                        "localhost",
                        "app_prod",
                    ]),
                ],
            ),
            table(
                "global_status",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("VARIABLE_NAME", "varchar(64)", string),
                    FakeColumn::new("VARIABLE_VALUE", "varchar(1024)", string),
                ],
                vec![
                    row(&["Uptime", "864000"]),
                    row(&["Threads_connected", "3"]),
                    row(&["Questions", "91234"]),
                ],
            ),
            table(
                "events_statements_summary_by_digest",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("SCHEMA_NAME", "varchar(64)", string),
                    FakeColumn::new("DIGEST_TEXT", "longtext", string),
                    FakeColumn::new("COUNT_STAR", "bigint unsigned", number),
                ],
                vec![
                    row(&["app_prod", "SELECT * FROM `users` WHERE `id` = ?", "812"]),
                    row(&[
                        "app_prod",
                        "SELECT * FROM `orders` WHERE `user_id` = ?",
                        "2331",
                    ]),
                ],
            ),
            table(
                "setup_consumers",
                "PERFORMANCE_SCHEMA",
                "",
                vec![
                    FakeColumn::new("NAME", "varchar(64)", string),
                    FakeColumn::new("ENABLED", "enum('YES','NO')", string),
                ],
                vec![row(&["global_instrumentation", "YES"])],
            ),
        ],
    }
}

fn sys_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "sys".to_string(),
        tables: vec![
            table(
                "version",
                "InnoDB",
                "Sys schema version",
                vec![
                    FakeColumn::new("sys_version", "varchar(128)", string),
                    FakeColumn::new("mysql_version", "varchar(128)", string),
                ],
                vec![row(&["2.1.1", "8.0.36"])],
            ),
            table(
                "schema_table_statistics",
                "InnoDB",
                "",
                vec![
                    FakeColumn::new("table_schema", "varchar(64)", string),
                    FakeColumn::new("table_name", "varchar(64)", string),
                    FakeColumn::new("total_latency", "varchar(11)", string),
                    FakeColumn::new("rows_fetched", "bigint unsigned", number),
                ],
                vec![
                    row(&["app_prod", "users", "1.23 s", "812"]),
                    row(&["app_prod", "orders", "3.11 s", "2331"]),
                ],
            ),
        ],
    }
}

fn app_prod_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    let decimal = column_type::DOUBLE;
    let datetime = column_type::DATETIME;
    FakeSchema {
        name: "app_prod".to_string(),
        tables: vec![
            table(
                "users",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("username", "varchar(64)", string),
                    FakeColumn::new("password", "varchar(255)", string),
                    FakeColumn::new("email", "varchar(128)", string),
                    FakeColumn::new("role", "varchar(32)", string),
                    FakeColumn::new("created_at", "datetime", datetime),
                ],
                vec![
                    row(&[
                        "1",
                        "admin",
                        "$2y$10$Qm9ndXNDb25jYXZlbm9uY2UwMTIzNDU2Nzg5",
                        "admin@example.com",
                        "administrator",
                        "2023-04-11 08:12:41",
                    ]),
                    row(&[
                        "2",
                        "alice",
                        "$2y$10$YWxpY2Vub25jZTAxMjM0NTY3ODkwYWJjZGVm",
                        "alice@example.com",
                        "user",
                        "2023-06-02 14:33:07",
                    ]),
                    row(&[
                        "3",
                        "bob",
                        "$2y$10$Ym9ibm9uY2UwMTIzNDU2Nzg5MGFiY2RlZmdo",
                        "bob@example.com",
                        "user",
                        "2023-11-19 22:05:55",
                    ]),
                ],
            ),
            table(
                "orders",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("amount", "decimal(10,2)", decimal),
                    FakeColumn::new("status", "varchar(32)", string),
                    FakeColumn::new("created_at", "datetime", datetime),
                ],
                vec![
                    row(&["1001", "1", "199.00", "paid", "2024-01-03 10:11:12"]),
                    row(&["1002", "2", "49.90", "paid", "2024-01-04 11:22:33"]),
                    row(&["1003", "3", "0.00", "refunded", "2024-02-15 09:00:01"]),
                ],
            ),
            table(
                "sessions",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("token", "varchar(128)", string),
                    FakeColumn::new("ip", "varchar(45)", string),
                ],
                vec![
                    row(&["9001", "1", "b7f1c0a1d9e04f4a8f4d0a5b6c7d8e9f", "10.0.0.5"]),
                    row(&["9002", "2", "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "10.0.0.9"]),
                ],
            ),
            table(
                "products",
                "InnoDB",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("sku", "varchar(64)", string),
                    FakeColumn::new("name", "varchar(128)", string),
                    FakeColumn::new("price", "decimal(10,2)", decimal),
                    FakeColumn::new("stock", "int", number),
                ],
                vec![
                    row(&["11", "SKU-1001", "Starter plan", "9.90", "999"]),
                    row(&["12", "SKU-1002", "Pro plan", "49.90", "499"]),
                ],
            ),
        ],
    }
}

fn backup_schema() -> FakeSchema {
    let string = column_type::VAR_STRING;
    let number = column_type::LONGLONG;
    FakeSchema {
        name: "backup".to_string(),
        tables: vec![
            table(
                "users_backup",
                "MyISAM",
                "nightly dump",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("username", "varchar(64)", string),
                    FakeColumn::new("password_hash", "varchar(255)", string),
                    FakeColumn::new("created_at", "datetime", string),
                ],
                vec![
                    row(&[
                        "1",
                        "admin",
                        "5f4dcc3b5aa765d61d8327deb882cf99",
                        "2023-04-11 08:12:41",
                    ]),
                    row(&[
                        "2",
                        "alice",
                        "098f6bcd4621d373cade4e832627b4f6",
                        "2023-06-02 14:33:07",
                    ]),
                    row(&[
                        "3",
                        "bob",
                        "e10adc3949ba59abbe56e057f20f883e",
                        "2023-11-19 22:05:55",
                    ]),
                ],
            ),
            table(
                "orders_2024",
                "MyISAM",
                "",
                vec![
                    FakeColumn::primary("id", "bigint unsigned", number),
                    FakeColumn::new("user_id", "bigint unsigned", number),
                    FakeColumn::new("amount", "decimal(10,2)", column_type::DOUBLE),
                    FakeColumn::new("status", "varchar(32)", string),
                ],
                vec![
                    row(&["1001", "1", "199.00", "paid"]),
                    row(&["1002", "2", "49.90", "paid"]),
                ],
            ),
        ],
    }
}
