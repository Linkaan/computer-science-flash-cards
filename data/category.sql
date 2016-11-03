create table if not exists categories (
  id integer primary key autoincrement,
  name text not null,
  type tinyint not null
);
INSERT OR IGNORE INTO categories (id, name, type) VALUES (1, "General", 1)
INSERT OR IGNORE INTO categories (id, name, type) VALUES (2, "Code", 2)
