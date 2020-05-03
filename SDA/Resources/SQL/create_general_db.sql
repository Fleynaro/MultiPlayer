create table sda_callnodes
(
    def_id     INTEGER,
    id         INTEGER,
    item_group INTEGER,
    item_id    INTEGER,
    extra      BLOB
);

create table sda_class_fields
(
    class_id    INTEGER,
    rel_offset  INTEGER,
    name        TEXT,
    type_id     INTEGER not null,
    pointer_lvl INTEGER not null,
    array_size  INTEGER not null,
    primary key (class_id, rel_offset)
);

create table sda_class_methods
(
    class_id INTEGER,
    decl_id  INTEGER,
    def_id   INTEGER,
    primary key (class_id, decl_id)
);

create table sda_classes
(
    class_id      INTEGER
        primary key,
    base_class_id INTEGER,
    size          INTEGER,
    vtable_id     INTEGER
);

create table sda_enum_fields
(
    enum_id INTEGER,
    name    TEXT,
    value   INTEGER
);

create table sda_func_arguments
(
    id          INTEGER,
    decl_id     INTEGER,
    name        TEXT,
    type_id     INTEGER not null,
    pointer_lvl INTEGER not null,
    array_size  INTEGER not null,
    primary key (id, decl_id)
);

create table sda_func_decls
(
    decl_id         INTEGER
        primary key autoincrement,
    name            TEXT
        unique,
    role            INTEGER,
    ret_type_id     INTEGER not null,
    ret_pointer_lvl INTEGER not null,
    ret_array_size  INTEGER not null,
    desc            TEXT
);

create table sda_func_defs
(
    def_id  INTEGER
        primary key autoincrement,
    decl_id INTEGER,
    offset  INTEGER
        unique
);

create table sda_func_ranges
(
    def_id     INTEGER,
    order_id   INTEGER,
    min_offset INTEGER,
    max_offset INTEGER
);

create table sda_func_tags
(
    tag_id        INTEGER
        primary key autoincrement,
    parent_tag_id INTEGER,
    decl_id       INTEGER,
    name          TEXT,
    desc          TEXT
);

CREATE TABLE "sda_func_trigger_filters" (
	"trigger_id"	INTEGER,
	"filter_id"	    INTEGER,
	"filter_idx"	INTEGER,
	"data"	BLOB
);

create table sda_gvars
(
    id          INTEGER
        primary key autoincrement,
    name        TEXT,
    offset      INTEGER,
    type_id     INTEGER,
    pointer_lvl INTEGER,
    array_size  INTEGER,
    desc        TEXT
);

CREATE TABLE "sda_trigger_group_triggers" (
	"group_id"	INTEGER,
	"trigger_id"	INTEGER
);

CREATE TABLE "sda_trigger_groups" (
	"group_id"	INTEGER,
	"name"	TEXT,
	"desc"	TEXT,
	PRIMARY KEY("group_id")
);

create table sda_triggers
(
    id   INTEGER
        primary key,
    type INTEGER,
    name TEXT,
    desc TEXT
);

create table sda_typedefs
(
    type_id     INTEGER
        primary key,
    ref_type_id INTEGER,
    pointer_lvl INTEGER,
    array_size  INTEGER
);

create table sda_types
(
    id      INTEGER
        primary key autoincrement,
    "group" INTEGER,
    name    TEXT
        unique,
    desc    TEXT
);
UPDATE SQLITE_SEQUENCE SET seq = 1000 WHERE name = 'sda_types';

create table sda_vtable_funcs
(
    vtable_id INTEGER,
    def_id    INTEGER,
    id        INTEGER,
    primary key (vtable_id, def_id)
);

create table sda_vtables
(
    id     INTEGER
        primary key autoincrement,
    name   TEXT,
    offset INTEGER,
    desc   TEXT
);

