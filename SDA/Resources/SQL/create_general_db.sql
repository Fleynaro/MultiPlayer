create table sda_saves
(
    save_id         INTEGER
        primary key autoincrement,
    date            INTEGER,
    insertsCount    INTEGER,
    updatesCount    INTEGER,
    deletesCount    INTEGER
);

create table sda_ghidra_sync
(
    sync_id         INTEGER
        primary key autoincrement,
    date            INTEGER,
    type            INTEGER,
    comment         TEXT,
    objectsCount    INTEGER
);

CREATE TABLE "sda_address_spaces" (
	"as_id"	        INTEGER,
	"name"	        TEXT,
	"comment"	    TEXT,
    "save_id"	    INTEGER,
	PRIMARY KEY("as_id")
);

CREATE TABLE "sda_images" (
	"image_id"	            INTEGER,
    "type"	                INTEGER,
	"name"	                TEXT,
	"comment"	            TEXT,
    "addr_space_id"         INTEGER,
    "global_table_id"       INTEGER,
    "vfunc_call_table_id"   INTEGER,
    "save_id"	            INTEGER,
	PRIMARY KEY("image_id")
);

CREATE TABLE "sda_symbols"
(
	"symbol_id"	            INTEGER PRIMARY KEY AUTOINCREMENT,
    "type"                  INTEGER,
	"name"	                TEXT,
	"type_id"	            INTEGER NOT NULL,
	"pointer_lvl"	        TEXT,
	"comment"	            TEXT,
    "json_extra"            TEXT,
	"save_id"	            INTEGER,
	"ghidra_sync_id"	    INTEGER,
	"deleted"	            INTEGER DEFAULT 0
);

CREATE TABLE "sda_mem_area_symbols" (
	"symbol_id"	        INTEGER,
	"mem_area_id"	    INTEGER,
	"offset"	        INTEGER,
	PRIMARY KEY("mem_area_id","symbol_id","offset")
);

CREATE TABLE "sda_mem_areas" (
	"mem_area_id"	INTEGER,
	"type"	        INTEGER,
    "size"          INTEGER,
    "save_id"	    INTEGER,
    "deleted"	    INTEGER DEFAULT 0,
	PRIMARY KEY("mem_area_id")
);


create table sda_struct_fields
(
    struct_id       INTEGER,
    symbol_id       INTEGER,
    primary key (struct_id, symbol_id)
);

create table sda_class_methods
(
    struct_id   INTEGER,
    func_id     INTEGER,
    primary key (struct_id, func_id)
);

create table sda_structures
(
    struct_id       INTEGER
        primary key,
    size            INTEGER
);

create table sda_classes
(
    struct_id       INTEGER
        primary key,
    base_struct_id  INTEGER,
    vtable_id       INTEGER
);

create table sda_enum_fields
(
    enum_id INTEGER,
    name    TEXT,
    value   INTEGER
);

create table sda_signature_storages
(
    signature_id        INTEGER,
    idx                 INTEGER,
    storage_type        INTEGER,
    register_id         INTEGER,
    offset              INTEGER
);

create table sda_signature_params
(
    order_id            INTEGER,
    signature_id        INTEGER,
    param_symbol_id     INTEGER,
    primary key (order_id, signature_id)
);

create table sda_signatures
(
    signature_id         INTEGER
        primary key,
    calling_convention   INTEGER not null,
    ret_type_id     INTEGER not null,
    ret_pointer_lvl TEXT
);

create table sda_functions
(
    func_id  INTEGER
        primary key autoincrement,
    func_symbol_id  INTEGER
        unique,
    signature_id        INTEGER,
    module_id           INTEGER,
    stack_mem_area_id   INTEGER DEFAULT 0,
    body_mem_area_id    INTEGER DEFAULT 0,
    exported            INTEGER,
    save_id             INTEGER,
    ghidra_sync_id      INTEGER,
    deleted             INTEGER DEFAULT 0
);

CREATE TABLE "sda_func_trigger_filters" (
	"trigger_id"	INTEGER,
	"filter_id"	    INTEGER,
	"filter_idx"	INTEGER,
	"data"	BLOB
);

CREATE TABLE "sda_trigger_group_triggers" (
	"group_id"	    INTEGER,
	"trigger_id"	INTEGER
);

CREATE TABLE "sda_trigger_groups" (
	"group_id"	INTEGER
        primary key autoincrement,
	"name"	    TEXT,
	"desc"	    TEXT
);

create table sda_triggers
(
    trigger_id   INTEGER
        primary key autoincrement,
    type        INTEGER,
    name        TEXT,
    desc        TEXT
);

create table sda_typedefs
(
    type_id     INTEGER
        primary key,
    ref_type_id INTEGER,
    pointer_lvl TEXT
);

create table sda_types
(
    id                  INTEGER
        primary key autoincrement,
    "group" INTEGER,
    name                TEXT
        unique,
    desc                TEXT,
    save_id             INTEGER,
    ghidra_sync_id      INTEGER,
    deleted             INTEGER DEFAULT 0
);
INSERT INTO sda_types (name) VALUES ('reserved');
UPDATE SQLITE_SEQUENCE SET seq=1000 WHERE name='sda_types';