create table sda_callnodes
(
    function_id INTEGER,
    id          INTEGER,
    item_group  INTEGER,
    item_id     INTEGER,
    extra       BLOB
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
    class_id    INTEGER,
    function_id INTEGER,
    primary key (class_id, function_id)
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
    function_id INTEGER,
    name        TEXT,
    type_id     INTEGER not null,
    pointer_lvl INTEGER not null,
    array_size  INTEGER not null,
    primary key (id, function_id)
);

create table sda_func_ranges
(
    function_id INTEGER,
    order_id    INTEGER,
    min_offset  INTEGER,
    max_offset  INTEGER
);

create table sda_func_trigger_filters
(
    trigger_id INTEGER,
    filter_id  INTEGER,
    data       BLOB
);

create table sda_functions
(
    id              INTEGER
        primary key autoincrement,
    name            TEXT
        unique,
    method          INTEGER,
    offset          INTEGER
        unique,
    ret_type_id     INTEGER not null,
    ret_pointer_lvl INTEGER not null,
    ret_array_size  INTEGER not null,
    desc            TEXT
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

create table sda_vtable_funcs
(
    vtable_id   INTEGER,
    function_id INTEGER,
    id          INTEGER,
    primary key (vtable_id, function_id)
);

create table sda_vtables
(
    id     INTEGER
        primary key autoincrement,
    name   TEXT,
    offset INTEGER,
    desc   TEXT
);

