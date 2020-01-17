create table sda_call_after
(
    id            INTEGER
        primary key,
    ret_value     INTEGER,
    ret_xmm_value INTEGER,
    elapsed_time  INTEGER
);

create table sda_call_args
(
    call_id INTEGER,
    id      INTEGER,
    value   INTEGER,
    primary key (call_id, id)
);

create table sda_call_before
(
    id          INTEGER
        primary key,
    function_id INTEGER,
    trigger_id  INTEGER
);

