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