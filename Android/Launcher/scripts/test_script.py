"""Small smoke test for the embedded GTA Python runtime."""

from __future__ import annotations

import gta
from gta import entity, player


def main() -> None:
    gta.log("Python runtime started")
    ped = player.get_player_ped(-1)
    gta.log(f"Player ped handle: {ped}")
    gta.log(f"Player health: {entity.get_entity_health(ped)}")
    gta.log(
        f"Player coordinates: {entity.get_entity_coords(ped).x} {entity.get_entity_coords(ped).y} {entity.get_entity_coords(ped).z}"
    )


if __name__ == "__main__":
    main()
