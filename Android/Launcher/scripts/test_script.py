"""Small smoke test for the embedded GTA Python runtime."""

from __future__ import annotations

import gta
from gta import entity, player


def main() -> None:
    gta.log("Python runtime started")
    ped = player.ped()
    gta.log(f"Player ped handle: {ped}")
    gta.log(f"Player health: {entity.health(ped)}")
    gta.log(
        f"Player coordinates: {entity.coords(ped).x} {entity.coords(ped).y} {entity.coords(ped).z}"
    )


if __name__ == "__main__":
    main()
