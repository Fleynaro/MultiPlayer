"""Small smoke test for the embedded GTA Python runtime."""

from __future__ import annotations

import debugpy

import gta
from gta import entity, player


def main() -> None:
    gta.log("Python runtime started")
    debugpy.listen(("127.0.0.1", 5678))
    gta.log("debugpy is listening on 127.0.0.1:5678")
    ped = player.ped()
    gta.log(f"Player ped handle: {ped}")
    gta.log(f"Player health: {entity.health(ped)}")


if __name__ == "__main__":
    main()
