"""Strictly typed public API exposed by the Client.dll Python module."""

from typing import Final


class Vector3:
    x: float
    y: float
    z: float

    def __init__(self, x: float, y: float, z: float) -> None: ...


Entity: Final = int
Ped: Final = int
Vehicle: Final = int


def log(message: str, /) -> None: ...
def wait(milliseconds: int, /) -> None: ...
class _PlayerNatives:
    def ped(self) -> Ped: ...


class _EntityNatives:
    def exists(self, entity: Entity, /) -> bool: ...
    def health(self, entity: Entity, /) -> int: ...
    def coords(self, entity: Entity, /) -> Vector3: ...
    def set_coords(self, entity: Entity, coordinates: Vector3, /) -> None: ...


class _PedNatives:
    def create(self, ped_type: int, model_hash: int, coordinates: Vector3, heading: float = 0.0,
               is_network: bool = True, this_script_check: bool = True, /) -> Ped: ...


class _VehicleNatives:
    def create(self, model_hash: int, coordinates: Vector3, heading: float = 0.0,
               is_network: bool = True, this_script_check: bool = True, /) -> Vehicle: ...


player: _PlayerNatives
entity: _EntityNatives
ped: _PedNatives
vehicle: _VehicleNatives
