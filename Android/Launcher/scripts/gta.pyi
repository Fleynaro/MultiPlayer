"""Strictly typed public API exposed by the Client.dll Python module."""

class Vector3:
    x: float
    y: float
    z: float

    def __init__(self, x: float, y: float, z: float) -> None: ...

Entity = int
Ped = int
Vehicle = int
Object = int
Pickup = int
Blip = int
Hash = int

def log(message: str, /) -> None: ...
def wait(milliseconds: int, /) -> None: ...
def stop_requested() -> bool: ...

class _EntityNatives:
    """APPLY_FORCE_TO_ENTITY: Provides the apply force to entity native operation."""
    @staticmethod
    def apply_force_to_entity(
        entity: Entity,
        forceType: int,
        x: float,
        y: float,
        z: float,
        offX: float,
        offY: float,
        offZ: float,
        nComponent: int,
        bLocalForce: bool,
        bLocalOffset: bool,
        bScaleByMass: bool,
        bPlayAudio: bool,
        bScaleByTimeWarp: bool,
        /,
    ) -> None: ...
    """APPLY_FORCE_TO_ENTITY_CENTER_OF_MASS: Apply a force to an entities center of mass."""
    @staticmethod
    def apply_force_to_entity_center_of_mass(
        entity: Entity,
        forceType: int,
        x: float,
        y: float,
        z: float,
        nComponent: int,
        bLocalForce: bool,
        bScaleByMass: bool,
        bApplyToChildren: bool,
        /,
    ) -> None: ...
    """_ATTACH_ENTITY_BONE_TO_ENTITY_BONE: Provides the attach entity bone to entity bone native operation."""
    @staticmethod
    def _attach_entity_bone_to_entity_bone(
        entity1: Entity,
        entity2: Entity,
        entityBone: int,
        entityBone2: int,
        p4: bool,
        p5: bool,
        /,
    ) -> None: ...
    """_ATTACH_ENTITY_BONE_TO_ENTITY_BONE_PHYSICALLY: Provides the attach entity bone to entity bone physically native operation."""
    @staticmethod
    def _attach_entity_bone_to_entity_bone_physically(
        entity1: Entity,
        entity2: Entity,
        entityBone: int,
        entityBone2: int,
        p4: bool,
        p5: bool,
        /,
    ) -> None: ...
    """ATTACH_ENTITY_TO_ENTITY: Attach an entity to the specified entity."""
    @staticmethod
    def attach_entity_to_entity(
        entity1: Entity,
        entity2: Entity,
        boneIndex: int,
        xPos: float,
        yPos: float,
        zPos: float,
        xRot: float,
        yRot: float,
        zRot: float,
        p9: bool,
        useSoftPinning: bool,
        collision: bool,
        isPed: bool,
        rotationOrder: int,
        syncRot: bool,
        /,
    ) -> None: ...
    """ATTACH_ENTITY_TO_ENTITY_PHYSICALLY: breakForce is the amount of force required to break the bond."""
    @staticmethod
    def attach_entity_to_entity_physically(
        entity1: Entity,
        entity2: Entity,
        boneIndex1: int,
        boneIndex2: int,
        xPos1: float,
        yPos1: float,
        zPos1: float,
        xPos2: float,
        yPos2: float,
        zPos2: float,
        xRot: float,
        yRot: float,
        zRot: float,
        breakForce: float,
        fixedRot: bool,
        p15: bool,
        collision: bool,
        teleport: bool,
        p18: int,
        /,
    ) -> None: ...
    """DELETE_ENTITY: Delete the specified entity, and invalidate the passed handle (i.e., the in/out argument)."""
    @staticmethod
    def delete_entity(entity: int, /) -> tuple[int]: ...
    """DETACH_ENTITY: Provides the detach entity native operation."""
    @staticmethod
    def detach_entity(entity: Entity, dynamic: bool, collision: bool, /) -> None: ...
    """DOES_ENTITY_EXIST: Checks whether an entity exists in the game world."""
    @staticmethod
    def does_entity_exist(entity: Entity, /) -> bool: ...
    """FREEZE_ENTITY_POSITION: Freezes or unfreezes an entity preventing its coordinates to change by the player if set to `true`. You can still change the entity position using [`SET_ENTITY_COORDS`](#_0x06843DA7060A026B)."""
    @staticmethod
    def freeze_entity_position(entity: Entity, toggle: bool, /) -> None: ...
    """GET_COLLISION_NORMAL_OF_LAST_HIT_FOR_ENTITY: Provides the get collision normal of last hit for entity native operation."""
    @staticmethod
    def get_collision_normal_of_last_hit_for_entity(entity: Entity, /) -> Vector3: ...
    """GET_ENTITY_ALPHA: Provides the get entity alpha native operation."""
    @staticmethod
    def get_entity_alpha(entity: Entity, /) -> int: ...
    """GET_ENTITY_ANIM_CURRENT_TIME: Returns a float value representing animation's current playtime with respect to its total playtime. This value increasing in a range from [0 to 1] and wrap back to 0 when it reach 1."""
    @staticmethod
    def get_entity_anim_current_time(
        entity: Entity, animDict: str, animName: str, /
    ) -> float: ...
    """GET_ENTITY_ANIM_TOTAL_TIME: Returns a float value representing animation's total playtime in milliseconds."""
    @staticmethod
    def get_entity_anim_total_time(
        entity: Entity, animDict: str, animName: str, /
    ) -> float: ...
    """GET_ENTITY_ATTACHED_TO: Provides the get entity attached to native operation."""
    @staticmethod
    def get_entity_attached_to(entity: Entity, /) -> int: ...
    """_GET_ENTITY_BONE_COUNT: Provides the get entity bone count native operation."""
    @staticmethod
    def _get_entity_bone_count(entity: Entity, /) -> int: ...
    """GET_ENTITY_BONE_INDEX_BY_NAME: Returns the index of the bone. If the bone was not found, -1 will be returned."""
    @staticmethod
    def get_entity_bone_index_by_name(entity: Entity, boneName: str, /) -> int: ...
    """_GET_ENTITY_BONE_POSITION_2: Gets the world rotation of the specified bone of the specified entity."""
    @staticmethod
    def _get_entity_bone_position_2(entity: Entity, boneIndex: int, /) -> Vector3: ...
    """_GET_ENTITY_BONE_ROTATION: Gets the world rotation of the specified bone of the specified entity."""
    @staticmethod
    def _get_entity_bone_rotation(entity: Entity, boneIndex: int, /) -> Vector3: ...
    """_GET_ENTITY_BONE_ROTATION_LOCAL: Gets the local rotation of the specified bone of the specified entity."""
    @staticmethod
    def _get_entity_bone_rotation_local(
        entity: Entity, boneIndex: int, /
    ) -> Vector3: ...
    """GET_ENTITY_CAN_BE_DAMAGED: Provides the get entity can be damaged native operation."""
    @staticmethod
    def get_entity_can_be_damaged(entity: Entity, /) -> bool: ...
    """GET_ENTITY_COLLISION_DISABLED: Provides the get entity collision disabled native operation."""
    @staticmethod
    def get_entity_collision_disabled(entity: Entity, /) -> bool: ...
    """GET_ENTITY_COORDS: Gets the current coordinates (world position) for a specified entity."""
    @staticmethod
    def get_entity_coords(entity: Entity, alive: bool, /) -> Vector3: ...
    """GET_ENTITY_FORWARD_VECTOR: Gets the entity's forward vector."""
    @staticmethod
    def get_entity_forward_vector(entity: Entity, /) -> Vector3: ...
    """GET_ENTITY_FORWARD_X: Gets the X-component of the entity's forward vector."""
    @staticmethod
    def get_entity_forward_x(entity: Entity, /) -> float: ...
    """GET_ENTITY_FORWARD_Y: Gets the Y-component of the entity's forward vector."""
    @staticmethod
    def get_entity_forward_y(entity: Entity, /) -> float: ...
    """GET_ENTITY_HEADING: Returns the heading of the entity in degrees. Also know as the "Yaw" of an entity."""
    @staticmethod
    def get_entity_heading(entity: Entity, /) -> float: ...
    """GET_ENTITY_HEADING_FROM_EULERS: Gets the heading of the entity physics in degrees, which tends to be more accurate than just [`GET_ENTITY_HEADING`](#_0xE83D4F9BA2A38914). This can be clearly seen while, for example, ragdolling a ped/player."""
    @staticmethod
    def get_entity_heading_from_eulers(entity: Entity, /) -> float: ...
    """GET_ENTITY_HEALTH: Returns an integer value of entity's current health."""
    @staticmethod
    def get_entity_health(entity: Entity, /) -> int: ...
    """GET_ENTITY_HEIGHT: Provides the get entity height native operation."""
    @staticmethod
    def get_entity_height(
        entity: Entity,
        X: float,
        Y: float,
        Z: float,
        atTop: bool,
        inWorldCoords: bool,
        /,
    ) -> float: ...

class _PlayerNatives:
    """CHANGE_PLAYER_PED: Provides the change player ped native operation."""
    @staticmethod
    def change_player_ped(
        player: int, ped: Ped, b2: bool, resetDamage: bool, /
    ) -> None: ...
    """DISABLE_PLAYER_FIRING: Inhibits the player from using any method of combat including melee and firearms."""
    @staticmethod
    def disable_player_firing(player: int, toggle: bool, /) -> None: ...
    """DISABLE_PLAYER_VEHICLE_REWARDS: Disables vehicle rewards for the current frame."""
    @staticmethod
    def disable_player_vehicle_rewards(player: int, /) -> None: ...
    """GET_IS_PLAYER_DRIVING_ON_HIGHWAY: Returns a boolean value representing if the player is driving on a highway."""
    @staticmethod
    def get_is_player_driving_on_highway(playerId: int, /) -> bool: ...
    """GET_PLAYER_CURRENT_STEALTH_NOISE: Provides the get player current stealth noise native operation."""
    @staticmethod
    def get_player_current_stealth_noise(player: int, /) -> float: ...
    """GET_PLAYER_GROUP: Returns the group ID the player is member of."""
    @staticmethod
    def get_player_group(player: int, /) -> int: ...
    """_GET_PLAYER_HEALTH_RECHARGE_LIMIT: Provides the get player health recharge limit native operation."""
    @staticmethod
    def _get_player_health_recharge_limit(player: int, /) -> float: ...
    """GET_PLAYER_INDEX: Returns the same as PLAYER_ID and NETWORK_PLAYER_ID_TO_INT"""
    @staticmethod
    def get_player_index() -> int: ...
    """GET_PLAYER_INVINCIBLE: This native will only return true if a player was made invincible with [`SET_PLAYER_INVINCIBLE`](#_0x239528EACDC3E7DE)."""
    @staticmethod
    def get_player_invincible(player: int, /) -> bool: ...
    """GET_PLAYER_MAX_ARMOUR: Provides the get player max armour native operation."""
    @staticmethod
    def get_player_max_armour(player: int, /) -> int: ...
    """GET_PLAYER_NAME: Returns the players name from a specified player index"""
    @staticmethod
    def get_player_name(player: int, /) -> str: ...
    """GET_PLAYER_PED: Gets the ped for a specified player index."""
    @staticmethod
    def get_player_ped(playerId: int, /) -> int: ...
    """GET_PLAYER_PED_SCRIPT_INDEX: Does the same like PLAYER::GET_PLAYER_PED"""
    @staticmethod
    def get_player_ped_script_index(player: int, /) -> int: ...
    """GET_PLAYER_RGB_COLOUR: Provides the get player rgb colour native operation."""
    @staticmethod
    def get_player_rgb_colour(
        player: int, r: int, g: int, b: int, /
    ) -> tuple[int, int, int]: ...
    """GET_PLAYERS_LAST_VEHICLE: This native will return `0` if the last vehicle the player was in was destroyed."""
    @staticmethod
    def get_players_last_vehicle() -> int: ...
    """GET_PLAYER_SPRINT_STAMINA_REMAINING: Provides the get player sprint stamina remaining native operation."""
    @staticmethod
    def get_player_sprint_stamina_remaining(player: int, /) -> float: ...
    """GET_PLAYER_SPRINT_TIME_REMAINING: Provides the get player sprint time remaining native operation."""
    @staticmethod
    def get_player_sprint_time_remaining(player: int, /) -> float: ...
    """GET_PLAYER_TARGET_ENTITY: Assigns the handle of locked-on melee target to *entity that you pass it."""
    @staticmethod
    def get_player_target_entity(player: int, entity: int, /) -> tuple[bool, int]: ...
    """GET_PLAYER_TEAM: Gets the player's team."""
    @staticmethod
    def get_player_team(player: int, /) -> int: ...
    """GET_PLAYER_UNDERWATER_TIME_REMAINING: Provides the get player underwater time remaining native operation."""
    @staticmethod
    def get_player_underwater_time_remaining(player: int, /) -> float: ...

class _PedNatives:
    """ADD_ARMOUR_TO_PED: Same as SET_PED_ARMOUR, but ADDS 'amount' to the armor the Ped already has."""
    @staticmethod
    def add_armour_to_ped(ped: Ped, amount: int, /) -> None: ...
    """ADD_PED_DECORATION_FROM_HASHES: Applies an Item from a PedDecorationCollection to a ped. These include tattoos and shirt decals."""
    @staticmethod
    def add_ped_decoration_from_hashes(
        ped: Ped, collection: Hash, overlay: Hash, /
    ) -> None: ...
    """ADD_PED_DECORATION_FROM_HASHES_IN_CORONA: Provides the add ped decoration from hashes in corona native operation."""
    @staticmethod
    def add_ped_decoration_from_hashes_in_corona(
        ped: Ped, collection: Hash, overlay: Hash, /
    ) -> None: ...
    """ADD_RELATIONSHIP_GROUP: Can't select void. This function returns nothing. The hash of the created relationship group is output in the second parameter."""
    @staticmethod
    def add_relationship_group(name: str, groupHash: int, /) -> tuple[int, int]: ...
    """CAN_PED_IN_COMBAT_SEE_TARGET: Provides the can ped in combat see target native operation."""
    @staticmethod
    def can_ped_in_combat_see_target(ped: Ped, target: Ped, /) -> bool: ...
    """CAN_PED_RAGDOLL: Prevents the ped from going limp."""
    @staticmethod
    def can_ped_ragdoll(ped: Ped, /) -> bool: ...
    """CAN_PED_SEE_HATED_PED: Provides the can ped see hated ped native operation."""
    @staticmethod
    def can_ped_see_hated_ped(ped1: Ped, ped2: Ped, /) -> bool: ...
    """CLEAR_PED_ALTERNATE_MOVEMENT_ANIM: Provides the clear ped alternate movement anim native operation."""
    @staticmethod
    def clear_ped_alternate_movement_anim(
        ped: Ped, stance: int, p2: float, /
    ) -> None: ...
    """CLEAR_PED_ALTERNATE_WALK_ANIM: Provides the clear ped alternate walk anim native operation."""
    @staticmethod
    def clear_ped_alternate_walk_anim(ped: Ped, p1: float, /) -> None: ...
    """CLEAR_PED_BLOOD_DAMAGE: Clears the blood on a ped."""
    @staticmethod
    def clear_ped_blood_damage(ped: Ped, /) -> None: ...
    """CLEAR_PED_BLOOD_DAMAGE_BY_ZONE: Somehow related to changing ped's clothes."""
    @staticmethod
    def clear_ped_blood_damage_by_zone(ped: Ped, p1: int, /) -> None: ...
    """_CLEAR_PED_COVER_CLIPSET_OVERRIDE: Provides the  clear ped cover clipset override native operation."""
    @staticmethod
    def _clear_ped_cover_clipset_override(ped: Ped, /) -> None: ...
    """CLEAR_PED_DAMAGE_DECAL_BY_ZONE: Provides the clear ped damage decal by zone native operation."""
    @staticmethod
    def clear_ped_damage_decal_by_zone(ped: Ped, p1: int, p2: str, /) -> None: ...
    """CLEAR_PED_DECORATIONS: Provides the clear ped decorations native operation."""
    @staticmethod
    def clear_ped_decorations(ped: Ped, /) -> None: ...
    """CLEAR_PED_DECORATIONS_LEAVE_SCARS: Provides the clear ped decorations leave scars native operation."""
    @staticmethod
    def clear_ped_decorations_leave_scars(ped: Ped, /) -> None: ...
    """CLEAR_PED_DRIVE_BY_CLIPSET_OVERRIDE: Provides the clear ped drive by clipset override native operation."""
    @staticmethod
    def clear_ped_drive_by_clipset_override(ped: Ped, /) -> None: ...
    """CLEAR_PED_ENV_DIRT: Provides the clear ped env dirt native operation."""
    @staticmethod
    def clear_ped_env_dirt(ped: Ped, /) -> None: ...
    """CLEAR_PED_LAST_DAMAGE_BONE: Provides the clear ped last damage bone native operation."""
    @staticmethod
    def clear_ped_last_damage_bone(ped: Ped, /) -> None: ...
    """CLEAR_PED_NON_CREATION_AREA: Provides the clear ped non creation area native operation."""
    @staticmethod
    def clear_ped_non_creation_area() -> None: ...
    """CLEAR_PED_PROP: Provides the clear ped prop native operation."""
    @staticmethod
    def clear_ped_prop(ped: Ped, propId: int, /) -> None: ...
    """CLEAR_PED_SCUBA_GEAR_VARIATION: Removes the scubagear (for mp male: component id: 8, drawableId: 123, textureId: any) from peds. Does not play the 'remove scuba gear' animation, but instantly removes it."""
    @staticmethod
    def clear_ped_scuba_gear_variation(ped: Ped, /) -> None: ...
    """CLEAR_PED_STORED_HAT_PROP: Provides the clear ped stored hat prop native operation."""
    @staticmethod
    def clear_ped_stored_hat_prop(ped: Ped, /) -> None: ...
    """CLEAR_PED_WETNESS: It clears the wetness of the selected Ped/Player. Clothes have to be wet to notice the difference."""
    @staticmethod
    def clear_ped_wetness(ped: Ped, /) -> None: ...
    """CLEAR_RAGDOLL_BLOCKING_FLAGS: There seem to be 26 flags"""
    @staticmethod
    def clear_ragdoll_blocking_flags(ped: Ped, flags: int, /) -> None: ...
    """CLEAR_RELATIONSHIP_BETWEEN_GROUPS: Clears the relationship between two groups. This should be called twice (once for each group)."""
    @staticmethod
    def clear_relationship_between_groups(
        relationship: int, group1: Hash, group2: Hash, /
    ) -> None: ...
    """CLONE_PED: Creates a copy of the passed ped, optionally setting it as local and/or shallow-copying the head blend data."""
    @staticmethod
    def clone_ped(
        ped: Ped, isNetwork: bool, bScriptHostPed: bool, copyHeadBlendFlag: bool, /
    ) -> int: ...
    """_CLONE_PED_EX: Used one time in fmmc_launcher.c instead of CLONE_PED because ?"""
    @staticmethod
    def _clone_ped_ex(
        ped: Ped, heading: float, isNetwork: bool, bScriptHostPed: bool, p4: int, /
    ) -> int: ...
    """CLONE_PED_TO_TARGET: Copies ped's components and props to targetPed."""
    @staticmethod
    def clone_ped_to_target(ped: Ped, targetPed: Ped, /) -> None: ...
    """_CLONE_PED_TO_TARGET_EX: Provides the clone ped to target ex native operation."""
    @staticmethod
    def _clone_ped_to_target_ex(ped: Ped, targetPed: Ped, p2: int, /) -> None: ...
    """CREATE_PED: Creates a ped (biped character, pedestrian, actor) with the specified model at the specified position and heading."""
    @staticmethod
    def create_ped(
        pedType: int,
        modelHash: Hash,
        x: float,
        y: float,
        z: float,
        heading: float,
        isNetwork: bool,
        bScriptHostPed: bool,
        /,
    ) -> int: ...
    """CREATE_PED_INSIDE_VEHICLE: Provides the create ped inside vehicle native operation."""
    @staticmethod
    def create_ped_inside_vehicle(
        vehicle: Vehicle,
        pedType: int,
        modelHash: Hash,
        seat: int,
        isNetwork: bool,
        bScriptHostPed: bool,
        /,
    ) -> int: ...
    """DELETE_PED: Deletes the specified ped, then sets the handle pointed to by the pointer to NULL."""
    @staticmethod
    def delete_ped(ped: int, /) -> tuple[int]: ...
    """_DOES_RELATIONSHIP_GROUP_EXIST: Provides the does relationship group exist native operation."""
    @staticmethod
    def _does_relationship_group_exist(groupHash: Hash, /) -> bool: ...
    """GET_COMBAT_FLOAT: Provides the get combat float native operation."""
    @staticmethod
    def get_combat_float(ped: Ped, p1: int, /) -> float: ...
    """GET_NUMBER_OF_PED_DRAWABLE_VARIATIONS: Provides the get number of ped drawable variations native operation."""
    @staticmethod
    def get_number_of_ped_drawable_variations(ped: Ped, componentId: int, /) -> int: ...
    """GET_NUMBER_OF_PED_PROP_DRAWABLE_VARIATIONS: Provides the get number of ped prop drawable variations native operation."""
    @staticmethod
    def get_number_of_ped_prop_drawable_variations(ped: Ped, propId: int, /) -> int: ...
    """GET_NUMBER_OF_PED_PROP_TEXTURE_VARIATIONS: Need to check behavior when drawableId = -1"""
    @staticmethod
    def get_number_of_ped_prop_texture_variations(
        ped: Ped, propId: int, drawableId: int, /
    ) -> int: ...
    """GET_NUMBER_OF_PED_TEXTURE_VARIATIONS: Provides the get number of ped texture variations native operation."""
    @staticmethod
    def get_number_of_ped_texture_variations(
        ped: Ped, componentId: int, drawableId: int, /
    ) -> int: ...
    """GET_PED_ACCURACY: Provides the get ped accuracy native operation."""
    @staticmethod
    def get_ped_accuracy(ped: Ped, /) -> int: ...
    """GET_PED_ALERTNESS: Returns the ped's alertness (0-3)."""
    @staticmethod
    def get_ped_alertness(ped: Ped, /) -> int: ...
    """GET_PED_ARMOUR: Provides the get ped armour native operation."""
    @staticmethod
    def get_ped_armour(ped: Ped, /) -> int: ...
    """GET_PED_AS_GROUP_LEADER: Provides the get ped as group leader native operation."""
    @staticmethod
    def get_ped_as_group_leader(groupID: int, /) -> int: ...
    """GET_PED_AS_GROUP_MEMBER: Provides the get ped as group member native operation."""
    @staticmethod
    def get_ped_as_group_member(groupID: int, memberNumber: int, /) -> int: ...
    """GET_PED_BONE_COORDS: Gets the position of the specified bone of the specified ped."""
    @staticmethod
    def get_ped_bone_coords(
        ped: Ped, boneId: int, offsetX: float, offsetY: float, offsetZ: float, /
    ) -> Vector3: ...
    """GET_PED_BONE_INDEX: Provides the get ped bone index native operation."""
    @staticmethod
    def get_ped_bone_index(ped: Ped, boneId: int, /) -> int: ...

class _VehicleNatives:
    """ARE_ALL_VEHICLE_WINDOWS_INTACT: Appears to return false if any window is broken."""
    @staticmethod
    def are_all_vehicle_windows_intact(vehicle: Vehicle, /) -> bool: ...
    """ARE_ANY_VEHICLE_SEATS_FREE: Dead peds still count as occupying a seat until the body is removed, so a vehicle full of corpses returns `false`. Peds tasked to enter the vehicle but not yet inserted do not occupy their target seat."""
    @staticmethod
    def are_any_vehicle_seats_free(vehicle: Vehicle, /) -> bool: ...
    """CREATE_VEHICLE: Creates a vehicle with the specified model at the specified position. This vehicle will initially be owned by the creating"""
    @staticmethod
    def create_vehicle(
        modelHash: Hash,
        x: float,
        y: float,
        z: float,
        heading: float,
        isNetwork: bool,
        netMissionEntity: bool,
        /,
    ) -> int: ...
    """DELETE_VEHICLE: Deletes a vehicle."""
    @staticmethod
    def delete_vehicle(vehicle: int, /) -> tuple[int]: ...
    """_DOES_VEHICLE_TYRE_EXIST: Checks if vehicle tyre at index exists. Also returns false if tyre was removed."""
    @staticmethod
    def _does_vehicle_tyre_exist(vehicle: Vehicle, tyreIndex: int, /) -> bool: ...
    """FIX_VEHICLE_WINDOW: See eWindowId declared in [`IS_VEHICLE_WINDOW_INTACT`](#_0x46E571A0E20D01F1)."""
    @staticmethod
    def fix_vehicle_window(vehicle: object, windowIndex: int, /) -> int: ...
    """GET_BOAT_VEHICLE_MODEL_AGILITY: Retrieves the agility for a specific boat model, including any vehicle mods. Unlike other vehicles where Rockstar Games typically assess performance based on traction, boats use agility as a measure. This static value is distinct from the traction metrics used for other vehicle types."""
    @staticmethod
    def get_boat_vehicle_model_agility(modelHash: Hash, /) -> float: ...
    """GET_DISPLAY_NAME_FROM_VEHICLE_MODEL: Returns the display name/text label (`gameName` in `vehicles.meta`) for the specified vehicle model."""
    @staticmethod
    def get_display_name_from_vehicle_model(modelHash: Hash, /) -> str: ...
    """_GET_IS_VEHICLE_ELECTRIC: Checks if the vehicle is electric."""
    @staticmethod
    def _get_is_vehicle_electric(vehicleModel: Hash, /) -> bool: ...
    """_GET_IS_VEHICLE_EMP_DISABLED: Returns whether this vehicle is currently disabled by an EMP mine."""
    @staticmethod
    def _get_is_vehicle_emp_disabled(vehicle: Vehicle, /) -> bool: ...
    """GET_IS_VEHICLE_ENGINE_RUNNING: Returns true when in a vehicle, false whilst entering/exiting."""
    @staticmethod
    def get_is_vehicle_engine_running(vehicle: Vehicle, /) -> bool: ...
    """GET_IS_VEHICLE_PRIMARY_COLOUR_CUSTOM: Provides the get is vehicle primary colour custom native operation."""
    @staticmethod
    def get_is_vehicle_primary_colour_custom(vehicle: Vehicle, /) -> bool: ...
    """GET_IS_VEHICLE_SECONDARY_COLOUR_CUSTOM: Check if Vehicle Secondary is avaliable for customize"""
    @staticmethod
    def get_is_vehicle_secondary_colour_custom(vehicle: Vehicle, /) -> bool: ...
    """_GET_IS_VEHICLE_SHUNT_BOOST_ACTIVE: Provides the get is vehicle shunt boost active native operation."""
    @staticmethod
    def _get_is_vehicle_shunt_boost_active(vehicle: Vehicle, /) -> bool: ...
    """GET_MAKE_NAME_FROM_VEHICLE_MODEL: Retrieves the manufacturer's name for a specified vehicle."""
    @staticmethod
    def get_make_name_from_vehicle_model(modelHash: Hash, /) -> str: ...
    """_GET_NUMBER_OF_VEHICLE_DOORS: Provides the get number of vehicle doors native operation."""
    @staticmethod
    def _get_number_of_vehicle_doors(vehicle: Vehicle, /) -> int: ...
    """GET_NUM_VEHICLE_MODS: Returns how many possible mods a vehicle has for a given mod type"""
    @staticmethod
    def get_num_vehicle_mods(vehicle: Vehicle, modType: int, /) -> int: ...
    """GET_NUM_VEHICLE_WINDOW_TINTS: Provides the get num vehicle window tints native operation."""
    @staticmethod
    def get_num_vehicle_window_tints() -> int: ...
    """GET_PED_USING_VEHICLE_DOOR: See eDoorId declared in [`SET_VEHICLE_DOOR_SHUT`](#_0x93D9BD300D7789E5)"""
    @staticmethod
    def get_ped_using_vehicle_door(vehicle: Vehicle, doorIndex: int, /) -> int: ...
    """GET_RANDOM_VEHICLE_MODEL_IN_MEMORY: Not present in the retail version! It's just a nullsub."""
    @staticmethod
    def get_random_vehicle_model_in_memory(
        p0: bool, modelHash: int, successIndicator: int, /
    ) -> tuple[int, int]: ...
    """GET_VEHICLE_ACCELERATION: Retrieves a static value representing the maximum drive force of specific a vehicle, including any vehicle mods. This value does not change dynamically during gameplay. This value provides an approximation and should be considered alongside other performance metrics like top speed for a more comprehensive understanding of the vehicle's capabilities."""
    @staticmethod
    def get_vehicle_acceleration(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_BODY_HEALTH: Seems related to vehicle health, like the one in IV."""
    @staticmethod
    def get_vehicle_body_health(vehicle: Vehicle, /) -> float: ...
    """_GET_VEHICLE_BOMB_COUNT: Gets the amount of bombs that this vehicle has. As far as I know, this does _not_ impact vehicle weapons or the ammo of those weapons in any way, it is just a way to keep track of the amount of bombs in a specific plane."""
    @staticmethod
    def _get_vehicle_bomb_count(aircraft: Vehicle, /) -> int: ...
    """GET_VEHICLE_CAUSE_OF_DESTRUCTION: A hash representing the destruction cause. These can be weapon hashes."""
    @staticmethod
    def get_vehicle_cause_of_destruction(vehicle: Vehicle, /) -> int: ...
    """GET_VEHICLE_CLASS: Returns an int"""
    @staticmethod
    def get_vehicle_class(vehicle: Vehicle, /) -> int: ...
    """GET_VEHICLE_CLASS_ESTIMATED_MAX_SPEED: Provides the get vehicle class estimated max speed native operation."""
    @staticmethod
    def get_vehicle_class_estimated_max_speed(vehicleClass: int, /) -> float: ...
    """GET_VEHICLE_CLASS_FROM_NAME: For a full enum, see here : pastebin.com/i2GGAjY0"""
    @staticmethod
    def get_vehicle_class_from_name(modelHash: Hash, /) -> int: ...
    """GET_VEHICLE_CLASS_MAX_ACCELERATION: Provides the get vehicle class max acceleration native operation."""
    @staticmethod
    def get_vehicle_class_max_acceleration(vehicleClass: int, /) -> float: ...
    """GET_VEHICLE_CLASS_MAX_AGILITY: Provides the get vehicle class max agility native operation."""
    @staticmethod
    def get_vehicle_class_max_agility(vehicleClass: int, /) -> float: ...
    """GET_VEHICLE_CLASS_MAX_BRAKING: Provides the get vehicle class max braking native operation."""
    @staticmethod
    def get_vehicle_class_max_braking(vehicleClass: int, /) -> float: ...
    """GET_VEHICLE_CLASS_MAX_TRACTION: Provides the get vehicle class max traction native operation."""
    @staticmethod
    def get_vehicle_class_max_traction(vehicleClass: int, /) -> float: ...
    """GET_VEHICLE_COLOR: See [`SET_VEHICLE_CUSTOM_PRIMARY_COLOUR`](#_0x7141766F91D15BEA) and [`SET_VEHICLE_CUSTOM_SECONDARY_COLOUR`](#_0x36CED73BFED89754)."""
    @staticmethod
    def get_vehicle_color(
        vehicle: Vehicle, r: int, g: int, b: int, /
    ) -> tuple[int, int, int]: ...
    """GET_VEHICLE_COLOUR_COMBINATION: Provides the get vehicle colour combination native operation."""
    @staticmethod
    def get_vehicle_colour_combination(vehicle: Vehicle, /) -> int: ...
    """GET_VEHICLE_COLOURS: Provides the get vehicle colours native operation."""
    @staticmethod
    def get_vehicle_colours(
        vehicle: Vehicle, colorPrimary: int, colorSecondary: int, /
    ) -> tuple[int, int]: ...
    """GET_VEHICLE_COLOURS_WHICH_CAN_BE_SET: Provides the get vehicle colours which can be set native operation."""
    @staticmethod
    def get_vehicle_colours_which_can_be_set(vehicle: Vehicle, /) -> int: ...
    """_GET_VEHICLE_COUNTERMEASURE_COUNT: Similar to [`_GET_AIRCRAFT_BOMB_COUNT`](#_0xEA12BD130D7569A1), this gets the amount of countermeasures that are present on this vehicle."""
    @staticmethod
    def _get_vehicle_countermeasure_count(aircraft: Vehicle, /) -> int: ...
    """_GET_VEHICLE_CURRENT_SLIPSTREAM_DRAFT: Returns a float value between 0.0 and 3.0 related to its slipstream draft (boost/speedup)."""
    @staticmethod
    def _get_vehicle_current_slipstream_draft(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_CUSTOM_PRIMARY_COLOUR: Provides the get vehicle custom primary colour native operation."""
    @staticmethod
    def get_vehicle_custom_primary_colour(
        vehicle: Vehicle, r: int, g: int, b: int, /
    ) -> tuple[int, int, int]: ...
    """GET_VEHICLE_CUSTOM_SECONDARY_COLOUR: Provides the get vehicle custom secondary colour native operation."""
    @staticmethod
    def get_vehicle_custom_secondary_colour(
        vehicle: Vehicle, r: int, g: int, b: int, /
    ) -> tuple[int, int, int]: ...
    """_GET_VEHICLE_DASHBOARD_COLOR: Provides the get vehicle dashboard color native operation."""
    @staticmethod
    def _get_vehicle_dashboard_color(vehicle: Vehicle, color: int, /) -> tuple[int]: ...
    """GET_VEHICLE_DEFORMATION_AT_POS: The only example I can find of this function in the scripts, is this:"""
    @staticmethod
    def get_vehicle_deformation_at_pos(
        vehicle: Vehicle, offsetX: float, offsetY: float, offsetZ: float, /
    ) -> Vector3: ...
    """GET_VEHICLE_DIRT_LEVEL: A getter for [`SET_VEHICLE_DIRT_LEVEL`](#_0x79D3B596FE44EE8B)."""
    @staticmethod
    def get_vehicle_dirt_level(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_DOOR_ANGLE_RATIO: Checks the angle of the door mapped from 0.0 - 1.0 where 0.0 is fully closed and 1.0 is fully open."""
    @staticmethod
    def get_vehicle_door_angle_ratio(vehicle: Vehicle, doorIndex: int, /) -> float: ...
    """GET_VEHICLE_DOOR_LOCK_STATUS: Returns the current lock status, refer to [SET_VEHICLE_DOORS_LOCKED](#_0xB664292EAECF7FA6)"""
    @staticmethod
    def get_vehicle_door_lock_status(vehicle: Vehicle, /) -> int: ...
    """GET_VEHICLE_DOORS_LOCKED_FOR_PLAYER: Provides the get vehicle doors locked for player native operation."""
    @staticmethod
    def get_vehicle_doors_locked_for_player(
        vehicle: Vehicle, player: int, /
    ) -> bool: ...
    """GET_VEHICLE_ENGINE_HEALTH: Returns 1000.0 if the function is unable to get the address of the specified vehicle or if it's not a vehicle."""
    @staticmethod
    def get_vehicle_engine_health(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_ENVEFF_SCALE: formerly known as _GET_VEHICLE_PAINT_FADE"""
    @staticmethod
    def get_vehicle_enveff_scale(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_ESTIMATED_MAX_SPEED: Retrieves a static value representing the estimated max speed of a specific vehicle, including any vehicle mods. This value does not change dynamically during gameplay."""
    @staticmethod
    def get_vehicle_estimated_max_speed(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_EXTRA_COLOURS: Provides the get vehicle extra colours native operation."""
    @staticmethod
    def get_vehicle_extra_colours(
        vehicle: Vehicle, pearlescentColor: int, wheelColor: int, /
    ) -> tuple[int, int]: ...
    """GET_VEHICLE_FLIGHT_NOZZLE_POSITION: A float indicating the percentage of the hover mode. 1.0 = in VTOL mode, 0.0 = in normal flying mode."""
    @staticmethod
    def get_vehicle_flight_nozzle_position(aircraft: Vehicle, /) -> float: ...
    """GET_VEHICLE_HAS_KERS: Returns true if the vehicle has a kers boost (for instance the lectro or the vindicator)"""
    @staticmethod
    def get_vehicle_has_kers(vehicle: Vehicle, /) -> bool: ...
    """GET_VEHICLE_HEALTH_PERCENTAGE: Provides the get vehicle health percentage native operation."""
    @staticmethod
    def get_vehicle_health_percentage(vehicle: Vehicle, /) -> float: ...
    """GET_VEHICLE_HOMING_LOCKON_STATE: Returns a value depending on the lock-on state of vehicle weapons."""
    @staticmethod
    def get_vehicle_homing_lockon_state(vehicle: Vehicle, /) -> int: ...
    """GET_VEHICLE_INDIVIDUAL_DOOR_LOCK_STATUS: See eDoorId declared in [`SET_VEHICLE_DOOR_SHUT`](#_0x93D9BD300D7789E5)"""
    @staticmethod
    def get_vehicle_individual_door_lock_status(
        vehicle: Vehicle, doorIndex: int, /
    ) -> int: ...
    """_GET_VEHICLE_INTERIOR_COLOR: Provides the get vehicle interior color native operation."""
    @staticmethod
    def _get_vehicle_interior_color(vehicle: Vehicle, color: int, /) -> tuple[int]: ...

class _ObjectNatives:
    """ATTACH_PORTABLE_PICKUP_TO_PED: Provides the attach portable pickup to ped native operation."""
    @staticmethod
    def attach_portable_pickup_to_ped(pickupObject: Object, ped: Ped, /) -> None: ...
    """CREATE_NON_NETWORKED_PORTABLE_PICKUP: Provides the create non networked portable pickup native operation."""
    @staticmethod
    def create_non_networked_portable_pickup(
        pickupHash: Hash,
        x: float,
        y: float,
        z: float,
        placeOnGround: bool,
        modelHash: Hash,
        /,
    ) -> int: ...
    """CREATE_OBJECT: Creates an object (prop) with the specified model at the specified position, offset on the Z axis by the radius of the object's model."""
    @staticmethod
    def create_object(
        modelHash: Hash,
        x: float,
        y: float,
        z: float,
        isNetwork: bool,
        netMissionEntity: bool,
        doorFlag: bool,
        /,
    ) -> int: ...
    """CREATE_OBJECT_NO_OFFSET: Creates an object (prop) with the specified model centered at the specified position."""
    @staticmethod
    def create_object_no_offset(
        modelHash: Hash,
        x: float,
        y: float,
        z: float,
        isNetwork: bool,
        netMissionEntity: bool,
        doorFlag: bool,
        /,
    ) -> int: ...
    """CREATE_PICKUP: Pickup hashes can be found [here](https://gist.github.com/4mmonium/1eabfb6b3996e3aa6b9525a3eccf8a0b)."""
    @staticmethod
    def create_pickup(
        pickupHash: Hash,
        posX: float,
        posY: float,
        posZ: float,
        p4: int,
        value: int,
        p6: bool,
        modelHash: Hash,
        /,
    ) -> int: ...
    """CREATE_PICKUP_ROTATE: Pickup hashes: pastebin.com/8EuSv2r1"""
    @staticmethod
    def create_pickup_rotate(
        pickupHash: Hash,
        posX: float,
        posY: float,
        posZ: float,
        rotX: float,
        rotY: float,
        rotZ: float,
        flag: int,
        amount: int,
        p9: int,
        p10: bool,
        modelHash: Hash,
        /,
    ) -> int: ...
    """CREATE_PORTABLE_PICKUP: Pickup hashes can be found [here](https://gist.github.com/4mmonium/1eabfb6b3996e3aa6b9525a3eccf8a0b)."""
    @staticmethod
    def create_portable_pickup(
        pickupHash: Hash,
        x: float,
        y: float,
        z: float,
        placeOnGround: bool,
        modelHash: Hash,
        /,
    ) -> int: ...
    """DELETE_OBJECT: Deletes the specified object."""
    @staticmethod
    def delete_object(object: int, /) -> tuple[int]: ...
    """DETACH_PORTABLE_PICKUP_FROM_PED: Provides the detach portable pickup from ped native operation."""
    @staticmethod
    def detach_portable_pickup_from_ped(pickupObject: Object, /) -> None: ...
    """GET_OBJECT_FRAGMENT_DAMAGE_HEALTH: Provides the get object fragment damage health native operation."""
    @staticmethod
    def get_object_fragment_damage_health(p0: int, p1: bool, /) -> float: ...
    """_GET_OBJECT_TEXTURE_VARIATION: Provides the get object texture variation native operation."""
    @staticmethod
    def _get_object_texture_variation(object: Object, /) -> int: ...
    """GET_PICKUP_COORDS: Provides the get pickup coords native operation."""
    @staticmethod
    def get_pickup_coords(pickup: Pickup, /) -> Vector3: ...
    """_GET_PICKUP_GENERATION_RANGE_MULTIPLIER: Provides the get pickup generation range multiplier native operation."""
    @staticmethod
    def _get_pickup_generation_range_multiplier() -> float: ...
    """_GET_PICKUP_HASH: returns pickup hash."""
    @staticmethod
    def _get_pickup_hash(pickupHash: Hash, /) -> int: ...
    """_GET_PICKUP_HASH_FROM_WEAPON: Returns the pickup hash for the given weapon hash"""
    @staticmethod
    def _get_pickup_hash_from_weapon(weapon: Hash, /) -> int: ...
    """GET_PICKUP_OBJECT: Provides the get pickup object native operation."""
    @staticmethod
    def get_pickup_object(pickup: Pickup, /) -> int: ...
    """HIDE_PORTABLE_PICKUP_WHEN_DETACHED: Provides the hide portable pickup when detached native operation."""
    @staticmethod
    def hide_portable_pickup_when_detached(pickup: Pickup, toggle: bool, /) -> None: ...
    """IS_OBJECT_A_PICKUP: Provides the is object a pickup native operation."""
    @staticmethod
    def is_object_a_pickup(object: Object, /) -> bool: ...
    """IS_OBJECT_A_PORTABLE_PICKUP: Provides the is object a portable pickup native operation."""
    @staticmethod
    def is_object_a_portable_pickup(object: Object, /) -> bool: ...
    """IS_OBJECT_ENTIRELY_INSIDE_GARAGE: Provides the is object entirely inside garage native operation."""
    @staticmethod
    def is_object_entirely_inside_garage(
        garageHash: Hash, entity: Entity, p2: float, p3: int, /
    ) -> bool: ...
    """IS_OBJECT_NEAR_POINT: Provides the is object near point native operation."""
    @staticmethod
    def is_object_near_point(
        objectHash: Hash, x: float, y: float, z: float, range: float, /
    ) -> bool: ...
    """IS_OBJECT_PARTIALLY_INSIDE_GARAGE: Provides the is object partially inside garage native operation."""
    @staticmethod
    def is_object_partially_inside_garage(
        garageHash: Hash, entity: Entity, p2: int, /
    ) -> bool: ...
    """IS_OBJECT_VISIBLE: Provides the is object visible native operation."""
    @staticmethod
    def is_object_visible(object: Object, /) -> bool: ...
    """PLACE_OBJECT_ON_GROUND_OR_OBJECT_PROPERLY: Casts a ray downward from the object's position and places the object on the surface it hits (including world surface and objects). Use [`PLACE_OBJECT_ON_GROUND_PROPERLY`](#_0x58A850EAEE20FAA3) to not include objects when determining the surface."""
    @staticmethod
    def place_object_on_ground_or_object_properly(object: Object, /) -> bool: ...
    """PLACE_OBJECT_ON_GROUND_PROPERLY: Provides the place object on ground properly native operation."""
    @staticmethod
    def place_object_on_ground_properly(object: Object, /) -> bool: ...

class _TaskNatives:
    """CLEAR_PED_TASKS: Clear a ped's tasks. Stop animations and other tasks created by scripts."""
    @staticmethod
    def clear_ped_tasks(ped: Ped, /) -> None: ...
    """CLEAR_PED_TASKS_IMMEDIATELY: Immediately stops the pedestrian from whatever it's doing. The difference between this and [CLEAR_PED_TASKS](#_0xE1EF3C1216AFF2CD) is that this one teleports the ped but does not change the position of the ped."""
    @staticmethod
    def clear_ped_tasks_immediately(ped: Ped, /) -> None: ...
    """CLOSE_SEQUENCE_TASK: For an example on how to use this please refer to [OPEN_SEQUENCE_TASK](#_0xE8854A4326B9E12B)"""
    @staticmethod
    def close_sequence_task(taskSequenceId: object, /) -> int: ...
    """DOES_SCENARIO_EXIST_IN_AREA: Provides the does scenario exist in area native operation."""
    @staticmethod
    def does_scenario_exist_in_area(
        x: float, y: float, z: float, radius: float, b: bool, /
    ) -> bool: ...
    """DOES_SCENARIO_GROUP_EXIST: Occurrences in the b617d scripts:"""
    @staticmethod
    def does_scenario_group_exist(scenarioGroup: str, /) -> bool: ...
    """DOES_SCENARIO_OF_TYPE_EXIST_IN_AREA: Provides the does scenario of type exist in area native operation."""
    @staticmethod
    def does_scenario_of_type_exist_in_area(
        p0: float, p1: float, p2: float, p3: str, p4: float, p5: bool, /
    ) -> bool: ...
    """IS_PED_ACTIVE_IN_SCENARIO: This is a stricter version of [`IS_PED_USING_ANY_SCENARIO`](#_0x57AB4A3080F85143). It only returns true if the ped is playing the ambient animations associated with the scenario."""
    @staticmethod
    def is_ped_active_in_scenario(ped: Ped, /) -> bool: ...
    """IS_PED_PLAYING_BASE_CLIP_IN_SCENARIO: Provides the is ped playing base clip in scenario native operation."""
    @staticmethod
    def is_ped_playing_base_clip_in_scenario(ped: Ped, /) -> bool: ...
    """IS_SCENARIO_GROUP_ENABLED: Occurrences in the b617d scripts:"""
    @staticmethod
    def is_scenario_group_enabled(scenarioGroup: str, /) -> bool: ...
    """IS_SCENARIO_OCCUPIED: Provides the is scenario occupied native operation."""
    @staticmethod
    def is_scenario_occupied(
        p0: float, p1: float, p2: float, p3: float, p4: bool, /
    ) -> bool: ...
    """IS_SCENARIO_TYPE_ENABLED: Occurrences in the b617d scripts:"""
    @staticmethod
    def is_scenario_type_enabled(scenarioType: str, /) -> bool: ...
    """OPEN_SEQUENCE_TASK: If this returns 0 that means it failed to get a sequence id."""
    @staticmethod
    def open_sequence_task(taskSequenceId: int, /) -> tuple[int, int]: ...
    """PED_HAS_USE_SCENARIO_TASK: Provides the ped has use scenario task native operation."""
    @staticmethod
    def ped_has_use_scenario_task(ped: Ped, /) -> bool: ...
    """PLAY_ANIM_ON_RUNNING_SCENARIO: Provides the play anim on running scenario native operation."""
    @staticmethod
    def play_anim_on_running_scenario(
        ped: Ped, animDict: str, animName: str, /
    ) -> None: ...
    """RESET_EXCLUSIVE_SCENARIO_GROUP: Provides the reset exclusive scenario group native operation."""
    @staticmethod
    def reset_exclusive_scenario_group() -> None: ...
    """RESET_SCENARIO_GROUPS_ENABLED: Provides the reset scenario groups enabled native operation."""
    @staticmethod
    def reset_scenario_groups_enabled() -> None: ...
    """RESET_SCENARIO_TYPES_ENABLED: Provides the reset scenario types enabled native operation."""
    @staticmethod
    def reset_scenario_types_enabled() -> None: ...
    """SET_DRIVE_TASK_CRUISE_SPEED: Provides the set drive task cruise speed native operation."""
    @staticmethod
    def set_drive_task_cruise_speed(driver: Ped, cruiseSpeed: float, /) -> None: ...
    """SET_DRIVE_TASK_DRIVING_STYLE: Sets the driving style for a ped currently performing a driving task."""
    @staticmethod
    def set_drive_task_driving_style(ped: Ped, drivingStyle: int, /) -> None: ...
    """SET_DRIVE_TASK_MAX_CRUISE_SPEED: Provides the set drive task max cruise speed native operation."""
    @staticmethod
    def set_drive_task_max_cruise_speed(p0: int, p1: float, /) -> None: ...
    """SET_EXCLUSIVE_SCENARIO_GROUP: Groups found in the scripts used with this native:"""
    @staticmethod
    def set_exclusive_scenario_group(scenarioGroup: str, /) -> None: ...
    """SET_SCENARIO_GROUP_ENABLED: Occurrences in the b617d scripts: pastebin.com/Tvg2PRHU"""
    @staticmethod
    def set_scenario_group_enabled(scenarioGroup: str, p1: bool, /) -> None: ...
    """SET_SCENARIO_TYPE_ENABLED: seems to enable/disable specific scenario-types from happening in the game world."""
    @staticmethod
    def set_scenario_type_enabled(scenarioType: str, toggle: bool, /) -> None: ...
    """TASK_AIM_GUN_AT_COORD: Provides the task aim gun at coord native operation."""
    @staticmethod
    def task_aim_gun_at_coord(
        ped: Ped,
        x: float,
        y: float,
        z: float,
        time: int,
        bInstantBlendToAim: bool,
        bPlayAimIntro: bool,
        /,
    ) -> None: ...
    """TASK_AIM_GUN_AT_ENTITY: duration: the amount of time in milliseconds to do the task. -1 will keep the task going until either another task is applied, or CLEAR_ALL_TASKS() is called with the ped"""
    @staticmethod
    def task_aim_gun_at_entity(
        ped: Ped, entity: Entity, duration: int, bInstantBlendToAim: bool, /
    ) -> None: ...
    """TASK_AIM_GUN_SCRIPTED: Provides the task aim gun scripted native operation."""
    @staticmethod
    def task_aim_gun_scripted(
        ped: Ped,
        scriptTask: Hash,
        bDisableBlockingClip: bool,
        bInstantBlendToAim: bool,
        /,
    ) -> None: ...
    """TASK_AIM_GUN_SCRIPTED_WITH_TARGET: Provides the task aim gun scripted with target native operation."""
    @staticmethod
    def task_aim_gun_scripted_with_target(
        ped: Ped,
        targetPed: Ped,
        x: float,
        y: float,
        z: float,
        iGunTaskType: Hash,
        bDisableBlockingClip: bool,
        bForceAim: bool,
        /,
    ) -> None: ...
    """TASK_COMBAT_HATED_TARGETS_AROUND_PED: Despite its name, it only attacks ONE hated target. The one closest hated target."""
    @staticmethod
    def task_combat_hated_targets_around_ped(
        ped: Ped, radius: float, p2: int, /
    ) -> None: ...
    """TASK_COMBAT_HATED_TARGETS_AROUND_PED_TIMED: Provides the task combat hated targets around ped timed native operation."""
    @staticmethod
    def task_combat_hated_targets_around_ped_timed(
        p0: int, p1: float, p2: int, p3: int, /
    ) -> None: ...
    """TASK_COMBAT_HATED_TARGETS_IN_AREA: Despite its name, it only attacks ONE hated target. The one closest to the specified position."""
    @staticmethod
    def task_combat_hated_targets_in_area(
        ped: Ped, x: float, y: float, z: float, radius: float, p5: int, /
    ) -> None: ...
    """TASK_COMBAT_PED: Makes the specified ped attack the target ped."""
    @staticmethod
    def task_combat_ped(ped: Ped, targetPed: Ped, p2: int, p3: int, /) -> None: ...
    """TASK_COMBAT_PED_TIMED: Provides the task combat ped timed native operation."""
    @staticmethod
    def task_combat_ped_timed(p0: int, ped: Ped, p2: int, p3: int, /) -> None: ...
    """TASK_FOLLOW_NAV_MESH_TO_COORD: Sometimes a path may not be able to be found. This could happen because there simply isn't any way to get there, or maybe a bunch of dynamic objects have blocked the way,"""
    @staticmethod
    def task_follow_nav_mesh_to_coord(
        ped: Ped,
        x: float,
        y: float,
        z: float,
        moveBlendRatio: float,
        time: int,
        radius: float,
        flags: int,
        finalHeading: float,
        /,
    ) -> None: ...
    """TASK_FOLLOW_NAV_MESH_TO_COORD_ADVANCED: Provides the task follow nav mesh to coord advanced native operation."""
    @staticmethod
    def task_follow_nav_mesh_to_coord_advanced(
        ped: Ped,
        x: float,
        y: float,
        z: float,
        speed: float,
        timeout: int,
        unkFloat: float,
        unkInt: int,
        unkX: float,
        unkY: float,
        unkZ: float,
        unk_40000f: float,
        /,
    ) -> None: ...
    """TASK_FOLLOW_POINT_ROUTE: Makes the ped go on a point route."""
    @staticmethod
    def task_follow_point_route(ped: Ped, speed: float, routeMode: int, /) -> None: ...
    """TASK_FOLLOW_TO_OFFSET_OF_ENTITY: p6 always -1"""
    @staticmethod
    def task_follow_to_offset_of_entity(
        ped: Ped,
        entity: Entity,
        offsetX: float,
        offsetY: float,
        offsetZ: float,
        movementSpeed: float,
        timeout: int,
        stoppingRange: float,
        persistFollowing: bool,
        /,
    ) -> None: ...
    """TASK_GO_STRAIGHT_TO_COORD: Provides the task go straight to coord native operation."""
    @staticmethod
    def task_go_straight_to_coord(
        ped: Ped,
        x: float,
        y: float,
        z: float,
        speed: float,
        timeout: int,
        targetHeading: float,
        distanceToSlide: float,
        /,
    ) -> None: ...
    """TASK_GO_STRAIGHT_TO_COORD_RELATIVE_TO_ENTITY: Provides the task go straight to coord relative to entity native operation."""
    @staticmethod
    def task_go_straight_to_coord_relative_to_entity(
        entity1: Entity,
        entity2: Entity,
        p2: float,
        p3: float,
        p4: float,
        p5: float,
        p6: int,
        /,
    ) -> None: ...
    """TASK_PLAY_ANIM: Provides the task play anim native operation."""
    @staticmethod
    def task_play_anim(
        ped: Ped,
        animDictionary: str,
        animationName: str,
        blendInSpeed: float,
        blendOutSpeed: float,
        duration: int,
        flag: int,
        playbackRate: float,
        lockX: bool,
        lockY: bool,
        lockZ: bool,
        /,
    ) -> None: ...
    """TASK_PLAY_ANIM_ADVANCED: Similar in functionality to [`TASK_PLAY_ANIM`](#_0xEA47FE3719165B94), except the position and rotation parameters let you specify the initial position and rotation of the task. The ped is teleported to the position specified."""
    @staticmethod
    def task_play_anim_advanced(
        ped: Ped,
        animDictionary: str,
        animationName: str,
        posX: float,
        posY: float,
        posZ: float,
        rotX: float,
        rotY: float,
        rotZ: float,
        blendInSpeed: float,
        blendOutSpeed: float,
        duration: int,
        flag: int,
        animTime: float,
        p14: int,
        p15: int,
        /,
    ) -> None: ...
    """TASK_REACT_AND_FLEE_PED: Provides the task react and flee ped native operation."""
    @staticmethod
    def task_react_and_flee_ped(ped: Ped, fleeTarget: Ped, /) -> None: ...
    """TASK_SHOOT_AT_COORD: Firing Pattern Hash Information: https://pastebin.com/Px036isB"""
    @staticmethod
    def task_shoot_at_coord(
        ped: Ped, x: float, y: float, z: float, duration: int, firingPattern: Hash, /
    ) -> None: ...
    """TASK_SHOOT_AT_ENTITY: Entity aimedentity;"""
    @staticmethod
    def task_shoot_at_entity(
        entity: Entity, target: Entity, duration: int, firingPattern: Hash, /
    ) -> None: ...
    """TASK_SMART_FLEE_COORD: Makes the specified ped flee the specified distance from the specified position."""
    @staticmethod
    def task_smart_flee_coord(
        ped: Ped,
        x: float,
        y: float,
        z: float,
        distance: float,
        time: int,
        p6: bool,
        p7: bool,
        /,
    ) -> None: ...
    """TASK_SMART_FLEE_PED: Makes a ped run away from another ped (fleeTarget)."""
    @staticmethod
    def task_smart_flee_ped(
        ped: Ped, fleeTarget: Ped, distance: float, fleeTime: int, p4: bool, p5: bool, /
    ) -> None: ...

class _WeaponNatives:
    """ADD_AMMO_TO_PED: Provides the add ammo to ped native operation."""
    @staticmethod
    def add_ammo_to_ped(ped: Ped, weaponHash: Hash, ammo: int, /) -> None: ...
    """_ADD_AMMO_TO_PED_BY_TYPE: Provides the add ammo to ped by type native operation."""
    @staticmethod
    def _add_ammo_to_ped_by_type(ped: Ped, ammoType: Hash, ammo: int, /) -> None: ...
    """CLEAR_ENTITY_LAST_WEAPON_DAMAGE: Provides the clear entity last weapon damage native operation."""
    @staticmethod
    def clear_entity_last_weapon_damage(entity: Entity, /) -> None: ...
    """CLEAR_PED_LAST_WEAPON_DAMAGE: Does NOT seem to work with HAS_PED_BEEN_DAMAGED_BY_WEAPON. Use CLEAR_ENTITY_LAST_WEAPON_DAMAGE and HAS_ENTITY_BEEN_DAMAGED_BY_WEAPON instead."""
    @staticmethod
    def clear_ped_last_weapon_damage(ped: Ped, /) -> None: ...
    """GET_AMMO_IN_CLIP: Provides the get ammo in clip native operation."""
    @staticmethod
    def get_ammo_in_clip(
        ped: Ped, weaponHash: Hash, ammo: int, /
    ) -> tuple[bool, int]: ...
    """GET_AMMO_IN_PED_WEAPON: WEAPON::GET_AMMO_IN_PED_WEAPON(PLAYER::PLAYER_PED_ID(), a_0)"""
    @staticmethod
    def get_ammo_in_ped_weapon(ped: Ped, weaponhash: Hash, /) -> int: ...
    """_GET_AMMO_IN_VEHICLE_WEAPON_CLIP: Provides the get ammo in vehicle weapon clip native operation."""
    @staticmethod
    def _get_ammo_in_vehicle_weapon_clip(
        vehicle: Vehicle, seat: int, ammo: int, /
    ) -> bool: ...
    """GET_PED_AMMO_BY_TYPE: Provides the get ped ammo by type native operation."""
    @staticmethod
    def get_ped_ammo_by_type(ped: Ped, ammoType: Hash, /) -> int: ...
    """GET_PED_AMMO_TYPE_FROM_WEAPON: Returns the current ammo type of the specified ped's specified weapon."""
    @staticmethod
    def get_ped_ammo_type_from_weapon(ped: Ped, weaponHash: Hash, /) -> int: ...
    """_GET_PED_AMMO_TYPE_FROM_WEAPON_2: Returns the base/default ammo type of the specified ped's specified weapon."""
    @staticmethod
    def _get_ped_ammo_type_from_weapon_2(ped: Ped, weaponHash: Hash, /) -> int: ...
    """GET_SELECTED_PED_WEAPON: Hash: The weapon hash of the currently selected weapon."""
    @staticmethod
    def get_selected_ped_weapon(ped: Ped, /) -> int: ...
    """_GET_TIME_BEFORE_VEHICLE_WEAPON_RELOAD_FINISHES: Provides the get time before vehicle weapon reload finishes native operation."""
    @staticmethod
    def _get_time_before_vehicle_weapon_reload_finishes(
        vehicle: Vehicle, seat: int, /
    ) -> int: ...
    """_GET_VEHICLE_WEAPON_RELOAD_TIME: Provides the get vehicle weapon reload time native operation."""
    @staticmethod
    def _get_vehicle_weapon_reload_time(vehicle: Vehicle, seat: int, /) -> float: ...
    """GET_WEAPON_CLIP_SIZE: Use it like this:"""
    @staticmethod
    def get_weapon_clip_size(weaponHash: Hash, /) -> int: ...
    """GET_WEAPON_COMPONENT_HUD_STATS: Provides the get weapon component hud stats native operation."""
    @staticmethod
    def get_weapon_component_hud_stats(
        componentHash: Hash, outData: int, /
    ) -> tuple[bool, int]: ...
    """GET_WEAPON_COMPONENT_TYPE_MODEL: Provides the get weapon component type model native operation."""
    @staticmethod
    def get_weapon_component_type_model(componentHash: Hash, /) -> int: ...
    """_GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_COUNT: Provides the get weapon component variant extra component count native operation."""
    @staticmethod
    def _get_weapon_component_variant_extra_component_count(
        componentHash: Hash, /
    ) -> int: ...
    """_GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_MODEL: Provides the get weapon component variant extra component model native operation."""
    @staticmethod
    def _get_weapon_component_variant_extra_component_model(
        componentHash: Hash, extraComponentIndex: int, /
    ) -> int: ...
    """GET_WEAPON_DAMAGE: This native does not return damages of weapons from the melee and explosive group."""
    @staticmethod
    def get_weapon_damage(weaponHash: Hash, componentHash: Hash, /) -> float: ...
    """GET_WEAPON_DAMAGE_TYPE: Provides the get weapon damage type native operation."""
    @staticmethod
    def get_weapon_damage_type(weaponHash: Hash, /) -> int: ...
    """GET_WEAPON_HUD_STATS: struct WeaponHudStatsData"""
    @staticmethod
    def get_weapon_hud_stats(weaponHash: Hash, outData: int, /) -> tuple[bool, int]: ...
    """GET_WEAPON_OBJECT_FROM_PED: Drops the current weapon and returns the object"""
    @staticmethod
    def get_weapon_object_from_ped(ped: Ped, p1: bool, /) -> int: ...
    """_GET_WEAPON_OBJECT_LIVERY_COLOR: Provides the get weapon object livery color native operation."""
    @staticmethod
    def _get_weapon_object_livery_color(
        weaponObject: Object, camoComponentHash: Hash, /
    ) -> int: ...
    """GET_WEAPON_OBJECT_TINT_INDEX: Provides the get weapon object tint index native operation."""
    @staticmethod
    def get_weapon_object_tint_index(weapon: Object, /) -> int: ...
    """_GET_WEAPON_TIME_BETWEEN_SHOTS: Provides the get weapon time between shots native operation."""
    @staticmethod
    def _get_weapon_time_between_shots(weaponHash: Hash, /) -> float: ...
    """GET_WEAPON_TINT_COUNT: Provides the get weapon tint count native operation."""
    @staticmethod
    def get_weapon_tint_count(weaponHash: Hash, /) -> int: ...
    """GET_WEAPONTYPE_GROUP: Gets and returns the hash of the group of the specified weapon (group names can be found/changed under "Group" in the weapons' meta file)."""
    @staticmethod
    def get_weapontype_group(weaponHash: Hash, /) -> int: ...
    """GET_WEAPONTYPE_MODEL: Returns the model of any weapon."""
    @staticmethod
    def get_weapontype_model(weaponHash: Hash, /) -> int: ...
    """GET_WEAPONTYPE_SLOT: Provides the get weapontype slot native operation."""
    @staticmethod
    def get_weapontype_slot(weaponHash: Hash, /) -> int: ...
    """GIVE_WEAPON_COMPONENT_TO_PED: Provides the give weapon component to ped native operation."""
    @staticmethod
    def give_weapon_component_to_ped(
        ped: Ped, weaponHash: Hash, componentHash: Hash, /
    ) -> None: ...
    """GIVE_WEAPON_COMPONENT_TO_WEAPON_OBJECT: addonHash:"""
    @staticmethod
    def give_weapon_component_to_weapon_object(
        weaponObject: Object, addonHash: Hash, /
    ) -> None: ...
    """GIVE_WEAPON_TO_PED: Provides the give weapon to ped native operation."""
    @staticmethod
    def give_weapon_to_ped(
        ped: Ped,
        weaponHash: Hash,
        ammoCount: int,
        isHidden: bool,
        bForceInHand: bool,
        /,
    ) -> None: ...
    """HAS_PED_GOT_WEAPON: p2 should be FALSE, otherwise it seems to always return FALSE"""
    @staticmethod
    def has_ped_got_weapon(ped: Ped, weaponHash: Hash, p2: bool, /) -> bool: ...
    """HAS_PED_GOT_WEAPON_COMPONENT: Provides the has ped got weapon component native operation."""
    @staticmethod
    def has_ped_got_weapon_component(
        ped: Ped, weaponHash: Hash, componentHash: Hash, /
    ) -> bool: ...
    """HAS_WEAPON_ASSET_LOADED: Provides the has weapon asset loaded native operation."""
    @staticmethod
    def has_weapon_asset_loaded(weaponHash: Hash, /) -> bool: ...

class _WorldNatives:
    """ACTIVATE_INTERIOR_ENTITY_SET: More info: http://gtaforums.com/topic/836367-adding-props-to-interiors/"""
    @staticmethod
    def activate_interior_entity_set(interior: int, entitySetName: str, /) -> None: ...
    """ADD_PICKUP_TO_INTERIOR_ROOM_BY_NAME: Provides the add pickup to interior room by name native operation."""
    @staticmethod
    def add_pickup_to_interior_room_by_name(
        pickup: Pickup, roomName: str, /
    ) -> None: ...
    """CAP_INTERIOR: Does something similar to INTERIOR::DISABLE_INTERIOR"""
    @staticmethod
    def cap_interior(interiorID: int, toggle: bool, /) -> None: ...
    """CLEAR_FOCUS: Provides the clear focus native operation."""
    @staticmethod
    def clear_focus() -> None: ...
    """_CLEAR_INTERIOR_FOR_ENTITY: Immediately removes entity from an interior. Like sets entity to `limbo` room."""
    @staticmethod
    def _clear_interior_for_entity(entity: Entity, /) -> None: ...
    """DEACTIVATE_INTERIOR_ENTITY_SET: Provides the deactivate interior entity set native operation."""
    @staticmethod
    def deactivate_interior_entity_set(
        interior: int, entitySetName: str, /
    ) -> None: ...
    """DISABLE_INTERIOR: Example:"""
    @staticmethod
    def disable_interior(interiorID: int, toggle: bool, /) -> None: ...
    """GET_CLOSEST_FIRE_POS: Returns TRUE if it found something. FALSE if not."""
    @staticmethod
    def get_closest_fire_pos(
        outPosition: int, x: float, y: float, z: float, /
    ) -> tuple[bool, Vector3]: ...
    """_GET_GLOBAL_WATER_TYPE: Provides the get global water type native operation."""
    @staticmethod
    def _get_global_water_type() -> int: ...
    """GET_INTERIOR_AT_COORDS: Returns interior ID from specified coordinates. If coordinates are outside, then it returns 0."""
    @staticmethod
    def get_interior_at_coords(x: float, y: float, z: float, /) -> int: ...
    """GET_INTERIOR_AT_COORDS_WITH_TYPE: Returns the interior ID representing the requested interior at that location (if found?). The supplied interior string is not the same as the one used to load the interior."""
    @staticmethod
    def get_interior_at_coords_with_type(
        x: float, y: float, z: float, interiorType: str, /
    ) -> int: ...
    """GET_INTERIOR_AT_COORDS_WITH_TYPEHASH: Hashed version of GET_INTERIOR_AT_COORDS_WITH_TYPE"""
    @staticmethod
    def get_interior_at_coords_with_typehash(
        x: float, y: float, z: float, typeHash: Hash, /
    ) -> int: ...
    """GET_INTERIOR_FROM_COLLISION: Provides the get interior from collision native operation."""
    @staticmethod
    def get_interior_from_collision(x: float, y: float, z: float, /) -> int: ...
    """GET_INTERIOR_FROM_ENTITY: Returns the handle of the interior that the entity is in. Returns 0 if outside."""
    @staticmethod
    def get_interior_from_entity(entity: Entity, /) -> int: ...
    """GET_INTERIOR_FROM_PRIMARY_VIEW: Provides the get interior from primary view native operation."""
    @staticmethod
    def get_interior_from_primary_view() -> int: ...
    """GET_INTERIOR_GROUP_ID: Returns the group ID of the specified interior. For example, regular interiors have group 0, subway interiors have group 1. There are a few other groups too."""
    @staticmethod
    def get_interior_group_id(interior: int, /) -> int: ...
    """GET_INTERIOR_HEADING: Returns interior heading in radians. Multiply the returned value with 57.29578 (or 180.0 / math.pi) to convert it to degrees."""
    @staticmethod
    def get_interior_heading(interior: int, /) -> float: ...
    """GET_INTERIOR_LOCATION_AND_NAMEHASH: Provides the get interior location and namehash native operation."""
    @staticmethod
    def get_interior_location_and_namehash(
        interior: int, position: int, nameHash: int, /
    ) -> tuple[Vector3, int]: ...
    """GET_NAME_OF_ZONE: Provides the get name of zone native operation."""
    @staticmethod
    def get_name_of_zone(x: float, y: float, z: float, /) -> str: ...
    """GET_NUMBER_OF_FIRES_IN_RANGE: Provides the get number of fires in range native operation."""
    @staticmethod
    def get_number_of_fires_in_range(
        x: float, y: float, z: float, radius: float, /
    ) -> int: ...
    """GET_OFFSET_FROM_INTERIOR_IN_WORLD_COORDS: Provides the get offset from interior in world coords native operation."""
    @staticmethod
    def get_offset_from_interior_in_world_coords(
        interior: int, x: float, y: float, z: float, /
    ) -> Vector3: ...
    """GET_WATER_HEIGHT: Retrieves the depth of the water beneath the specified position, accounting for the waves."""
    @staticmethod
    def get_water_height(
        x: float, y: float, z: float, height: int, /
    ) -> tuple[bool, float]: ...
    """GET_WATER_HEIGHT_NO_WAVES: Retrieves the depth of the water beneath the specified position, disregarding wave effects."""
    @staticmethod
    def get_water_height_no_waves(
        x: float, y: float, z: float, height: int, /
    ) -> tuple[bool, float]: ...
    """GET_ZONE_AT_COORDS: Provides the get zone at coords native operation."""
    @staticmethod
    def get_zone_at_coords(x: float, y: float, z: float, /) -> int: ...
    """GET_ZONE_FROM_NAME_ID: Refer to https://docs.fivem.net/docs/game-references/zones/ for a list of all zones including their integer ID, string ID, short name and full name"""
    @staticmethod
    def get_zone_from_name_id(zoneName: str, /) -> int: ...

class _HudNatives:
    """_ADD_BLIP_FOR_AREA: Adds a rectangular blip for the specified coordinates/area."""
    @staticmethod
    def _add_blip_for_area(
        x: float, y: float, z: float, width: float, height: float, /
    ) -> int: ...
    """ADD_BLIP_FOR_COORD: Creates a blip for the specified coordinates. You can use `SET_BLIP_` natives to change the blip."""
    @staticmethod
    def add_blip_for_coord(x: float, y: float, z: float, /) -> int: ...
    """ADD_BLIP_FOR_ENTITY: Create a blip that by default is red (enemy), you can use [SET_BLIP_AS_FRIENDLY](#_0xC6F43D0E) to make it blue (friend)."""
    @staticmethod
    def add_blip_for_entity(entity: Entity, /) -> int: ...
    """ADD_BLIP_FOR_PICKUP: Provides the add blip for pickup native operation."""
    @staticmethod
    def add_blip_for_pickup(pickup: Pickup, /) -> int: ...
    """ADD_BLIP_FOR_RADIUS: Create a blip with a radius for the specified coordinates (it doesnt create the blip sprite, so you need to use [AddBlipCoords](#_0xC6F43D0E))"""
    @staticmethod
    def add_blip_for_radius(
        posX: float, posY: float, posZ: float, radius: float, /
    ) -> int: ...
    """ADD_POINT_TO_GPS_CUSTOM_ROUTE: Provides the add point to gps custom route native operation."""
    @staticmethod
    def add_point_to_gps_custom_route(x: float, y: float, z: float, /) -> None: ...
    """ADD_POINT_TO_GPS_MULTI_ROUTE: Provides the add point to gps multi route native operation."""
    @staticmethod
    def add_point_to_gps_multi_route(x: float, y: float, z: float, /) -> None: ...
    """ADD_TEXT_COMPONENT_FLOAT: Adds a float to a text component placeholder, replacing `~1~` in the current text command's text label."""
    @staticmethod
    def add_text_component_float(value: float, decimalPlaces: int, /) -> None: ...
    """ADD_TEXT_COMPONENT_FORMATTED_INTEGER: Adds a formatted integer as a text component placeholder, replacing ~a~ in the current text command's text label."""
    @staticmethod
    def add_text_component_formatted_integer(
        value: int, commaSeparated: bool, /
    ) -> None: ...
    """ADD_TEXT_COMPONENT_INTEGER: Provides the add text component integer native operation."""
    @staticmethod
    def add_text_component_integer(value: int, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_BLIP_NAME: Provides the add text component substring blip name native operation."""
    @staticmethod
    def add_text_component_substring_blip_name(blip: Blip, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_KEYBOARD_DISPLAY: Certain characters like `<` will have to be escaped using html entities (e.g. `&lt;`), otherwise the text wont display properly."""
    @staticmethod
    def add_text_component_substring_keyboard_display(string: str, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_PHONE_NUMBER: p1 was always -1"""
    @staticmethod
    def add_text_component_substring_phone_number(p0: str, p1: int, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME: Adds an arbitrary string as a text component placeholder, replacing `~a~` in the current text command's text label."""
    @staticmethod
    def add_text_component_substring_player_name(text: str, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL: Provides the add text component substring text label native operation."""
    @staticmethod
    def add_text_component_substring_text_label(labelName: str, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL_HASH_KEY: It adds the localized text of the specified GXT entry name. Eg. if the argument is GET_HASH_KEY("ES_HELP"), adds "Continue". Just uses a text labels hash key"""
    @staticmethod
    def add_text_component_substring_text_label_hash_key(
        gxtEntryHash: Hash, /
    ) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_TIME: Takes a time in milliseconds and converts it to a string. Use `~a~` to mark the position in your line of text where you want this substring inserted."""
    @staticmethod
    def add_text_component_substring_time(timestamp: int, format: int, /) -> None: ...
    """ADD_TEXT_COMPONENT_SUBSTRING_WEBSITE: This native (along with 0x5F68520888E69014 and 0x6C188BE134E074AA) do not actually filter anything. They simply add the provided text (as of 944)"""
    @staticmethod
    def add_text_component_substring_website(website: str, /) -> None: ...
    """BEGIN_TEXT_COMMAND_BUSYSPINNER_ON: Initializes the text entry for the the text next to a loading prompt. All natives for for building UI texts can be used here"""
    @staticmethod
    def begin_text_command_busyspinner_on(string: str, /) -> None: ...
    """BEGIN_TEXT_COMMAND_CLEAR_PRINT: clears a print text command with this text"""
    @staticmethod
    def begin_text_command_clear_print(text: str, /) -> None: ...

entity: _EntityNatives
hud: _HudNatives
object: _ObjectNatives
ped: _PedNatives
player: _PlayerNatives
task: _TaskNatives
vehicle: _VehicleNatives
weapon: _WeaponNatives
world: _WorldNatives
