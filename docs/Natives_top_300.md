# RP Native Reference

A practical reference of 300 named, original GTA V natives commonly useful in RP and FiveM-style gameplay. The database in `natives/` contains Rockstar originals, not CFX namespace natives; `_0x...` placeholders and project-specific CFX natives are intentionally excluded. Signatures are copied from each source markdown file. Native availability, behavior, hashes, and ABI details can vary by GTA V build, so verify against the target build before relying on a declaration.

## Entity

| Native | Description | C signature |
|---|---|---|
| [APPLY_FORCE_TO_ENTITY](../natives/ENTITY/ApplyForceToEntity.md) | Provides the apply force to entity native operation. | `void APPLY_FORCE_TO_ENTITY(Entity entity, int forceType, float x, float y, float z, float offX, float offY, float offZ, int nComponent, BOOL bLocalForce, BOOL bLocalOffset, BOOL bScaleByMass, BOOL bPlayAudio, BOOL bScaleByTimeWarp);` |
| [APPLY_FORCE_TO_ENTITY_CENTER_OF_MASS](../natives/ENTITY/ApplyForceToEntityCenterOfMass.md) | Apply a force to an entities center of mass. | `void APPLY_FORCE_TO_ENTITY_CENTER_OF_MASS(Entity entity, int forceType, float x, float y, float z, cs_type(BOOL) int nComponent, BOOL bLocalForce, BOOL bScaleByMass, BOOL bApplyToChildren);` |
| [_ATTACH_ENTITY_BONE_TO_ENTITY_BONE](../natives/ENTITY/AttachEntityBoneToEntityBone.md) | Provides the attach entity bone to entity bone native operation. | `void _ATTACH_ENTITY_BONE_TO_ENTITY_BONE(Entity entity1, Entity entity2, int entityBone, int entityBone2, BOOL p4, BOOL p5);` |
| [_ATTACH_ENTITY_BONE_TO_ENTITY_BONE_PHYSICALLY](../natives/ENTITY/AttachEntityBoneToEntityBonePhysically.md) | Provides the attach entity bone to entity bone physically native operation. | `void _ATTACH_ENTITY_BONE_TO_ENTITY_BONE_PHYSICALLY(Entity entity1, Entity entity2, int entityBone, int entityBone2, BOOL p4, BOOL p5);` |
| [ATTACH_ENTITY_TO_ENTITY](../natives/ENTITY/AttachEntityToEntity.md) | Attach an entity to the specified entity. | `void ATTACH_ENTITY_TO_ENTITY(Entity entity1, Entity entity2, int boneIndex, float xPos, float yPos, float zPos, float xRot, float yRot, float zRot, BOOL p9, BOOL useSoftPinning, BOOL collision, BOOL isPed, int rotationOrder, BOOL syncRot);` |
| [ATTACH_ENTITY_TO_ENTITY_PHYSICALLY](../natives/ENTITY/AttachEntityToEntityPhysically.md) | breakForce is the amount of force required to break the bond. | `void ATTACH_ENTITY_TO_ENTITY_PHYSICALLY(Entity entity1, Entity entity2, int boneIndex1, int boneIndex2, float xPos1, float yPos1, float zPos1, float xPos2, float yPos2, float zPos2, float xRot, float yRot, float zRot, float breakForce, BOOL fixedRot, BOOL p15, BOOL collision, BOOL teleport, int p18);` |
| [DELETE_ENTITY](../natives/ENTITY/DeleteEntity.md) | Delete the specified entity, and invalidate the passed handle (i.e., the in/out argument). | `void DELETE_ENTITY(Entity* entity);` |
| [DETACH_ENTITY](../natives/ENTITY/DetachEntity.md) | Provides the detach entity native operation. | `void DETACH_ENTITY(Entity entity, BOOL dynamic, BOOL collision);` |
| [DOES_ENTITY_EXIST](../natives/ENTITY/DoesEntityExist.md) | Checks whether an entity exists in the game world. | `BOOL DOES_ENTITY_EXIST(Entity entity);` |
| [FREEZE_ENTITY_POSITION](../natives/ENTITY/FreezeEntityPosition.md) | Freezes or unfreezes an entity preventing its coordinates to change by the player if set to `true`. You can still change the entity position using [`SET_ENTITY_COORDS`](#_0x06843DA7060A026B). | `void FREEZE_ENTITY_POSITION(Entity entity, BOOL toggle);` |
| [GET_COLLISION_NORMAL_OF_LAST_HIT_FOR_ENTITY](../natives/ENTITY/GetCollisionNormalOfLastHitForEntity.md) | Provides the get collision normal of last hit for entity native operation. | `Vector3 GET_COLLISION_NORMAL_OF_LAST_HIT_FOR_ENTITY(Entity entity);` |
| [GET_ENTITY_ALPHA](../natives/ENTITY/GetEntityAlpha.md) | Provides the get entity alpha native operation. | `int GET_ENTITY_ALPHA(Entity entity);` |
| [GET_ENTITY_ANIM_CURRENT_TIME](../natives/ENTITY/GetEntityAnimCurrentTime.md) | Returns a float value representing animation's current playtime with respect to its total playtime. This value increasing in a range from [0 to 1] and wrap back to 0 when it reach 1. | `float GET_ENTITY_ANIM_CURRENT_TIME(Entity entity, char* animDict, char* animName);` |
| [GET_ENTITY_ANIM_TOTAL_TIME](../natives/ENTITY/GetEntityAnimTotalTime.md) | Returns a float value representing animation's total playtime in milliseconds. | `float GET_ENTITY_ANIM_TOTAL_TIME(Entity entity, char* animDict, char* animName);` |
| [GET_ENTITY_ATTACHED_TO](../natives/ENTITY/GetEntityAttachedTo.md) | Provides the get entity attached to native operation. | `Entity GET_ENTITY_ATTACHED_TO(Entity entity);` |
| [_GET_ENTITY_BONE_COUNT](../natives/ENTITY/GetEntityBoneCount.md) | Provides the get entity bone count native operation. | `int _GET_ENTITY_BONE_COUNT(Entity entity);` |
| [GET_ENTITY_BONE_INDEX_BY_NAME](../natives/ENTITY/GetEntityBoneIndexByName.md) | Returns the index of the bone. If the bone was not found, -1 will be returned. | `int GET_ENTITY_BONE_INDEX_BY_NAME(Entity entity, char* boneName);` |
| [_GET_ENTITY_BONE_POSITION_2](../natives/ENTITY/GetEntityBonePosition_2.md) | Gets the world rotation of the specified bone of the specified entity. | `Vector3 _GET_ENTITY_BONE_POSITION_2(Entity entity, int boneIndex);` |
| [_GET_ENTITY_BONE_ROTATION](../natives/ENTITY/GetEntityBoneRotation.md) | Gets the world rotation of the specified bone of the specified entity. | `Vector3 _GET_ENTITY_BONE_ROTATION(Entity entity, int boneIndex);` |
| [_GET_ENTITY_BONE_ROTATION_LOCAL](../natives/ENTITY/GetEntityBoneRotationLocal.md) | Gets the local rotation of the specified bone of the specified entity. | `Vector3 _GET_ENTITY_BONE_ROTATION_LOCAL(Entity entity, int boneIndex);` |
| [GET_ENTITY_CAN_BE_DAMAGED](../natives/ENTITY/GetEntityCanBeDamaged.md) | Provides the get entity can be damaged native operation. | `BOOL GET_ENTITY_CAN_BE_DAMAGED(Entity entity);` |
| [GET_ENTITY_COLLISION_DISABLED](../natives/ENTITY/GetEntityCollisionDisabled.md) | Provides the get entity collision disabled native operation. | `BOOL GET_ENTITY_COLLISION_DISABLED(Entity entity);` |
| [GET_ENTITY_COORDS](../natives/ENTITY/GetEntityCoords.md) | Gets the current coordinates (world position) for a specified entity. | `Vector3 GET_ENTITY_COORDS(Entity entity, BOOL alive);` |
| [GET_ENTITY_FORWARD_VECTOR](../natives/ENTITY/GetEntityForwardVector.md) | Gets the entity's forward vector. | `Vector3 GET_ENTITY_FORWARD_VECTOR(Entity entity);` |
| [GET_ENTITY_FORWARD_X](../natives/ENTITY/GetEntityForwardX.md) | Gets the X-component of the entity's forward vector. | `float GET_ENTITY_FORWARD_X(Entity entity);` |
| [GET_ENTITY_FORWARD_Y](../natives/ENTITY/GetEntityForwardY.md) | Gets the Y-component of the entity's forward vector. | `float GET_ENTITY_FORWARD_Y(Entity entity);` |
| [GET_ENTITY_HEADING](../natives/ENTITY/GetEntityHeading.md) | Returns the heading of the entity in degrees. Also know as the "Yaw" of an entity. | `float GET_ENTITY_HEADING(Entity entity);` |
| [GET_ENTITY_HEADING_FROM_EULERS](../natives/ENTITY/GetEntityHeadingFromEulers.md) | Gets the heading of the entity physics in degrees, which tends to be more accurate than just [`GET_ENTITY_HEADING`](#_0xE83D4F9BA2A38914). This can be clearly seen while, for example, ragdolling a ped/player. | `float GET_ENTITY_HEADING_FROM_EULERS(Entity entity);` |
| [GET_ENTITY_HEALTH](../natives/ENTITY/GetEntityHealth.md) | Returns an integer value of entity's current health. | `int GET_ENTITY_HEALTH(Entity entity);` |
| [GET_ENTITY_HEIGHT](../natives/ENTITY/GetEntityHeight.md) | Provides the get entity height native operation. | `float GET_ENTITY_HEIGHT(Entity entity, float X, float Y, float Z, BOOL atTop, BOOL inWorldCoords);` |

<!-- 30 rows -->

## Player

| Native | Description | C signature |
|---|---|---|
| [CHANGE_PLAYER_PED](../natives/PLAYER/ChangePlayerPed.md) | Provides the change player ped native operation. | `void CHANGE_PLAYER_PED(Player player, Ped ped, BOOL b2, BOOL resetDamage);` |
| [DISABLE_PLAYER_FIRING](../natives/PLAYER/DisablePlayerFiring.md) | Inhibits the player from using any method of combat including melee and firearms. | `void DISABLE_PLAYER_FIRING(Player player, BOOL toggle);` |
| [DISABLE_PLAYER_VEHICLE_REWARDS](../natives/PLAYER/DisablePlayerVehicleRewards.md) | Disables vehicle rewards for the current frame. | `void DISABLE_PLAYER_VEHICLE_REWARDS(Player player);` |
| [GET_IS_PLAYER_DRIVING_ON_HIGHWAY](../natives/PLAYER/GetIsPlayerDrivingOnHighway.md) | Returns a boolean value representing if the player is driving on a highway. | `BOOL GET_IS_PLAYER_DRIVING_ON_HIGHWAY(Player playerId);` |
| [GET_PLAYER_CURRENT_STEALTH_NOISE](../natives/PLAYER/GetPlayerCurrentStealthNoise.md) | Provides the get player current stealth noise native operation. | `float GET_PLAYER_CURRENT_STEALTH_NOISE(Player player);` |
| [GET_PLAYER_GROUP](../natives/PLAYER/GetPlayerGroup.md) | Returns the group ID the player is member of. | `int GET_PLAYER_GROUP(Player player);` |
| [_GET_PLAYER_HEALTH_RECHARGE_LIMIT](../natives/PLAYER/GetPlayerHealthRechargeLimit.md) | Provides the get player health recharge limit native operation. | `float _GET_PLAYER_HEALTH_RECHARGE_LIMIT(Player player);` |
| [GET_PLAYER_INDEX](../natives/PLAYER/GetPlayerIndex.md) | Returns the same as PLAYER_ID and NETWORK_PLAYER_ID_TO_INT | `Player GET_PLAYER_INDEX();` |
| [GET_PLAYER_INVINCIBLE](../natives/PLAYER/GetPlayerInvincible.md) | This native will only return true if a player was made invincible with [`SET_PLAYER_INVINCIBLE`](#_0x239528EACDC3E7DE). | `BOOL GET_PLAYER_INVINCIBLE(Player player);` |
| [GET_PLAYER_MAX_ARMOUR](../natives/PLAYER/GetPlayerMaxArmour.md) | Provides the get player max armour native operation. | `int GET_PLAYER_MAX_ARMOUR(Player player);` |
| [GET_PLAYER_NAME](../natives/PLAYER/GetPlayerName.md) | Returns the players name from a specified player index | `char* GET_PLAYER_NAME(Player player);` |
| [GET_PLAYER_PED](../natives/PLAYER/GetPlayerPed.md) | Gets the ped for a specified player index. | `Ped GET_PLAYER_PED(Player playerId);` |
| [GET_PLAYER_PED_SCRIPT_INDEX](../natives/PLAYER/GetPlayerPedScriptIndex.md) | Does the same like PLAYER::GET_PLAYER_PED | `Ped GET_PLAYER_PED_SCRIPT_INDEX(Player player);` |
| [GET_PLAYER_RGB_COLOUR](../natives/PLAYER/GetPlayerRgbColour.md) | Provides the get player rgb colour native operation. | `void GET_PLAYER_RGB_COLOUR(Player player, int* r, int* g, int* b);` |
| [GET_PLAYERS_LAST_VEHICLE](../natives/PLAYER/GetPlayersLastVehicle.md) | This native will return `0` if the last vehicle the player was in was destroyed. | `Vehicle GET_PLAYERS_LAST_VEHICLE();` |
| [GET_PLAYER_SPRINT_STAMINA_REMAINING](../natives/PLAYER/GetPlayerSprintStaminaRemaining.md) | Provides the get player sprint stamina remaining native operation. | `float GET_PLAYER_SPRINT_STAMINA_REMAINING(Player player);` |
| [GET_PLAYER_SPRINT_TIME_REMAINING](../natives/PLAYER/GetPlayerSprintTimeRemaining.md) | Provides the get player sprint time remaining native operation. | `float GET_PLAYER_SPRINT_TIME_REMAINING(Player player);` |
| [GET_PLAYER_TARGET_ENTITY](../natives/PLAYER/GetPlayerTargetEntity.md) | Assigns the handle of locked-on melee target to *entity that you pass it. | `BOOL GET_PLAYER_TARGET_ENTITY(Player player, Entity* entity);` |
| [GET_PLAYER_TEAM](../natives/PLAYER/GetPlayerTeam.md) | Gets the player's team. | `int GET_PLAYER_TEAM(Player player);` |
| [GET_PLAYER_UNDERWATER_TIME_REMAINING](../natives/PLAYER/GetPlayerUnderwaterTimeRemaining.md) | Provides the get player underwater time remaining native operation. | `float GET_PLAYER_UNDERWATER_TIME_REMAINING(Player player);` |

<!-- 20 rows -->

## Ped and Appearance

| Native | Description | C signature |
|---|---|---|
| [ADD_ARMOUR_TO_PED](../natives/PED/AddArmourToPed.md) | Same as SET_PED_ARMOUR, but ADDS 'amount' to the armor the Ped already has. | `void ADD_ARMOUR_TO_PED(Ped ped, int amount);` |
| [ADD_PED_DECORATION_FROM_HASHES](../natives/PED/AddPedDecorationFromHashes.md) | Applies an Item from a PedDecorationCollection to a ped. These include tattoos and shirt decals. | `void ADD_PED_DECORATION_FROM_HASHES(Ped ped, Hash collection, Hash overlay);` |
| [ADD_PED_DECORATION_FROM_HASHES_IN_CORONA](../natives/PED/AddPedDecorationFromHashesInCorona.md) | Provides the add ped decoration from hashes in corona native operation. | `void ADD_PED_DECORATION_FROM_HASHES_IN_CORONA(Ped ped, Hash collection, Hash overlay);` |
| [ADD_RELATIONSHIP_GROUP](../natives/PED/AddRelationshipGroup.md) | Can't select void. This function returns nothing. The hash of the created relationship group is output in the second parameter. | `Any ADD_RELATIONSHIP_GROUP(char* name, Hash* groupHash);` |
| [CAN_PED_IN_COMBAT_SEE_TARGET](../natives/PED/CanPedInCombatSeeTarget.md) | Provides the can ped in combat see target native operation. | `BOOL CAN_PED_IN_COMBAT_SEE_TARGET(Ped ped, Ped target);` |
| [CAN_PED_RAGDOLL](../natives/PED/CanPedRagdoll.md) | Prevents the ped from going limp. | `BOOL CAN_PED_RAGDOLL(Ped ped);` |
| [CAN_PED_SEE_HATED_PED](../natives/PED/CanPedSeeHatedPed.md) | Provides the can ped see hated ped native operation. | `BOOL CAN_PED_SEE_HATED_PED(Ped ped1, Ped ped2);` |
| [CLEAR_PED_ALTERNATE_MOVEMENT_ANIM](../natives/PED/ClearPedAlternateMovementAnim.md) | Provides the clear ped alternate movement anim native operation. | `void CLEAR_PED_ALTERNATE_MOVEMENT_ANIM(Ped ped, int stance, float p2);` |
| [CLEAR_PED_ALTERNATE_WALK_ANIM](../natives/PED/ClearPedAlternateWalkAnim.md) | Provides the clear ped alternate walk anim native operation. | `void CLEAR_PED_ALTERNATE_WALK_ANIM(Ped ped, float p1);` |
| [CLEAR_PED_BLOOD_DAMAGE](../natives/PED/ClearPedBloodDamage.md) | Clears the blood on a ped. | `void CLEAR_PED_BLOOD_DAMAGE(Ped ped);` |
| [CLEAR_PED_BLOOD_DAMAGE_BY_ZONE](../natives/PED/ClearPedBloodDamageByZone.md) | Somehow related to changing ped's clothes. | `void CLEAR_PED_BLOOD_DAMAGE_BY_ZONE(Ped ped, int p1);` |
| [_CLEAR_PED_COVER_CLIPSET_OVERRIDE](../natives/PED/ClearPedCoverClipsetOverride.md) | Provides the  clear ped cover clipset override native operation. | `void _CLEAR_PED_COVER_CLIPSET_OVERRIDE(Ped ped);` |
| [CLEAR_PED_DAMAGE_DECAL_BY_ZONE](../natives/PED/ClearPedDamageDecalByZone.md) | Provides the clear ped damage decal by zone native operation. | `void CLEAR_PED_DAMAGE_DECAL_BY_ZONE(Ped ped, int p1, char* p2);` |
| [CLEAR_PED_DECORATIONS](../natives/PED/ClearPedDecorations.md) | Provides the clear ped decorations native operation. | `void CLEAR_PED_DECORATIONS(Ped ped);` |
| [CLEAR_PED_DECORATIONS_LEAVE_SCARS](../natives/PED/ClearPedDecorationsLeaveScars.md) | Provides the clear ped decorations leave scars native operation. | `void CLEAR_PED_DECORATIONS_LEAVE_SCARS(Ped ped);` |
| [CLEAR_PED_DRIVE_BY_CLIPSET_OVERRIDE](../natives/PED/ClearPedDriveByClipsetOverride.md) | Provides the clear ped drive by clipset override native operation. | `void CLEAR_PED_DRIVE_BY_CLIPSET_OVERRIDE(Ped ped);` |
| [CLEAR_PED_ENV_DIRT](../natives/PED/ClearPedEnvDirt.md) | Provides the clear ped env dirt native operation. | `void CLEAR_PED_ENV_DIRT(Ped ped);` |
| [CLEAR_PED_LAST_DAMAGE_BONE](../natives/PED/ClearPedLastDamageBone.md) | Provides the clear ped last damage bone native operation. | `void CLEAR_PED_LAST_DAMAGE_BONE(Ped ped);` |
| [CLEAR_PED_NON_CREATION_AREA](../natives/PED/ClearPedNonCreationArea.md) | Provides the clear ped non creation area native operation. | `void CLEAR_PED_NON_CREATION_AREA();` |
| [CLEAR_PED_PROP](../natives/PED/ClearPedProp.md) | Provides the clear ped prop native operation. | `void CLEAR_PED_PROP(Ped ped, int propId);` |
| [CLEAR_PED_SCUBA_GEAR_VARIATION](../natives/PED/ClearPedScubaGearVariation.md) | Removes the scubagear (for mp male: component id: 8, drawableId: 123, textureId: any) from peds. Does not play the 'remove scuba gear' animation, but instantly removes it. | `void CLEAR_PED_SCUBA_GEAR_VARIATION(Ped ped);` |
| [CLEAR_PED_STORED_HAT_PROP](../natives/PED/ClearPedStoredHatProp.md) | Provides the clear ped stored hat prop native operation. | `void CLEAR_PED_STORED_HAT_PROP(Ped ped);` |
| [CLEAR_PED_WETNESS](../natives/PED/ClearPedWetness.md) | It clears the wetness of the selected Ped/Player. Clothes have to be wet to notice the difference. | `void CLEAR_PED_WETNESS(Ped ped);` |
| [CLEAR_RAGDOLL_BLOCKING_FLAGS](../natives/PED/ClearRagdollBlockingFlags.md) | There seem to be 26 flags | `void CLEAR_RAGDOLL_BLOCKING_FLAGS(Ped ped, int flags);` |
| [CLEAR_RELATIONSHIP_BETWEEN_GROUPS](../natives/PED/ClearRelationshipBetweenGroups.md) | Clears the relationship between two groups. This should be called twice (once for each group). | `void CLEAR_RELATIONSHIP_BETWEEN_GROUPS(int relationship, Hash group1, Hash group2);` |
| [CLONE_PED](../natives/PED/ClonePed.md) | Creates a copy of the passed ped, optionally setting it as local and/or shallow-copying the head blend data. | `Ped CLONE_PED(Ped ped, cs_type(float) BOOL isNetwork, BOOL bScriptHostPed, BOOL copyHeadBlendFlag);` |
| [_CLONE_PED_EX](../natives/PED/ClonePedEx.md) | Used one time in fmmc_launcher.c instead of CLONE_PED because ? | `Ped _CLONE_PED_EX(Ped ped, cs_type(Any) float heading, cs_type(Any) BOOL isNetwork, cs_type(Any) BOOL bScriptHostPed, Any p4);` |
| [CLONE_PED_TO_TARGET](../natives/PED/ClonePedToTarget.md) | Copies ped's components and props to targetPed. | `void CLONE_PED_TO_TARGET(Ped ped, Ped targetPed);` |
| [_CLONE_PED_TO_TARGET_EX](../natives/PED/ClonePedToTargetEx.md) | Provides the clone ped to target ex native operation. | `void _CLONE_PED_TO_TARGET_EX(Ped ped, Ped targetPed, Any p2);` |
| [CREATE_PED](../natives/PED/CreatePed.md) | Creates a ped (biped character, pedestrian, actor) with the specified model at the specified position and heading. | `Ped CREATE_PED(int pedType, Hash modelHash, float x, float y, float z, float heading, BOOL isNetwork, BOOL bScriptHostPed);` |
| [CREATE_PED_INSIDE_VEHICLE](../natives/PED/CreatePedInsideVehicle.md) | Provides the create ped inside vehicle native operation. | `Ped CREATE_PED_INSIDE_VEHICLE(Vehicle vehicle, int pedType, Hash modelHash, int seat, BOOL isNetwork, BOOL bScriptHostPed);` |
| [DELETE_PED](../natives/PED/DeletePed.md) | Deletes the specified ped, then sets the handle pointed to by the pointer to NULL. | `void DELETE_PED(Ped* ped);` |
| [_DOES_RELATIONSHIP_GROUP_EXIST](../natives/PED/DoesRelationshipGroupExist.md) | Provides the does relationship group exist native operation. | `BOOL _DOES_RELATIONSHIP_GROUP_EXIST(cs_type(Any) Hash groupHash);` |
| [GET_COMBAT_FLOAT](../natives/PED/GetCombatFloat.md) | Provides the get combat float native operation. | `float GET_COMBAT_FLOAT(Ped ped, int p1);` |
| [GET_NUMBER_OF_PED_DRAWABLE_VARIATIONS](../natives/PED/GetNumberOfPedDrawableVariations.md) | Provides the get number of ped drawable variations native operation. | `int GET_NUMBER_OF_PED_DRAWABLE_VARIATIONS(Ped ped, int componentId);` |
| [GET_NUMBER_OF_PED_PROP_DRAWABLE_VARIATIONS](../natives/PED/GetNumberOfPedPropDrawableVariations.md) | Provides the get number of ped prop drawable variations native operation. | `int GET_NUMBER_OF_PED_PROP_DRAWABLE_VARIATIONS(Ped ped, int propId);` |
| [GET_NUMBER_OF_PED_PROP_TEXTURE_VARIATIONS](../natives/PED/GetNumberOfPedPropTextureVariations.md) | Need to check behavior when drawableId = -1 | `int GET_NUMBER_OF_PED_PROP_TEXTURE_VARIATIONS(Ped ped, int propId, int drawableId);` |
| [GET_NUMBER_OF_PED_TEXTURE_VARIATIONS](../natives/PED/GetNumberOfPedTextureVariations.md) | Provides the get number of ped texture variations native operation. | `int GET_NUMBER_OF_PED_TEXTURE_VARIATIONS(Ped ped, int componentId, int drawableId);` |
| [GET_PED_ACCURACY](../natives/PED/GetPedAccuracy.md) | Provides the get ped accuracy native operation. | `int GET_PED_ACCURACY(Ped ped);` |
| [GET_PED_ALERTNESS](../natives/PED/GetPedAlertness.md) | Returns the ped's alertness (0-3). | `int GET_PED_ALERTNESS(Ped ped);` |
| [GET_PED_ARMOUR](../natives/PED/GetPedArmour.md) | Provides the get ped armour native operation. | `int GET_PED_ARMOUR(Ped ped);` |
| [GET_PED_AS_GROUP_LEADER](../natives/PED/GetPedAsGroupLeader.md) | Provides the get ped as group leader native operation. | `Ped GET_PED_AS_GROUP_LEADER(int groupID);` |
| [GET_PED_AS_GROUP_MEMBER](../natives/PED/GetPedAsGroupMember.md) | Provides the get ped as group member native operation. | `Ped GET_PED_AS_GROUP_MEMBER(int groupID, int memberNumber);` |
| [GET_PED_BONE_COORDS](../natives/PED/GetPedBoneCoords.md) | Gets the position of the specified bone of the specified ped. | `Vector3 GET_PED_BONE_COORDS(Ped ped, int boneId, float offsetX, float offsetY, float offsetZ);` |
| [GET_PED_BONE_INDEX](../natives/PED/GetPedBoneIndex.md) | Provides the get ped bone index native operation. | `int GET_PED_BONE_INDEX(Ped ped, int boneId);` |

<!-- 45 rows -->

## Vehicle

| Native | Description | C signature |
|---|---|---|
| [ARE_ALL_VEHICLE_WINDOWS_INTACT](../natives/VEHICLE/AreAllVehicleWindowsIntact.md) | Appears to return false if any window is broken. | `BOOL ARE_ALL_VEHICLE_WINDOWS_INTACT(Vehicle vehicle);` |
| [ARE_ANY_VEHICLE_SEATS_FREE](../natives/VEHICLE/AreAnyVehicleSeatsFree.md) | Dead peds still count as occupying a seat until the body is removed, so a vehicle full of corpses returns `false`. Peds tasked to enter the vehicle but not yet inserted do not occupy their target seat. | `BOOL ARE_ANY_VEHICLE_SEATS_FREE(Vehicle vehicle);` |
| [CREATE_VEHICLE](../natives/VEHICLE/CreateVehicle.md) | Creates a vehicle with the specified model at the specified position. This vehicle will initially be owned by the creating | `Vehicle CREATE_VEHICLE(Hash modelHash, float x, float y, float z, float heading, BOOL isNetwork, BOOL netMissionEntity);` |
| [DELETE_VEHICLE](../natives/VEHICLE/DeleteVehicle.md) | Deletes a vehicle. | `void DELETE_VEHICLE(Vehicle* vehicle);` |
| [_DOES_VEHICLE_TYRE_EXIST](../natives/VEHICLE/DoesVehicleTyreExist.md) | Checks if vehicle tyre at index exists. Also returns false if tyre was removed. | `BOOL _DOES_VEHICLE_TYRE_EXIST(Vehicle vehicle, int tyreIndex);` |
| [FIX_VEHICLE_WINDOW](../natives/VEHICLE/FixVehicleWindow.md) | See eWindowId declared in [`IS_VEHICLE_WINDOW_INTACT`](#_0x46E571A0E20D01F1). | `cs_type(Any) void FIX_VEHICLE_WINDOW(Vehicle vehicle, int windowIndex);` |
| [GET_BOAT_VEHICLE_MODEL_AGILITY](../natives/VEHICLE/GetBoatVehicleModelAgility.md) | Retrieves the agility for a specific boat model, including any vehicle mods. Unlike other vehicles where Rockstar Games typically assess performance based on traction, boats use agility as a measure. This static value is distinct from the traction metrics used for other vehicle types. | `float GET_BOAT_VEHICLE_MODEL_AGILITY(Hash modelHash);` |
| [GET_DISPLAY_NAME_FROM_VEHICLE_MODEL](../natives/VEHICLE/GetDisplayNameFromVehicleModel.md) | Returns the display name/text label (`gameName` in `vehicles.meta`) for the specified vehicle model. | `char* GET_DISPLAY_NAME_FROM_VEHICLE_MODEL(Hash modelHash);` |
| [_GET_IS_VEHICLE_ELECTRIC](../natives/VEHICLE/GetIsVehicleElectric.md) | Checks if the vehicle is electric. | `BOOL _GET_IS_VEHICLE_ELECTRIC(Hash vehicleModel);` |
| [_GET_IS_VEHICLE_EMP_DISABLED](../natives/VEHICLE/GetIsVehicleEmpDisabled.md) | Returns whether this vehicle is currently disabled by an EMP mine. | `BOOL _GET_IS_VEHICLE_EMP_DISABLED(Vehicle vehicle);` |
| [GET_IS_VEHICLE_ENGINE_RUNNING](../natives/VEHICLE/GetIsVehicleEngineRunning.md) | Returns true when in a vehicle, false whilst entering/exiting. | `BOOL GET_IS_VEHICLE_ENGINE_RUNNING(Vehicle vehicle);` |
| [GET_IS_VEHICLE_PRIMARY_COLOUR_CUSTOM](../natives/VEHICLE/GetIsVehiclePrimaryColourCustom.md) | Provides the get is vehicle primary colour custom native operation. | `BOOL GET_IS_VEHICLE_PRIMARY_COLOUR_CUSTOM(Vehicle vehicle);` |
| [GET_IS_VEHICLE_SECONDARY_COLOUR_CUSTOM](../natives/VEHICLE/GetIsVehicleSecondaryColourCustom.md) | Check if Vehicle Secondary is avaliable for customize | `BOOL GET_IS_VEHICLE_SECONDARY_COLOUR_CUSTOM(Vehicle vehicle);` |
| [_GET_IS_VEHICLE_SHUNT_BOOST_ACTIVE](../natives/VEHICLE/GetIsVehicleShuntBoostActive.md) | Provides the get is vehicle shunt boost active native operation. | `BOOL _GET_IS_VEHICLE_SHUNT_BOOST_ACTIVE(Vehicle vehicle);` |
| [GET_MAKE_NAME_FROM_VEHICLE_MODEL](../natives/VEHICLE/GetMakeNameFromVehicleModel.md) | Retrieves the manufacturer's name for a specified vehicle. | `char* GET_MAKE_NAME_FROM_VEHICLE_MODEL(Hash modelHash);` |
| [_GET_NUMBER_OF_VEHICLE_DOORS](../natives/VEHICLE/GetNumberOfVehicleDoors.md) | Provides the get number of vehicle doors native operation. | `int _GET_NUMBER_OF_VEHICLE_DOORS(Vehicle vehicle);` |
| [GET_NUM_VEHICLE_MODS](../natives/VEHICLE/GetNumVehicleMods.md) | Returns how many possible mods a vehicle has for a given mod type | `int GET_NUM_VEHICLE_MODS(Vehicle vehicle, int modType);` |
| [GET_NUM_VEHICLE_WINDOW_TINTS](../natives/VEHICLE/GetNumVehicleWindowTints.md) | Provides the get num vehicle window tints native operation. | `int GET_NUM_VEHICLE_WINDOW_TINTS();` |
| [GET_PED_USING_VEHICLE_DOOR](../natives/VEHICLE/GetPedUsingVehicleDoor.md) | See eDoorId declared in [`SET_VEHICLE_DOOR_SHUT`](#_0x93D9BD300D7789E5) | `Ped GET_PED_USING_VEHICLE_DOOR(Vehicle vehicle, int doorIndex);` |
| [GET_RANDOM_VEHICLE_MODEL_IN_MEMORY](../natives/VEHICLE/GetRandomVehicleModelInMemory.md) | Not present in the retail version! It's just a nullsub. | `void GET_RANDOM_VEHICLE_MODEL_IN_MEMORY(BOOL p0, Hash* modelHash, int* successIndicator);` |
| [GET_VEHICLE_ACCELERATION](../natives/VEHICLE/GetVehicleAcceleration.md) | Retrieves a static value representing the maximum drive force of specific a vehicle, including any vehicle mods. This value does not change dynamically during gameplay. This value provides an approximation and should be considered alongside other performance metrics like top speed for a more comprehensive understanding of the vehicle's capabilities. | `float GET_VEHICLE_ACCELERATION(Vehicle vehicle);` |
| [GET_VEHICLE_BODY_HEALTH](../natives/VEHICLE/GetVehicleBodyHealth.md) | Seems related to vehicle health, like the one in IV. | `float GET_VEHICLE_BODY_HEALTH(Vehicle vehicle);` |
| [_GET_VEHICLE_BOMB_COUNT](../natives/VEHICLE/GetVehicleBombCount.md) | Gets the amount of bombs that this vehicle has. As far as I know, this does _not_ impact vehicle weapons or the ammo of those weapons in any way, it is just a way to keep track of the amount of bombs in a specific plane. | `int _GET_VEHICLE_BOMB_COUNT(Vehicle aircraft);` |
| [GET_VEHICLE_CAUSE_OF_DESTRUCTION](../natives/VEHICLE/GetVehicleCauseOfDestruction.md) | A hash representing the destruction cause. These can be weapon hashes. | `Hash GET_VEHICLE_CAUSE_OF_DESTRUCTION(Vehicle vehicle);` |
| [GET_VEHICLE_CLASS](../natives/VEHICLE/GetVehicleClass.md) | Returns an int | `int GET_VEHICLE_CLASS(Vehicle vehicle);` |
| [GET_VEHICLE_CLASS_ESTIMATED_MAX_SPEED](../natives/VEHICLE/GetVehicleClassEstimatedMaxSpeed.md) | Provides the get vehicle class estimated max speed native operation. | `float GET_VEHICLE_CLASS_ESTIMATED_MAX_SPEED(int vehicleClass);` |
| [GET_VEHICLE_CLASS_FROM_NAME](../natives/VEHICLE/GetVehicleClassFromName.md) | For a full enum, see here : pastebin.com/i2GGAjY0 | `int GET_VEHICLE_CLASS_FROM_NAME(Hash modelHash);` |
| [GET_VEHICLE_CLASS_MAX_ACCELERATION](../natives/VEHICLE/GetVehicleClassMaxAcceleration.md) | Provides the get vehicle class max acceleration native operation. | `float GET_VEHICLE_CLASS_MAX_ACCELERATION(int vehicleClass);` |
| [GET_VEHICLE_CLASS_MAX_AGILITY](../natives/VEHICLE/GetVehicleClassMaxAgility.md) | Provides the get vehicle class max agility native operation. | `float GET_VEHICLE_CLASS_MAX_AGILITY(int vehicleClass);` |
| [GET_VEHICLE_CLASS_MAX_BRAKING](../natives/VEHICLE/GetVehicleClassMaxBraking.md) | Provides the get vehicle class max braking native operation. | `float GET_VEHICLE_CLASS_MAX_BRAKING(int vehicleClass);` |
| [GET_VEHICLE_CLASS_MAX_TRACTION](../natives/VEHICLE/GetVehicleClassMaxTraction.md) | Provides the get vehicle class max traction native operation. | `float GET_VEHICLE_CLASS_MAX_TRACTION(int vehicleClass);` |
| [GET_VEHICLE_COLOR](../natives/VEHICLE/GetVehicleColor.md) | See [`SET_VEHICLE_CUSTOM_PRIMARY_COLOUR`](#_0x7141766F91D15BEA) and [`SET_VEHICLE_CUSTOM_SECONDARY_COLOUR`](#_0x36CED73BFED89754). | `void GET_VEHICLE_COLOR(Vehicle vehicle, int* r, int* g, int* b);` |
| [GET_VEHICLE_COLOUR_COMBINATION](../natives/VEHICLE/GetVehicleColourCombination.md) | Provides the get vehicle colour combination native operation. | `int GET_VEHICLE_COLOUR_COMBINATION(Vehicle vehicle);` |
| [GET_VEHICLE_COLOURS](../natives/VEHICLE/GetVehicleColours.md) | Provides the get vehicle colours native operation. | `void GET_VEHICLE_COLOURS(Vehicle vehicle, int* colorPrimary, int* colorSecondary);` |
| [GET_VEHICLE_COLOURS_WHICH_CAN_BE_SET](../natives/VEHICLE/GetVehicleColoursWhichCanBeSet.md) | Provides the get vehicle colours which can be set native operation. | `int GET_VEHICLE_COLOURS_WHICH_CAN_BE_SET(Vehicle vehicle);` |
| [_GET_VEHICLE_COUNTERMEASURE_COUNT](../natives/VEHICLE/GetVehicleCountermeasureCount.md) | Similar to [`_GET_AIRCRAFT_BOMB_COUNT`](#_0xEA12BD130D7569A1), this gets the amount of countermeasures that are present on this vehicle. | `int _GET_VEHICLE_COUNTERMEASURE_COUNT(Vehicle aircraft);` |
| [_GET_VEHICLE_CURRENT_SLIPSTREAM_DRAFT](../natives/VEHICLE/GetVehicleCurrentSlipstreamDraft.md) | Returns a float value between 0.0 and 3.0 related to its slipstream draft (boost/speedup). | `float _GET_VEHICLE_CURRENT_SLIPSTREAM_DRAFT(Vehicle vehicle);` |
| [GET_VEHICLE_CUSTOM_PRIMARY_COLOUR](../natives/VEHICLE/GetVehicleCustomPrimaryColour.md) | Provides the get vehicle custom primary colour native operation. | `void GET_VEHICLE_CUSTOM_PRIMARY_COLOUR(Vehicle vehicle, int* r, int* g, int* b);` |
| [GET_VEHICLE_CUSTOM_SECONDARY_COLOUR](../natives/VEHICLE/GetVehicleCustomSecondaryColour.md) | Provides the get vehicle custom secondary colour native operation. | `void GET_VEHICLE_CUSTOM_SECONDARY_COLOUR(Vehicle vehicle, int* r, int* g, int* b);` |
| [_GET_VEHICLE_DASHBOARD_COLOR](../natives/VEHICLE/GetVehicleDashboardColor.md) | Provides the get vehicle dashboard color native operation. | `void _GET_VEHICLE_DASHBOARD_COLOR(Vehicle vehicle, int* color);` |
| [GET_VEHICLE_DEFORMATION_AT_POS](../natives/VEHICLE/GetVehicleDeformationAtPos.md) | The only example I can find of this function in the scripts, is this: | `Vector3 GET_VEHICLE_DEFORMATION_AT_POS(Vehicle vehicle, float offsetX, float offsetY, float offsetZ);` |
| [GET_VEHICLE_DIRT_LEVEL](../natives/VEHICLE/GetVehicleDirtLevel.md) | A getter for [`SET_VEHICLE_DIRT_LEVEL`](#_0x79D3B596FE44EE8B). | `float GET_VEHICLE_DIRT_LEVEL(Vehicle vehicle);` |
| [GET_VEHICLE_DOOR_ANGLE_RATIO](../natives/VEHICLE/GetVehicleDoorAngleRatio.md) | Checks the angle of the door mapped from 0.0 - 1.0 where 0.0 is fully closed and 1.0 is fully open. | `float GET_VEHICLE_DOOR_ANGLE_RATIO(Vehicle vehicle, int doorIndex);` |
| [GET_VEHICLE_DOOR_LOCK_STATUS](../natives/VEHICLE/GetVehicleDoorLockStatus.md) | Returns the current lock status, refer to [SET_VEHICLE_DOORS_LOCKED](#_0xB664292EAECF7FA6) | `int GET_VEHICLE_DOOR_LOCK_STATUS(Vehicle vehicle);` |
| [GET_VEHICLE_DOORS_LOCKED_FOR_PLAYER](../natives/VEHICLE/GetVehicleDoorsLockedForPlayer.md) | Provides the get vehicle doors locked for player native operation. | `BOOL GET_VEHICLE_DOORS_LOCKED_FOR_PLAYER(Vehicle vehicle, Player player);` |
| [GET_VEHICLE_ENGINE_HEALTH](../natives/VEHICLE/GetVehicleEngineHealth.md) | Returns 1000.0 if the function is unable to get the address of the specified vehicle or if it's not a vehicle. | `float GET_VEHICLE_ENGINE_HEALTH(Vehicle vehicle);` |
| [GET_VEHICLE_ENVEFF_SCALE](../natives/VEHICLE/GetVehicleEnveffScale.md) | formerly known as _GET_VEHICLE_PAINT_FADE | `float GET_VEHICLE_ENVEFF_SCALE(Vehicle vehicle);` |
| [GET_VEHICLE_ESTIMATED_MAX_SPEED](../natives/VEHICLE/GetVehicleEstimatedMaxSpeed.md) | Retrieves a static value representing the estimated max speed of a specific vehicle, including any vehicle mods. This value does not change dynamically during gameplay. | `float GET_VEHICLE_ESTIMATED_MAX_SPEED(Vehicle vehicle);` |
| [GET_VEHICLE_EXTRA_COLOURS](../natives/VEHICLE/GetVehicleExtraColours.md) | Provides the get vehicle extra colours native operation. | `void GET_VEHICLE_EXTRA_COLOURS(Vehicle vehicle, int* pearlescentColor, int* wheelColor);` |
| [GET_VEHICLE_FLIGHT_NOZZLE_POSITION](../natives/VEHICLE/GetVehicleFlightNozzlePosition.md) | A float indicating the percentage of the hover mode. 1.0 = in VTOL mode, 0.0 = in normal flying mode. | `float GET_VEHICLE_FLIGHT_NOZZLE_POSITION(Vehicle aircraft);` |
| [GET_VEHICLE_HAS_KERS](../natives/VEHICLE/GetVehicleHasKers.md) | Returns true if the vehicle has a kers boost (for instance the lectro or the vindicator) | `BOOL GET_VEHICLE_HAS_KERS(Vehicle vehicle);` |
| [GET_VEHICLE_HEALTH_PERCENTAGE](../natives/VEHICLE/GetVehicleHealthPercentage.md) | Provides the get vehicle health percentage native operation. | `float GET_VEHICLE_HEALTH_PERCENTAGE(Vehicle vehicle);` |
| [GET_VEHICLE_HOMING_LOCKON_STATE](../natives/VEHICLE/GetVehicleHomingLockonState.md) | Returns a value depending on the lock-on state of vehicle weapons. | `int GET_VEHICLE_HOMING_LOCKON_STATE(Vehicle vehicle);` |
| [GET_VEHICLE_INDIVIDUAL_DOOR_LOCK_STATUS](../natives/VEHICLE/GetVehicleIndividualDoorLockStatus.md) | See eDoorId declared in [`SET_VEHICLE_DOOR_SHUT`](#_0x93D9BD300D7789E5) | `int GET_VEHICLE_INDIVIDUAL_DOOR_LOCK_STATUS(Vehicle vehicle, int doorIndex);` |
| [_GET_VEHICLE_INTERIOR_COLOR](../natives/VEHICLE/GetVehicleInteriorColor.md) | Provides the get vehicle interior color native operation. | `void _GET_VEHICLE_INTERIOR_COLOR(Vehicle vehicle, int* color);` |

<!-- 55 rows -->

## Object and Pickups

| Native | Description | C signature |
|---|---|---|
| [ATTACH_PORTABLE_PICKUP_TO_PED](../natives/OBJECT/AttachPortablePickupToPed.md) | Provides the attach portable pickup to ped native operation. | `void ATTACH_PORTABLE_PICKUP_TO_PED(Object pickupObject, Ped ped);` |
| [CREATE_NON_NETWORKED_PORTABLE_PICKUP](../natives/OBJECT/CreateNonNetworkedPortablePickup.md) | Provides the create non networked portable pickup native operation. | `Object CREATE_NON_NETWORKED_PORTABLE_PICKUP(Hash pickupHash, float x, float y, float z, BOOL placeOnGround, Hash modelHash);` |
| [CREATE_OBJECT](../natives/OBJECT/CreateObject.md) | Creates an object (prop) with the specified model at the specified position, offset on the Z axis by the radius of the object's model. | `Object CREATE_OBJECT(cs_type(int) Hash modelHash, float x, float y, float z, BOOL isNetwork, BOOL netMissionEntity, BOOL doorFlag);` |
| [CREATE_OBJECT_NO_OFFSET](../natives/OBJECT/CreateObjectNoOffset.md) | Creates an object (prop) with the specified model centered at the specified position. | `Object CREATE_OBJECT_NO_OFFSET(Hash modelHash, float x, float y, float z, BOOL isNetwork, BOOL netMissionEntity, BOOL doorFlag);` |
| [CREATE_PICKUP](../natives/OBJECT/CreatePickup.md) | Pickup hashes can be found [here](https://gist.github.com/4mmonium/1eabfb6b3996e3aa6b9525a3eccf8a0b). | `Pickup CREATE_PICKUP(Hash pickupHash, float posX, float posY, float posZ, int p4, int value, BOOL p6, Hash modelHash);` |
| [CREATE_PICKUP_ROTATE](../natives/OBJECT/CreatePickupRotate.md) | Pickup hashes: pastebin.com/8EuSv2r1 | `Pickup CREATE_PICKUP_ROTATE(Hash pickupHash, float posX, float posY, float posZ, float rotX, float rotY, float rotZ, int flag, int amount, Any p9, BOOL p10, Hash modelHash);` |
| [CREATE_PORTABLE_PICKUP](../natives/OBJECT/CreatePortablePickup.md) | Pickup hashes can be found [here](https://gist.github.com/4mmonium/1eabfb6b3996e3aa6b9525a3eccf8a0b). | `Object CREATE_PORTABLE_PICKUP(Hash pickupHash, float x, float y, float z, BOOL placeOnGround, Hash modelHash);` |
| [DELETE_OBJECT](../natives/OBJECT/DeleteObject.md) | Deletes the specified object. | `void DELETE_OBJECT(Object* object);` |
| [DETACH_PORTABLE_PICKUP_FROM_PED](../natives/OBJECT/DetachPortablePickupFromPed.md) | Provides the detach portable pickup from ped native operation. | `void DETACH_PORTABLE_PICKUP_FROM_PED(Object pickupObject);` |
| [GET_OBJECT_FRAGMENT_DAMAGE_HEALTH](../natives/OBJECT/GetObjectFragmentDamageHealth.md) | Provides the get object fragment damage health native operation. | `float GET_OBJECT_FRAGMENT_DAMAGE_HEALTH(Any p0, BOOL p1);` |
| [_GET_OBJECT_TEXTURE_VARIATION](../natives/OBJECT/GetObjectTextureVariation.md) | Provides the get object texture variation native operation. | `int _GET_OBJECT_TEXTURE_VARIATION(Object object);` |
| [GET_PICKUP_COORDS](../natives/OBJECT/GetPickupCoords.md) | Provides the get pickup coords native operation. | `Vector3 GET_PICKUP_COORDS(Pickup pickup);` |
| [_GET_PICKUP_GENERATION_RANGE_MULTIPLIER](../natives/OBJECT/GetPickupGenerationRangeMultiplier.md) | Provides the get pickup generation range multiplier native operation. | `float _GET_PICKUP_GENERATION_RANGE_MULTIPLIER();` |
| [_GET_PICKUP_HASH](../natives/OBJECT/GetPickupHash.md) | returns pickup hash. | `Hash _GET_PICKUP_HASH(cs_type(Pickup) Hash pickupHash);` |
| [_GET_PICKUP_HASH_FROM_WEAPON](../natives/OBJECT/GetPickupHashFromWeapon.md) | Returns the pickup hash for the given weapon hash | `Hash _GET_PICKUP_HASH_FROM_WEAPON(Hash weapon);` |
| [GET_PICKUP_OBJECT](../natives/OBJECT/GetPickupObject.md) | Provides the get pickup object native operation. | `Object GET_PICKUP_OBJECT(Pickup pickup);` |
| [HIDE_PORTABLE_PICKUP_WHEN_DETACHED](../natives/OBJECT/HidePortablePickupWhenDetached.md) | Provides the hide portable pickup when detached native operation. | `void HIDE_PORTABLE_PICKUP_WHEN_DETACHED(Pickup pickup, BOOL toggle);` |
| [IS_OBJECT_A_PICKUP](../natives/OBJECT/IsObjectAPickup.md) | Provides the is object a pickup native operation. | `BOOL IS_OBJECT_A_PICKUP(Object object);` |
| [IS_OBJECT_A_PORTABLE_PICKUP](../natives/OBJECT/IsObjectAPortablePickup.md) | Provides the is object a portable pickup native operation. | `BOOL IS_OBJECT_A_PORTABLE_PICKUP(Object object);` |
| [IS_OBJECT_ENTIRELY_INSIDE_GARAGE](../natives/OBJECT/IsObjectEntirelyInsideGarage.md) | Provides the is object entirely inside garage native operation. | `BOOL IS_OBJECT_ENTIRELY_INSIDE_GARAGE(cs_type(Any) Hash garageHash, Entity entity, float p2, int p3);` |
| [IS_OBJECT_NEAR_POINT](../natives/OBJECT/IsObjectNearPoint.md) | Provides the is object near point native operation. | `BOOL IS_OBJECT_NEAR_POINT(Hash objectHash, float x, float y, float z, float range);` |
| [IS_OBJECT_PARTIALLY_INSIDE_GARAGE](../natives/OBJECT/IsObjectPartiallyInsideGarage.md) | Provides the is object partially inside garage native operation. | `BOOL IS_OBJECT_PARTIALLY_INSIDE_GARAGE(cs_type(Any) Hash garageHash, Entity entity, int p2);` |
| [IS_OBJECT_VISIBLE](../natives/OBJECT/IsObjectVisible.md) | Provides the is object visible native operation. | `BOOL IS_OBJECT_VISIBLE(Object object);` |
| [PLACE_OBJECT_ON_GROUND_OR_OBJECT_PROPERLY](../natives/OBJECT/PlaceObjectOnGroundOrObjectProperly.md) | Casts a ray downward from the object's position and places the object on the surface it hits (including world surface and objects). Use [`PLACE_OBJECT_ON_GROUND_PROPERLY`](#_0x58A850EAEE20FAA3) to not include objects when determining the surface. | `BOOL PLACE_OBJECT_ON_GROUND_OR_OBJECT_PROPERLY(Object object);` |
| [PLACE_OBJECT_ON_GROUND_PROPERLY](../natives/OBJECT/PlaceObjectOnGroundProperly.md) | Provides the place object on ground properly native operation. | `BOOL PLACE_OBJECT_ON_GROUND_PROPERLY(Object object);` |

<!-- 25 rows -->

## Tasks and AI

| Native | Description | C signature |
|---|---|---|
| [CLEAR_PED_TASKS](../natives/TASK/ClearPedTasks.md) | Clear a ped's tasks. Stop animations and other tasks created by scripts. | `void CLEAR_PED_TASKS(Ped ped);` |
| [CLEAR_PED_TASKS_IMMEDIATELY](../natives/TASK/ClearPedTasksImmediately.md) | Immediately stops the pedestrian from whatever it's doing. The difference between this and [CLEAR_PED_TASKS](#_0xE1EF3C1216AFF2CD) is that this one teleports the ped but does not change the position of the ped. | `void CLEAR_PED_TASKS_IMMEDIATELY(Ped ped);` |
| [CLOSE_SEQUENCE_TASK](../natives/TASK/CloseSequenceTask.md) | For an example on how to use this please refer to [OPEN_SEQUENCE_TASK](#_0xE8854A4326B9E12B) | `cs_type(Any) void CLOSE_SEQUENCE_TASK(int taskSequenceId);` |
| [DOES_SCENARIO_EXIST_IN_AREA](../natives/TASK/DoesScenarioExistInArea.md) | Provides the does scenario exist in area native operation. | `BOOL DOES_SCENARIO_EXIST_IN_AREA(float x, float y, float z, float radius, BOOL b);` |
| [DOES_SCENARIO_GROUP_EXIST](../natives/TASK/DoesScenarioGroupExist.md) | Occurrences in the b617d scripts: | `BOOL DOES_SCENARIO_GROUP_EXIST(char* scenarioGroup);` |
| [DOES_SCENARIO_OF_TYPE_EXIST_IN_AREA](../natives/TASK/DoesScenarioOfTypeExistInArea.md) | Provides the does scenario of type exist in area native operation. | `BOOL DOES_SCENARIO_OF_TYPE_EXIST_IN_AREA(float p0, float p1, float p2, char* p3, float p4, BOOL p5);` |
| [IS_PED_ACTIVE_IN_SCENARIO](../natives/TASK/IsPedActiveInScenario.md) | This is a stricter version of [`IS_PED_USING_ANY_SCENARIO`](#_0x57AB4A3080F85143). It only returns true if the ped is playing the ambient animations associated with the scenario. | `BOOL IS_PED_ACTIVE_IN_SCENARIO(Ped ped);` |
| [IS_PED_PLAYING_BASE_CLIP_IN_SCENARIO](../natives/TASK/IsPedPlayingBaseClipInScenario.md) | Provides the is ped playing base clip in scenario native operation. | `BOOL IS_PED_PLAYING_BASE_CLIP_IN_SCENARIO(Ped ped);` |
| [IS_SCENARIO_GROUP_ENABLED](../natives/TASK/IsScenarioGroupEnabled.md) | Occurrences in the b617d scripts: | `BOOL IS_SCENARIO_GROUP_ENABLED(char* scenarioGroup);` |
| [IS_SCENARIO_OCCUPIED](../natives/TASK/IsScenarioOccupied.md) | Provides the is scenario occupied native operation. | `BOOL IS_SCENARIO_OCCUPIED(float p0, float p1, float p2, float p3, BOOL p4);` |
| [IS_SCENARIO_TYPE_ENABLED](../natives/TASK/IsScenarioTypeEnabled.md) | Occurrences in the b617d scripts: | `BOOL IS_SCENARIO_TYPE_ENABLED(char* scenarioType);` |
| [OPEN_SEQUENCE_TASK](../natives/TASK/OpenSequenceTask.md) | If this returns 0 that means it failed to get a sequence id. | `cs_type(Any) void OPEN_SEQUENCE_TASK(int* taskSequenceId);` |
| [PED_HAS_USE_SCENARIO_TASK](../natives/TASK/PedHasUseScenarioTask.md) | Provides the ped has use scenario task native operation. | `BOOL PED_HAS_USE_SCENARIO_TASK(Ped ped);` |
| [PLAY_ANIM_ON_RUNNING_SCENARIO](../natives/TASK/PlayAnimOnRunningScenario.md) | Provides the play anim on running scenario native operation. | `void PLAY_ANIM_ON_RUNNING_SCENARIO(Ped ped, char* animDict, char* animName);` |
| [RESET_EXCLUSIVE_SCENARIO_GROUP](../natives/TASK/ResetExclusiveScenarioGroup.md) | Provides the reset exclusive scenario group native operation. | `void RESET_EXCLUSIVE_SCENARIO_GROUP();` |
| [RESET_SCENARIO_GROUPS_ENABLED](../natives/TASK/ResetScenarioGroupsEnabled.md) | Provides the reset scenario groups enabled native operation. | `void RESET_SCENARIO_GROUPS_ENABLED();` |
| [RESET_SCENARIO_TYPES_ENABLED](../natives/TASK/ResetScenarioTypesEnabled.md) | Provides the reset scenario types enabled native operation. | `void RESET_SCENARIO_TYPES_ENABLED();` |
| [SET_DRIVE_TASK_CRUISE_SPEED](../natives/TASK/SetDriveTaskCruiseSpeed.md) | Provides the set drive task cruise speed native operation. | `void SET_DRIVE_TASK_CRUISE_SPEED(Ped driver, float cruiseSpeed);` |
| [SET_DRIVE_TASK_DRIVING_STYLE](../natives/TASK/SetDriveTaskDrivingStyle.md) | Sets the driving style for a ped currently performing a driving task. | `void SET_DRIVE_TASK_DRIVING_STYLE(Ped ped, int drivingStyle);` |
| [SET_DRIVE_TASK_MAX_CRUISE_SPEED](../natives/TASK/SetDriveTaskMaxCruiseSpeed.md) | Provides the set drive task max cruise speed native operation. | `void SET_DRIVE_TASK_MAX_CRUISE_SPEED(Any p0, float p1);` |
| [SET_EXCLUSIVE_SCENARIO_GROUP](../natives/TASK/SetExclusiveScenarioGroup.md) | Groups found in the scripts used with this native: | `void SET_EXCLUSIVE_SCENARIO_GROUP(char* scenarioGroup);` |
| [SET_SCENARIO_GROUP_ENABLED](../natives/TASK/SetScenarioGroupEnabled.md) | Occurrences in the b617d scripts: pastebin.com/Tvg2PRHU | `void SET_SCENARIO_GROUP_ENABLED(char* scenarioGroup, BOOL p1);` |
| [SET_SCENARIO_TYPE_ENABLED](../natives/TASK/SetScenarioTypeEnabled.md) | seems to enable/disable specific scenario-types from happening in the game world. | `void SET_SCENARIO_TYPE_ENABLED(char* scenarioType, BOOL toggle);` |
| [TASK_AIM_GUN_AT_COORD](../natives/TASK/TaskAimGunAtCoord.md) | Provides the task aim gun at coord native operation. | `void TASK_AIM_GUN_AT_COORD(Ped ped, float x, float y, float z, int time, BOOL bInstantBlendToAim, BOOL bPlayAimIntro);` |
| [TASK_AIM_GUN_AT_ENTITY](../natives/TASK/TaskAimGunAtEntity.md) | duration: the amount of time in milliseconds to do the task. -1 will keep the task going until either another task is applied, or CLEAR_ALL_TASKS() is called with the ped | `void TASK_AIM_GUN_AT_ENTITY(Ped ped, Entity entity, int duration, BOOL bInstantBlendToAim);` |
| [TASK_AIM_GUN_SCRIPTED](../natives/TASK/TaskAimGunScripted.md) | Provides the task aim gun scripted native operation. | `void TASK_AIM_GUN_SCRIPTED(Ped ped, Hash scriptTask, BOOL bDisableBlockingClip, BOOL bInstantBlendToAim);` |
| [TASK_AIM_GUN_SCRIPTED_WITH_TARGET](../natives/TASK/TaskAimGunScriptedWithTarget.md) | Provides the task aim gun scripted with target native operation. | `void TASK_AIM_GUN_SCRIPTED_WITH_TARGET(Ped ped, Ped targetPed, float x, float y, float z, cs_type(Any) Hash iGunTaskType, BOOL bDisableBlockingClip, BOOL bForceAim);` |
| [TASK_COMBAT_HATED_TARGETS_AROUND_PED](../natives/TASK/TaskCombatHatedTargetsAroundPed.md) | Despite its name, it only attacks ONE hated target. The one closest hated target. | `void TASK_COMBAT_HATED_TARGETS_AROUND_PED(Ped ped, float radius, int p2);` |
| [TASK_COMBAT_HATED_TARGETS_AROUND_PED_TIMED](../natives/TASK/TaskCombatHatedTargetsAroundPedTimed.md) | Provides the task combat hated targets around ped timed native operation. | `void TASK_COMBAT_HATED_TARGETS_AROUND_PED_TIMED(Any p0, float p1, Any p2, Any p3);` |
| [TASK_COMBAT_HATED_TARGETS_IN_AREA](../natives/TASK/TaskCombatHatedTargetsInArea.md) | Despite its name, it only attacks ONE hated target. The one closest to the specified position. | `void TASK_COMBAT_HATED_TARGETS_IN_AREA(Ped ped, float x, float y, float z, float radius, Any p5);` |
| [TASK_COMBAT_PED](../natives/TASK/TaskCombatPed.md) | Makes the specified ped attack the target ped. | `void TASK_COMBAT_PED(Ped ped, Ped targetPed, int p2, int p3);` |
| [TASK_COMBAT_PED_TIMED](../natives/TASK/TaskCombatPedTimed.md) | Provides the task combat ped timed native operation. | `void TASK_COMBAT_PED_TIMED(Any p0, Ped ped, int p2, Any p3);` |
| [TASK_FOLLOW_NAV_MESH_TO_COORD](../natives/TASK/TaskFollowNavMeshToCoord.md) | Sometimes a path may not be able to be found. This could happen because there simply isn't any way to get there, or maybe a bunch of dynamic objects have blocked the way, | `void TASK_FOLLOW_NAV_MESH_TO_COORD(Ped ped, float x, float y, float z, float moveBlendRatio, int time, float radius, cs_type(BOOL) int flags, float finalHeading);` |
| [TASK_FOLLOW_NAV_MESH_TO_COORD_ADVANCED](../natives/TASK/TaskFollowNavMeshToCoordAdvanced.md) | Provides the task follow nav mesh to coord advanced native operation. | `void TASK_FOLLOW_NAV_MESH_TO_COORD_ADVANCED(Ped ped, float x, float y, float z, float speed, int timeout, float unkFloat, int unkInt, float unkX, float unkY, float unkZ, float unk_40000f);` |
| [TASK_FOLLOW_POINT_ROUTE](../natives/TASK/TaskFollowPointRoute.md) | Makes the ped go on a point route. | `void TASK_FOLLOW_POINT_ROUTE(Ped ped, float speed, int routeMode);` |
| [TASK_FOLLOW_TO_OFFSET_OF_ENTITY](../natives/TASK/TaskFollowToOffsetOfEntity.md) | p6 always -1 | `void TASK_FOLLOW_TO_OFFSET_OF_ENTITY(Ped ped, Entity entity, float offsetX, float offsetY, float offsetZ, float movementSpeed, int timeout, float stoppingRange, BOOL persistFollowing);` |
| [TASK_GO_STRAIGHT_TO_COORD](../natives/TASK/TaskGoStraightToCoord.md) | Provides the task go straight to coord native operation. | `void TASK_GO_STRAIGHT_TO_COORD(Ped ped, float x, float y, float z, float speed, int timeout, float targetHeading, float distanceToSlide);` |
| [TASK_GO_STRAIGHT_TO_COORD_RELATIVE_TO_ENTITY](../natives/TASK/TaskGoStraightToCoordRelativeToEntity.md) | Provides the task go straight to coord relative to entity native operation. | `void TASK_GO_STRAIGHT_TO_COORD_RELATIVE_TO_ENTITY(Entity entity1, Entity entity2, float p2, float p3, float p4, float p5, Any p6);` |
| [TASK_PLAY_ANIM](../natives/TASK/TaskPlayAnim.md) | Provides the task play anim native operation. | `void TASK_PLAY_ANIM(Ped ped, char* animDictionary, char* animationName, float blendInSpeed, float blendOutSpeed, int duration, int flag, float playbackRate, BOOL lockX, BOOL lockY, BOOL lockZ);` |
| [TASK_PLAY_ANIM_ADVANCED](../natives/TASK/TaskPlayAnimAdvanced.md) | Similar in functionality to [`TASK_PLAY_ANIM`](#_0xEA47FE3719165B94), except the position and rotation parameters let you specify the initial position and rotation of the task. The ped is teleported to the position specified. | `void TASK_PLAY_ANIM_ADVANCED(Ped ped, char* animDictionary, char* animationName, float posX, float posY, float posZ, float rotX, float rotY, float rotZ, float blendInSpeed, float blendOutSpeed, int duration, Any flag, float animTime, Any p14, Any p15);` |
| [TASK_REACT_AND_FLEE_PED](../natives/TASK/TaskReactAndFleePed.md) | Provides the task react and flee ped native operation. | `void TASK_REACT_AND_FLEE_PED(Ped ped, Ped fleeTarget);` |
| [TASK_SHOOT_AT_COORD](../natives/TASK/TaskShootAtCoord.md) | Firing Pattern Hash Information: https://pastebin.com/Px036isB | `void TASK_SHOOT_AT_COORD(Ped ped, float x, float y, float z, int duration, Hash firingPattern);` |
| [TASK_SHOOT_AT_ENTITY](../natives/TASK/TaskShootAtEntity.md) | Entity aimedentity; | `void TASK_SHOOT_AT_ENTITY(Entity entity, Entity target, int duration, Hash firingPattern);` |
| [TASK_SMART_FLEE_COORD](../natives/TASK/TaskSmartFleeCoord.md) | Makes the specified ped flee the specified distance from the specified position. | `void TASK_SMART_FLEE_COORD(Ped ped, float x, float y, float z, float distance, int time, BOOL p6, BOOL p7);` |
| [TASK_SMART_FLEE_PED](../natives/TASK/TaskSmartFleePed.md) | Makes a ped run away from another ped (fleeTarget). | `void TASK_SMART_FLEE_PED(Ped ped, Ped fleeTarget, float distance, Any fleeTime, BOOL p4, BOOL p5);` |

<!-- 45 rows -->

## Weapons

| Native | Description | C signature |
|---|---|---|
| [ADD_AMMO_TO_PED](../natives/WEAPON/AddAmmoToPed.md) | Provides the add ammo to ped native operation. | `void ADD_AMMO_TO_PED(Ped ped, Hash weaponHash, int ammo);` |
| [_ADD_AMMO_TO_PED_BY_TYPE](../natives/WEAPON/AddAmmoToPedByType.md) | Provides the add ammo to ped by type native operation. | `void _ADD_AMMO_TO_PED_BY_TYPE(Ped ped, cs_type(Any) Hash ammoType, int ammo);` |
| [CLEAR_ENTITY_LAST_WEAPON_DAMAGE](../natives/WEAPON/ClearEntityLastWeaponDamage.md) | Provides the clear entity last weapon damage native operation. | `void CLEAR_ENTITY_LAST_WEAPON_DAMAGE(Entity entity);` |
| [CLEAR_PED_LAST_WEAPON_DAMAGE](../natives/WEAPON/ClearPedLastWeaponDamage.md) | Does NOT seem to work with HAS_PED_BEEN_DAMAGED_BY_WEAPON. Use CLEAR_ENTITY_LAST_WEAPON_DAMAGE and HAS_ENTITY_BEEN_DAMAGED_BY_WEAPON instead. | `void CLEAR_PED_LAST_WEAPON_DAMAGE(Ped ped);` |
| [GET_AMMO_IN_CLIP](../natives/WEAPON/GetAmmoInClip.md) | Provides the get ammo in clip native operation. | `BOOL GET_AMMO_IN_CLIP(Ped ped, Hash weaponHash, int* ammo);` |
| [GET_AMMO_IN_PED_WEAPON](../natives/WEAPON/GetAmmoInPedWeapon.md) | WEAPON::GET_AMMO_IN_PED_WEAPON(PLAYER::PLAYER_PED_ID(), a_0) | `int GET_AMMO_IN_PED_WEAPON(Ped ped, Hash weaponhash);` |
| [_GET_AMMO_IN_VEHICLE_WEAPON_CLIP](../natives/WEAPON/GetAmmoInVehicleWeaponClip.md) | Provides the get ammo in vehicle weapon clip native operation. | `BOOL _GET_AMMO_IN_VEHICLE_WEAPON_CLIP(Vehicle vehicle, int seat, int ammo);` |
| [GET_PED_AMMO_BY_TYPE](../natives/WEAPON/GetPedAmmoByType.md) | Provides the get ped ammo by type native operation. | `int GET_PED_AMMO_BY_TYPE(Ped ped, cs_type(Any) Hash ammoType);` |
| [GET_PED_AMMO_TYPE_FROM_WEAPON](../natives/WEAPON/GetPedAmmoTypeFromWeapon.md) | Returns the current ammo type of the specified ped's specified weapon. | `Hash GET_PED_AMMO_TYPE_FROM_WEAPON(Ped ped, Hash weaponHash);` |
| [_GET_PED_AMMO_TYPE_FROM_WEAPON_2](../natives/WEAPON/GetPedAmmoTypeFromWeapon_2.md) | Returns the base/default ammo type of the specified ped's specified weapon. | `Hash _GET_PED_AMMO_TYPE_FROM_WEAPON_2(Ped ped, Hash weaponHash);` |
| [GET_SELECTED_PED_WEAPON](../natives/WEAPON/GetSelectedPedWeapon.md) | Hash: The weapon hash of the currently selected weapon. | `Hash GET_SELECTED_PED_WEAPON(Ped ped);` |
| [_GET_TIME_BEFORE_VEHICLE_WEAPON_RELOAD_FINISHES](../natives/WEAPON/GetTimeBeforeVehicleWeaponReloadFinishes.md) | Provides the get time before vehicle weapon reload finishes native operation. | `int _GET_TIME_BEFORE_VEHICLE_WEAPON_RELOAD_FINISHES(Vehicle vehicle, int seat);` |
| [_GET_VEHICLE_WEAPON_RELOAD_TIME](../natives/WEAPON/GetVehicleWeaponReloadTime.md) | Provides the get vehicle weapon reload time native operation. | `float _GET_VEHICLE_WEAPON_RELOAD_TIME(Vehicle vehicle, int seat);` |
| [GET_WEAPON_CLIP_SIZE](../natives/WEAPON/GetWeaponClipSize.md) | Use it like this: | `int GET_WEAPON_CLIP_SIZE(Hash weaponHash);` |
| [GET_WEAPON_COMPONENT_HUD_STATS](../natives/WEAPON/GetWeaponComponentHudStats.md) | Provides the get weapon component hud stats native operation. | `BOOL GET_WEAPON_COMPONENT_HUD_STATS(Hash componentHash, int* outData);` |
| [GET_WEAPON_COMPONENT_TYPE_MODEL](../natives/WEAPON/GetWeaponComponentTypeModel.md) | Provides the get weapon component type model native operation. | `Hash GET_WEAPON_COMPONENT_TYPE_MODEL(Hash componentHash);` |
| [_GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_COUNT](../natives/WEAPON/GetWeaponComponentVariantExtraComponentCount.md) | Provides the get weapon component variant extra component count native operation. | `int _GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_COUNT(cs_type(Any) Hash componentHash);` |
| [_GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_MODEL](../natives/WEAPON/GetWeaponComponentVariantExtraComponentModel.md) | Provides the get weapon component variant extra component model native operation. | `cs_type(Any) Hash _GET_WEAPON_COMPONENT_VARIANT_EXTRA_COMPONENT_MODEL(cs_type(Any) Hash componentHash, int extraComponentIndex);` |
| [GET_WEAPON_DAMAGE](../natives/WEAPON/GetWeaponDamage.md) | This native does not return damages of weapons from the melee and explosive group. | `float GET_WEAPON_DAMAGE(Hash weaponHash, cs_type(Any) Hash componentHash);` |
| [GET_WEAPON_DAMAGE_TYPE](../natives/WEAPON/GetWeaponDamageType.md) | Provides the get weapon damage type native operation. | `int GET_WEAPON_DAMAGE_TYPE(Hash weaponHash);` |
| [GET_WEAPON_HUD_STATS](../natives/WEAPON/GetWeaponHudStats.md) | struct WeaponHudStatsData | `BOOL GET_WEAPON_HUD_STATS(Hash weaponHash, Any* outData);` |
| [GET_WEAPON_OBJECT_FROM_PED](../natives/WEAPON/GetWeaponObjectFromPed.md) | Drops the current weapon and returns the object | `Object GET_WEAPON_OBJECT_FROM_PED(Ped ped, BOOL p1);` |
| [_GET_WEAPON_OBJECT_LIVERY_COLOR](../natives/WEAPON/GetWeaponObjectLiveryColor.md) | Provides the get weapon object livery color native operation. | `int _GET_WEAPON_OBJECT_LIVERY_COLOR(Object weaponObject, cs_type(Any) Hash camoComponentHash);` |
| [GET_WEAPON_OBJECT_TINT_INDEX](../natives/WEAPON/GetWeaponObjectTintIndex.md) | Provides the get weapon object tint index native operation. | `int GET_WEAPON_OBJECT_TINT_INDEX(Object weapon);` |
| [_GET_WEAPON_TIME_BETWEEN_SHOTS](../natives/WEAPON/GetWeaponTimeBetweenShots.md) | Provides the get weapon time between shots native operation. | `cs_type(Any) float _GET_WEAPON_TIME_BETWEEN_SHOTS(Hash weaponHash);` |
| [GET_WEAPON_TINT_COUNT](../natives/WEAPON/GetWeaponTintCount.md) | Provides the get weapon tint count native operation. | `int GET_WEAPON_TINT_COUNT(Hash weaponHash);` |
| [GET_WEAPONTYPE_GROUP](../natives/WEAPON/GetWeapontypeGroup.md) | Gets and returns the hash of the group of the specified weapon (group names can be found/changed under "Group" in the weapons' meta file). | `Hash GET_WEAPONTYPE_GROUP(Hash weaponHash);` |
| [GET_WEAPONTYPE_MODEL](../natives/WEAPON/GetWeapontypeModel.md) | Returns the model of any weapon. | `Hash GET_WEAPONTYPE_MODEL(Hash weaponHash);` |
| [GET_WEAPONTYPE_SLOT](../natives/WEAPON/GetWeapontypeSlot.md) | Provides the get weapontype slot native operation. | `Hash GET_WEAPONTYPE_SLOT(Hash weaponHash);` |
| [GIVE_WEAPON_COMPONENT_TO_PED](../natives/WEAPON/GiveWeaponComponentToPed.md) | Provides the give weapon component to ped native operation. | `void GIVE_WEAPON_COMPONENT_TO_PED(Ped ped, Hash weaponHash, Hash componentHash);` |
| [GIVE_WEAPON_COMPONENT_TO_WEAPON_OBJECT](../natives/WEAPON/GiveWeaponComponentToWeaponObject.md) | addonHash: | `void GIVE_WEAPON_COMPONENT_TO_WEAPON_OBJECT(Object weaponObject, Hash addonHash);` |
| [GIVE_WEAPON_TO_PED](../natives/WEAPON/GiveWeaponToPed.md) | Provides the give weapon to ped native operation. | `void GIVE_WEAPON_TO_PED(Ped ped, Hash weaponHash, int ammoCount, BOOL isHidden, BOOL bForceInHand);` |
| [HAS_PED_GOT_WEAPON](../natives/WEAPON/HasPedGotWeapon.md) | p2 should be FALSE, otherwise it seems to always return FALSE | `BOOL HAS_PED_GOT_WEAPON(Ped ped, Hash weaponHash, BOOL p2);` |
| [HAS_PED_GOT_WEAPON_COMPONENT](../natives/WEAPON/HasPedGotWeaponComponent.md) | Provides the has ped got weapon component native operation. | `BOOL HAS_PED_GOT_WEAPON_COMPONENT(Ped ped, Hash weaponHash, Hash componentHash);` |
| [HAS_WEAPON_ASSET_LOADED](../natives/WEAPON/HasWeaponAssetLoaded.md) | Provides the has weapon asset loaded native operation. | `BOOL HAS_WEAPON_ASSET_LOADED(Hash weaponHash);` |

<!-- 35 rows -->

## Streaming and World

| Native | Description | C signature |
|---|---|---|
| [ACTIVATE_INTERIOR_ENTITY_SET](../natives/INTERIOR/ActivateInteriorEntitySet.md) | More info: http://gtaforums.com/topic/836367-adding-props-to-interiors/ | `void ACTIVATE_INTERIOR_ENTITY_SET(int interior, char* entitySetName);` |
| [ADD_PICKUP_TO_INTERIOR_ROOM_BY_NAME](../natives/INTERIOR/AddPickupToInteriorRoomByName.md) | Provides the add pickup to interior room by name native operation. | `void ADD_PICKUP_TO_INTERIOR_ROOM_BY_NAME(Pickup pickup, char* roomName);` |
| [CAP_INTERIOR](../natives/INTERIOR/CapInterior.md) | Does something similar to INTERIOR::DISABLE_INTERIOR | `void CAP_INTERIOR(int interiorID, BOOL toggle);` |
| [CLEAR_FOCUS](../natives/STREAMING/ClearFocus.md) | Provides the clear focus native operation. | `void CLEAR_FOCUS();` |
| [_CLEAR_INTERIOR_FOR_ENTITY](../natives/INTERIOR/ClearInteriorForEntity.md) | Immediately removes entity from an interior. Like sets entity to `limbo` room. | `void _CLEAR_INTERIOR_FOR_ENTITY(Entity entity);` |
| [DEACTIVATE_INTERIOR_ENTITY_SET](../natives/INTERIOR/DeactivateInteriorEntitySet.md) | Provides the deactivate interior entity set native operation. | `void DEACTIVATE_INTERIOR_ENTITY_SET(int interior, char* entitySetName);` |
| [DISABLE_INTERIOR](../natives/INTERIOR/DisableInterior.md) | Example: | `void DISABLE_INTERIOR(int interiorID, BOOL toggle);` |
| [GET_CLOSEST_FIRE_POS](../natives/FIRE/GetClosestFirePos.md) | Returns TRUE if it found something. FALSE if not. | `BOOL GET_CLOSEST_FIRE_POS(Vector3* outPosition, float x, float y, float z);` |
| [_GET_GLOBAL_WATER_TYPE](../natives/STREAMING/GetGlobalWaterType.md) | Provides the get global water type native operation. | `int _GET_GLOBAL_WATER_TYPE();` |
| [GET_INTERIOR_AT_COORDS](../natives/INTERIOR/GetInteriorAtCoords.md) | Returns interior ID from specified coordinates. If coordinates are outside, then it returns 0. | `int GET_INTERIOR_AT_COORDS(float x, float y, float z);` |
| [GET_INTERIOR_AT_COORDS_WITH_TYPE](../natives/INTERIOR/GetInteriorAtCoordsWithType.md) | Returns the interior ID representing the requested interior at that location (if found?). The supplied interior string is not the same as the one used to load the interior. | `int GET_INTERIOR_AT_COORDS_WITH_TYPE(float x, float y, float z, char* interiorType);` |
| [GET_INTERIOR_AT_COORDS_WITH_TYPEHASH](../natives/INTERIOR/GetInteriorAtCoordsWithTypehash.md) | Hashed version of GET_INTERIOR_AT_COORDS_WITH_TYPE | `int GET_INTERIOR_AT_COORDS_WITH_TYPEHASH(float x, float y, float z, cs_type(int) Hash typeHash);` |
| [GET_INTERIOR_FROM_COLLISION](../natives/INTERIOR/GetInteriorFromCollision.md) | Provides the get interior from collision native operation. | `int GET_INTERIOR_FROM_COLLISION(float x, float y, float z);` |
| [GET_INTERIOR_FROM_ENTITY](../natives/INTERIOR/GetInteriorFromEntity.md) | Returns the handle of the interior that the entity is in. Returns 0 if outside. | `int GET_INTERIOR_FROM_ENTITY(Entity entity);` |
| [GET_INTERIOR_FROM_PRIMARY_VIEW](../natives/INTERIOR/GetInteriorFromPrimaryView.md) | Provides the get interior from primary view native operation. | `int GET_INTERIOR_FROM_PRIMARY_VIEW();` |
| [GET_INTERIOR_GROUP_ID](../natives/INTERIOR/GetInteriorGroupId.md) | Returns the group ID of the specified interior. For example, regular interiors have group 0, subway interiors have group 1. There are a few other groups too. | `int GET_INTERIOR_GROUP_ID(int interior);` |
| [GET_INTERIOR_HEADING](../natives/INTERIOR/GetInteriorHeading.md) | Returns interior heading in radians. Multiply the returned value with 57.29578 (or 180.0 / math.pi) to convert it to degrees. | `float GET_INTERIOR_HEADING(int interior);` |
| [GET_INTERIOR_LOCATION_AND_NAMEHASH](../natives/INTERIOR/GetInteriorLocationAndNamehash.md) | Provides the get interior location and namehash native operation. | `void GET_INTERIOR_LOCATION_AND_NAMEHASH(int interior, Vector3* position, Hash* nameHash);` |
| [GET_NAME_OF_ZONE](../natives/ZONE/GetNameOfZone.md) | Provides the get name of zone native operation. | `char* GET_NAME_OF_ZONE(float x, float y, float z);` |
| [GET_NUMBER_OF_FIRES_IN_RANGE](../natives/FIRE/GetNumberOfFiresInRange.md) | Provides the get number of fires in range native operation. | `int GET_NUMBER_OF_FIRES_IN_RANGE(float x, float y, float z, float radius);` |
| [GET_OFFSET_FROM_INTERIOR_IN_WORLD_COORDS](../natives/INTERIOR/GetOffsetFromInteriorInWorldCoords.md) | Provides the get offset from interior in world coords native operation. | `Vector3 GET_OFFSET_FROM_INTERIOR_IN_WORLD_COORDS(int interior, float x, float y, float z);` |
| [GET_WATER_HEIGHT](../natives/WATER/GetWaterHeight.md) | Retrieves the depth of the water beneath the specified position, accounting for the waves. | `BOOL GET_WATER_HEIGHT(float x, float y, float z, float* height);` |
| [GET_WATER_HEIGHT_NO_WAVES](../natives/WATER/GetWaterHeightNoWaves.md) | Retrieves the depth of the water beneath the specified position, disregarding wave effects. | `BOOL GET_WATER_HEIGHT_NO_WAVES(float x, float y, float z, float* height);` |
| [GET_ZONE_AT_COORDS](../natives/ZONE/GetZoneAtCoords.md) | Provides the get zone at coords native operation. | `int GET_ZONE_AT_COORDS(float x, float y, float z);` |
| [GET_ZONE_FROM_NAME_ID](../natives/ZONE/GetZoneFromNameId.md) | Refer to https://docs.fivem.net/docs/game-references/zones/ for a list of all zones including their integer ID, string ID, short name and full name | `int GET_ZONE_FROM_NAME_ID(char* zoneName);` |

<!-- 25 rows -->

## HUD and Blips

| Native | Description | C signature |
|---|---|---|
| [_ADD_BLIP_FOR_AREA](../natives/HUD/AddBlipForArea.md) | Adds a rectangular blip for the specified coordinates/area. | `Blip _ADD_BLIP_FOR_AREA(float x, float y, float z, float width, float height);` |
| [ADD_BLIP_FOR_COORD](../natives/HUD/AddBlipForCoord.md) | Creates a blip for the specified coordinates. You can use `SET_BLIP_` natives to change the blip. | `Blip ADD_BLIP_FOR_COORD(float x, float y, float z);` |
| [ADD_BLIP_FOR_ENTITY](../natives/HUD/AddBlipForEntity.md) | Create a blip that by default is red (enemy), you can use [SET_BLIP_AS_FRIENDLY](#_0xC6F43D0E) to make it blue (friend). | `Blip ADD_BLIP_FOR_ENTITY(Entity entity);` |
| [ADD_BLIP_FOR_PICKUP](../natives/HUD/AddBlipForPickup.md) | Provides the add blip for pickup native operation. | `Blip ADD_BLIP_FOR_PICKUP(Pickup pickup);` |
| [ADD_BLIP_FOR_RADIUS](../natives/HUD/AddBlipForRadius.md) | Create a blip with a radius for the specified coordinates (it doesnt create the blip sprite, so you need to use [AddBlipCoords](#_0xC6F43D0E)) | `Blip ADD_BLIP_FOR_RADIUS(float posX, float posY, float posZ, float radius);` |
| [ADD_POINT_TO_GPS_CUSTOM_ROUTE](../natives/HUD/AddPointToGpsCustomRoute.md) | Provides the add point to gps custom route native operation. | `void ADD_POINT_TO_GPS_CUSTOM_ROUTE(float x, float y, float z);` |
| [ADD_POINT_TO_GPS_MULTI_ROUTE](../natives/HUD/AddPointToGpsMultiRoute.md) | Provides the add point to gps multi route native operation. | `void ADD_POINT_TO_GPS_MULTI_ROUTE(float x, float y, float z);` |
| [ADD_TEXT_COMPONENT_FLOAT](../natives/HUD/AddTextComponentFloat.md) | Adds a float to a text component placeholder, replacing `~1~` in the current text command's text label. | `void ADD_TEXT_COMPONENT_FLOAT(float value, int decimalPlaces);` |
| [ADD_TEXT_COMPONENT_FORMATTED_INTEGER](../natives/HUD/AddTextComponentFormattedInteger.md) | Adds a formatted integer as a text component placeholder, replacing ~a~ in the current text command's text label. | `void ADD_TEXT_COMPONENT_FORMATTED_INTEGER(int value, BOOL commaSeparated);` |
| [ADD_TEXT_COMPONENT_INTEGER](../natives/HUD/AddTextComponentInteger.md) | Provides the add text component integer native operation. | `void ADD_TEXT_COMPONENT_INTEGER(int value);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_BLIP_NAME](../natives/HUD/AddTextComponentSubstringBlipName.md) | Provides the add text component substring blip name native operation. | `void ADD_TEXT_COMPONENT_SUBSTRING_BLIP_NAME(Blip blip);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_KEYBOARD_DISPLAY](../natives/HUD/AddTextComponentSubstringKeyboardDisplay.md) | Certain characters like `<` will have to be escaped using html entities (e.g. `&lt;`), otherwise the text wont display properly. | `void ADD_TEXT_COMPONENT_SUBSTRING_KEYBOARD_DISPLAY(char* string);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_PHONE_NUMBER](../natives/HUD/AddTextComponentSubstringPhoneNumber.md) | p1 was always -1 | `void ADD_TEXT_COMPONENT_SUBSTRING_PHONE_NUMBER(char* p0, int p1);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME](../natives/HUD/AddTextComponentSubstringPlayerName.md) | Adds an arbitrary string as a text component placeholder, replacing `~a~` in the current text command's text label. | `void ADD_TEXT_COMPONENT_SUBSTRING_PLAYER_NAME(char* text);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL](../natives/HUD/AddTextComponentSubstringTextLabel.md) | Provides the add text component substring text label native operation. | `void ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL(char* labelName);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL_HASH_KEY](../natives/HUD/AddTextComponentSubstringTextLabelHashKey.md) | It adds the localized text of the specified GXT entry name. Eg. if the argument is GET_HASH_KEY("ES_HELP"), adds "Continue". Just uses a text labels hash key | `void ADD_TEXT_COMPONENT_SUBSTRING_TEXT_LABEL_HASH_KEY(Hash gxtEntryHash);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_TIME](../natives/HUD/AddTextComponentSubstringTime.md) | Takes a time in milliseconds and converts it to a string. Use `~a~` to mark the position in your line of text where you want this substring inserted. | `void ADD_TEXT_COMPONENT_SUBSTRING_TIME(int timestamp, int format);` |
| [ADD_TEXT_COMPONENT_SUBSTRING_WEBSITE](../natives/HUD/AddTextComponentSubstringWebsite.md) | This native (along with 0x5F68520888E69014 and 0x6C188BE134E074AA) do not actually filter anything. They simply add the provided text (as of 944) | `void ADD_TEXT_COMPONENT_SUBSTRING_WEBSITE(char* website);` |
| [BEGIN_TEXT_COMMAND_BUSYSPINNER_ON](../natives/HUD/BeginTextCommandBusyspinnerOn.md) | Initializes the text entry for the the text next to a loading prompt. All natives for for building UI texts can be used here | `void BEGIN_TEXT_COMMAND_BUSYSPINNER_ON(char* string);` |
| [BEGIN_TEXT_COMMAND_CLEAR_PRINT](../natives/HUD/BeginTextCommandClearPrint.md) | clears a print text command with this text | `void BEGIN_TEXT_COMMAND_CLEAR_PRINT(char* text);` |

<!-- 20 rows -->

Total rows: 300.
