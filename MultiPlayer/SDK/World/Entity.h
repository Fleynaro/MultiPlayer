#pragma once


#include "../NativeCaller.h"
#include "../Model/Model.h"
#include "Animation.h"
#include "Game/GameStructure.h"

namespace SDK {
	class Entity : public Class::IExportable<Entity>
	{
	public:
		//for export
		Entity* getPersistent() override {
			return constructor(getId());
		}

		static Entity* constructor(SE::Entity id) {
			return new Entity(id);
		}

		enum Type
		{
			No,
			Ped,
			Vehicle,
			Object
		};
		///<summary>Gets the type of Entity.</summary>
		static Type getType(SE::Entity id) {
			return (Type)Call(
				SE::ENTITY::GET_ENTITY_TYPE,
				id
			);
		}

		Entity(SE::Entity id) {
			m_id = id;
		}

		///<summary>Gets or sets the id of this <see cref="Entity"/>.</summary>
		SE::Entity getId() {
			return m_id;
		}

		///<summary>Gets the type of this entity.</summary>
		Type getType() {
			return getType(getId());
		}

		///<summary>Gets or sets the address of this <see cref="Entity"/>.</summary>
		std::uintptr_t getAddr() {
			return (std::uintptr_t)GameObject::EntityToAddress(getId());
		}

		static SE::Entity GetIdByAddress(std::uintptr_t addr) {
			return (SE::Entity)GameObject::AddressToEntity((void*)addr);
		}

		///<summary>Gets the model of this entity.</summary>
		Model getModel() {
			return Model(
				Call(
					SE::ENTITY::GET_ENTITY_MODEL,
					getId()
				)
			);
		}

		///<summary>Gets the health of this <see cref="Entity"/> as an <see cref="uint32_t"/>.</summary>
		uint32_t getHealth() {
			return Call(
				SE::ENTITY::GET_ENTITY_HEALTH,
				getId()
			);
		}

		///<summary>Gets the maximum health of this <see cref="Entity"/> as an <see cref="uint32_t"/>.</summary>
		uint32_t getMaxHealth() {
			return Call(
				SE::ENTITY::GET_ENTITY_MAX_HEALTH,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is dead.</summary>
		bool isDead() {
			return Call(
				SE::ENTITY::IS_ENTITY_DEAD,
				getId()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is alive.</summary>
		bool isAlive() {
			return !isDead();
		}

		///<summary>Gets the position of this <see cref="Entity"/>.</summary>
		Vector3D getPos() {
			return Call(
				SE::ENTITY::GET_ENTITY_COORDS,
				getId(),
				TRUE
			);
		}

		///<summary>Sets the position of this <see cref="Entity"/>.</summary>
		void setPos(Vector3D pos) {
			Call(
				SE::ENTITY::SET_ENTITY_COORDS,
				getId(),
				pos.getX(), pos.getY(), pos.getZ(),
				1, 0, 0, 1
			);
		}

		///<summary>Gets the rotation of this <see cref="Entity"/>.</summary>
		Vector3D getRot() {
			return Call(
				SE::ENTITY::GET_ENTITY_ROTATION,
				getId(),
				TRUE
			);
		}
		
		///<summary>Sets the rotation of this <see cref="Entity"/>.</summary>
		void setRot(Vector3D rot) {
			Call(
				SE::ENTITY::SET_ENTITY_ROTATION,
				getId(),
				rot.getX(), rot.getY(), rot.getZ(),
				0, TRUE
			);
		}

		///<summary>Sets the position of this <see cref="Entity"/> without any offset.</summary>
		void setPosNoOffset(Vector3D pos) {
			Call(
				SE::ENTITY::SET_ENTITY_COORDS_NO_OFFSET,
				getId(),
				pos.getX(), pos.getY(), pos.getZ(),
				TRUE, TRUE, TRUE
			);
		}
		
		//Quaternion


		///<summary>Gets the heading of this <see cref="Entity"/>.</summary>
		float getHeading() {
			return Call(
				SE::ENTITY::GET_ENTITY_HEADING,
				getId()
			);
		}

		///<summary>Sets the heading of this <see cref="Entity"/>.</summary>
		void setHeading(float value) {
			Call(
				SE::ENTITY::SET_ENTITY_HEADING,
				getId(),
				value
			);
		}

		///<summary>Gets the vector that points above this <see cref="Entity"/>.</summary>
		Vector3D getUpVector() {}
		Vector3D getRightVector() {}
		Vector3D getForwardVector() {}
		Vector3D getLeftVector() {}
		//getMatrix(4x4)

		///<summary>Sets a value indicating whether this <see cref="Entity"/> is frozen.</summary>
		void setPositionFrozen(bool state) {
			Call(
				SE::ENTITY::FREEZE_ENTITY_POSITION,
				getId(),
				state
			);
		}

		///<summary>Gets the velocity of this <see cref="Entity"/>.</summary>
		Vector3D getVelocity() {
			return Call(
				SE::ENTITY::GET_ENTITY_VELOCITY,
				getId()
			);
		}

		///<summary>Sets the velocity of this <see cref="Entity"/>.</summary>
		void setVelocity(Vector3D vel) {
			Call(
				SE::ENTITY::SET_ENTITY_VELOCITY,
				getId(),
				vel.getX(), vel.getY(), vel.getZ()
			);
		}

		///<summary>Gets the rotation velocity of this <see cref="Entity"/>.</summary>
		Vector3D getRotVelocity() {
			return Call(
				SE::ENTITY::GET_ENTITY_ROTATION_VELOCITY,
				getId()
			);
		}

		///<summary>Gets the speed of this <see cref="Entity"/>.</summary>
		float getSpeed() {
			return Call(
				SE::ENTITY::GET_ENTITY_SPEED,
				getId()
			);
		}

		///<summary>Sets the max speed of this <see cref="Entity"/>.</summary>
		void setMaxSpeed(float value) {
			Call(
				SE::ENTITY::SET_ENTITY_MAX_SPEED,
				getId(),
				value
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Entity"/> has gravity.</summary>
		void setHasMaxGravity(bool state) {
			Call(
				SE::ENTITY::SET_ENTITY_HAS_GRAVITY,
				getId(),
				state
			);
		}

		///<summary>Gets how high above ground this <see cref="Entity"/> is.</summary>
		float getHeightAboveGround() {
			return Call(
				SE::ENTITY::GET_ENTITY_HEIGHT_ABOVE_GROUND,
				getId()
			);
		}

		///<summary>Gets a value indicating how submersed this <see cref="Entity"/> is, 1.0f means the whole entity is submerged.</summary>
		float getSubmersionLevel() {
			return Call(
				SE::ENTITY::GET_ENTITY_SUBMERGED_LEVEL,
				getId()
			);
		}

		///<summary>Gets the level of detail distance of this <see cref="Entity"/>.</summary>
		int getLodDistance() {
			return Call(
				SE::ENTITY::GET_ENTITY_LOD_DIST,
				getId()
			);
		}

		///<summary>Sets the level of detail distance of this <see cref="Entity"/>.</summary>
		void setLodDistance(int value) {
			return Call(
				SE::ENTITY::SET_ENTITY_LOD_DIST,
				getId(),
				value
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is visible.</summary>
		bool isVisible() {
			return Call(
				SE::ENTITY::IS_ENTITY_VISIBLE,
				getId()
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Entity"/> is visible.</summary>
		void setVisible(bool state) {
			return Call(
				SE::ENTITY::SET_ENTITY_VISIBLE,
				getId(),
				state,
				FALSE
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is occluded.</summary>
		bool isOccluded() {
			return Call(
				SE::ENTITY::IS_ENTITY_OCCLUDED,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is on screen.</summary>
		bool isOnScreen() {
			return Call(
				SE::ENTITY::IS_ENTITY_ON_SCREEN,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is rendered.</summary>
		bool isRendered() { return false; }

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is upright.</summary>
		bool isUpright() {
			return Call(
				SE::ENTITY::IS_ENTITY_UPRIGHT,
				getId(),
				30.f
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is upside down.</summary>
		bool isUpsideDown() {
			return Call(
				SE::ENTITY::IS_ENTITY_UPSIDEDOWN,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is in the air.</summary>
		bool isInAir() {
			return Call(
				SE::ENTITY::IS_ENTITY_IN_AIR,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is in water.</summary>
		bool isInWater() {
			return Call(
				SE::ENTITY::IS_ENTITY_IN_WATER,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is persistent.</summary>
		bool isPersistent() {
			return Call(
				SE::ENTITY::IS_ENTITY_A_MISSION_ENTITY,
				getId()
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Entity"/> is persistent.</summary>
		void setPersistent(bool state) {
			if (state)
			{
				Call(
					SE::ENTITY::SET_ENTITY_AS_MISSION_ENTITY,
					getId(),
					TRUE, FALSE
				);
			}
			else {
				//markAsNoLongerNeeded();
			}
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is on fire.</summary>
		bool isOnFire() {
			return Call(
				SE::FIRE::IS_ENTITY_ON_FIRE,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> is invincible.</summary>
		bool isInvincible() { return false; }
		///<summary>Sets a value indicating whether this <see cref="Entity"/> is invincible.</summary>
		void setInvincible(bool state) {
			Call(
				SE::ENTITY::SET_ENTITY_INVINCIBLE,
				getId(),
				state
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> can only be damaged by <see cref="Player"/>s.</summary>
		bool isOnlyDamagedByPlayer() { return false; }
		///<summary>Sets a value indicating whether this <see cref="Entity"/> can only be damaged by <see cref="Player"/>s.</summary>
		void setOnlyDamagedByPlayer(bool state) {
			Call(
				SE::ENTITY::SET_ENTITY_ONLY_DAMAGED_BY_PLAYER,
				getId(),
				state
			);
		}

		///<summary>Gets how opaque this <see cref="Entity"/> is.</summary>
		int getOpacity() {
			return Call(
				SE::ENTITY::GET_ENTITY_ALPHA,
				getId()
			);
		}

		///<summary>Sets how opaque this <see cref="Entity"/> is.</summary>
		void setOpacity(int value) {
			Call(
				SE::ENTITY::SET_ENTITY_ALPHA,
				getId(),
				value,
				FALSE
			);
		}

		///<summary>Resets the opacity, <seealso cref="Opacity"/>.</summary>
		void resetOpacity() {
			Call(
				SE::ENTITY::RESET_ENTITY_ALPHA,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> has collided with anything.</summary>
		bool hasCollided() {
			return Call(
				SE::ENTITY::HAS_ENTITY_COLLIDED_WITH_ANYTHING,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Entity"/> has collision.</summary>
		bool isCollisionEnabled() {
			return Call(
				SE::ENTITY::_GET_ENTITY_COLLISON_DISABLED,
				getId()
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Entity"/> has collision.</summary>
		void setCollisionEnabled(bool state) {
			Call(
				SE::ENTITY::SET_ENTITY_COLLISION,
				getId(),
				state, FALSE
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Entity"/> is recording collisions.</summary>
		void setRecordingCollisions(bool state) {
			Call(
				SE::ENTITY::SET_ENTITY_RECORDS_COLLISIONS,
				getId(),
				state
			);
		}

		///<summary>Sets the collision between this <see cref="Entity"/> and another <see cref="Entity"/>.</summary>
		void setNoCollision(Entity *entity, bool toggle) {
			Call(
				SE::ENTITY::SET_ENTITY_NO_COLLISION_ENTITY,
				getId(), entity->getId(),
				toggle
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> has been damaged by a specified <see cref="Entity"/>.</summary>
		virtual bool hasBeenDamagedBy(Entity* entity) {
			return Call(
				SE::ENTITY::HAS_ENTITY_BEEN_DAMAGED_BY_ENTITY,
				getId(), entity->getId(),
				TRUE
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> has been damaged by any weapon.</summary>
		virtual bool hasBeenDamagedByAnyWeapon() {
			return Call(
				SE::WEAPON::HAS_ENTITY_BEEN_DAMAGED_BY_WEAPON,
				getId(),
				0, 2
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> has been damaged by any melee weapon.</summary>
		virtual bool hasBeenDamagedByAnyMeleeWeapon() {
			return Call(
				SE::WEAPON::HAS_ENTITY_BEEN_DAMAGED_BY_WEAPON,
				getId(),
				0, 1
			);
		}

		///<summary>Clears the last weapon damage this <see cref="Entity"/> received.</summary>
		virtual void ClearLastWeaponDamage() {
			Call(
				SE::WEAPON::CLEAR_ENTITY_LAST_WEAPON_DAMAGE,
				getId()
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is in a specified area</summary>
		bool isInArea(Vector3D minBounds, Vector3D maxBounds) {
			return Call(
				SE::ENTITY::IS_ENTITY_IN_AREA,
				getId(),
				minBounds.getX(), minBounds.getY(), minBounds.getZ(),
				maxBounds.getX(), maxBounds.getY(), maxBounds.getZ(),
				FALSE, TRUE, (SE::Any)0
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is in a specified angled area</summary>
		bool isInAngledArea(Vector3D origin, Vector3D edge, float angle) {
			return Call(
				SE::ENTITY::IS_ENTITY_IN_ANGLED_AREA,
				getId(),
				origin.getX(), origin.getY(), origin.getZ(),
				edge.getX(), edge.getY(), edge.getZ(),
				angle,
				FALSE, TRUE, (SE::Any)0
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is near a specified <see cref="Entity"/>.</summary>
		bool isNearEntity(Entity* entity, Vector3D bounds) {
			return Call(
				SE::ENTITY::IS_ENTITY_AT_ENTITY,
				getId(), entity->getId(),
				bounds.getX(), bounds.getY(), bounds.getZ(),
				FALSE, TRUE, FALSE
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is touching an <see cref="Entity"/> with the <see cref="Model"/> <paramref name="model"/>.</summary>
		bool isTouching(Model model) {
			return Call(
				SE::ENTITY::IS_ENTITY_TOUCHING_MODEL,
				getId(),
				model.getHash()
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is touching the <see cref="Entity"/> <paramref name="entity"/>.</summary>
		bool isTouching(Entity* entity) {
			return Call(
				SE::ENTITY::IS_ENTITY_TOUCHING_ENTITY,
				getId(), entity->getId()
			);
		}

		///<summary>Gets the position in world coords of an offset relative this <see cref="Entity"/>.</summary>
		Vector3D getOffsetPosition(Vector3D offset) {
			return Call(
				SE::ENTITY::GET_OFFSET_FROM_ENTITY_IN_WORLD_COORDS,
				getId(),
				offset.getX(), offset.getY(), offset.getZ()
			);
		}

		///<summary>Gets the relative offset of this <see cref="Entity"/> from a world coords position.</summary>
		Vector3D getPositionOffset(Vector3D worldCoords) {
			return Call(
				SE::ENTITY::GET_OFFSET_FROM_ENTITY_GIVEN_WORLD_COORDS,
				getId(),
				worldCoords.getX(), worldCoords.getY(), worldCoords.getZ()
			);
		}

		///<summary>Attaches this <see cref="Entity"/> to a different <see cref="Entity"/>.</summary>
		void attachTo(Entity *entity, Vector3D position, Vector3D rotation) {
			Call(
				SE::ENTITY::ATTACH_ENTITY_TO_ENTITY,
				getId(), entity->getId(),
				-1,
				position.getX(), position.getY(), position.getZ(),
				rotation.getX(), rotation.getY(), rotation.getZ(),
				0, 0, 0, 0, 2, 1
			);
		}

		///<summary>Detaches this <see cref="Entity"/> from any <see cref="Entity"/> it may be attached to.</summary>
		void detach() {
			Call(
				SE::ENTITY::DETACH_ENTITY,
				getId(),
				TRUE, TRUE
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is attached to any other <see cref="Entity"/>.</summary>
		bool isAttached() {
			return Call(
				SE::ENTITY::IS_ENTITY_ATTACHED,
				getId()
			);
		}

		///<summary>Determines whether this <see cref="Entity"/> is attached to the specified <see cref="Entity"/>.</summary>
		bool isAttachedTo(Entity *entity) {
			return Call(
				SE::ENTITY::IS_ENTITY_ATTACHED_TO_ENTITY,
				getId(), entity->getId()
			);
		}

		///<summary>Gets the <see cref="Entity"/> this <see cref="Entity"/> is attached to.</summary>
		/*Entity* getEntityAttachedTo() {
			return callNative(
				SE::ENTITY::GET_ENTITY_ATTACHED_TO,
				getId()
			);
		}*/
		
		///<summary></summary>
		bool isPlayingAnim(ANIM::Anim& animation) {
			return isPlayingAnim(
				animation.getDict().c_str(),
				animation.getName().c_str()
			);
		}

		///<summary></summary>
		bool isPlayingAnim(const char* dict, const char* name) {
			return Call(
				SE::ENTITY::IS_ENTITY_PLAYING_ANIM,
				getId(),
				dict, name,
				3
			);
		}

		///<summary>Stops all particle effects attached to this <see cref="Entity"/>.</summary>
		void removeAllParticleEffects() {
			Call(
				SE::GRAPHICS::REMOVE_PARTICLE_FX_FROM_ENTITY,
				getId()
			);
		}

		///<summary>Marks this <see cref="Entity"/> as no longer needed letting the game delete it when its too far away.</summary>
		void markAsNoLongerNeeded() {
			Call(
				SE::ENTITY::SET_ENTITY_AS_MISSION_ENTITY,
				getId(),
				FALSE, TRUE
			);

			auto handle = getId();
			Call(
				SE::ENTITY::SET_ENTITY_AS_NO_LONGER_NEEDED,
				&handle
			);
			m_id = handle;
		}

		///<summary>Determines whether this <see cref="Entity"/> exists.</summary>
		bool exists() {
			return Call(
				SE::ENTITY::DOES_ENTITY_EXIST,
				getId()
			);
		}
	private:
		SE::Entity m_id = 0;
	};
};