#pragma once


#include "../NativeCaller.h"
#include "Ped/Ped.h"
#include "Ped/PedBoneHashes.h"
#include "../Model/Model.h"
#include "ICollection.h"

namespace SDK {
	class EntityBone : public Class::IExportable<EntityBone>
	{
	public:
		using Type = int;

		//for export
		EntityBone* getPersistent() override {
			return EntityBone::constructor(getIndex(), getOwner());
		}

		static EntityBone* constructor(EntityBone::Type index, Entity* owner) {
			return new EntityBone(index, owner);
		}

		EntityBone(EntityBone::Type index, Entity* owner)
			: m_index(index), m_owner(owner)
		{}
		EntityBone(std::string boneName, Entity* owner)
			: EntityBone(getIndexByName(owner->getId(), boneName), owner)
		{}

		///<summary>Gets the position of this <see cref="EntityBone"/> in world coords.</summary>
		Vector3D getPos() {
			return Call(
				SE::ENTITY::GET_WORLD_POSITION_OF_ENTITY_BONE,
				getOwner()->getId(),
				getIndex()
			);
		}

		///<summary>Determines if this <see cref="EntityBone"/> is valid.</summary>
		bool isValid() {
			return getIndex() != -1;
		}

		///<summary></summary>
		static EntityBone::Type getIndexByName(SE::Entity entity, std::string boneName) {
			return Call(
				SE::ENTITY::GET_ENTITY_BONE_INDEX_BY_NAME,
				entity,
				boneName.c_str()
			);
		}

		///<summary>Gets the bone index of this <see cref="EntityBone"/>.</summary>
		EntityBone::Type getIndex() {
			return m_index;
		}

		///<summary></summary>
		Entity* getOwner() {
			return m_owner;
		}
	private:
		EntityBone::Type m_index;
		Entity* m_owner = nullptr;
	};


	class PedBone
		: public EntityBone, public Class::IExportable<PedBone>
	{
	public:
		//for export
		PedBone* getPersistent() override {
			return PedBone::constructor(getIndex(), getOwner());
		}

		static PedBone* constructor(EntityBone::Type index, Entity* owner) {
			return new PedBone(index, owner);
		}
		
		PedBone(HASH::PedBone bone, Ped* owner)
			: PedBone(getIndexByPedBone(owner, bone), owner)
		{}

		PedBone(EntityBone::Type index, Entity* owner)
			: EntityBone(index, owner)
		{}

		///<summary></summary>
		static EntityBone::Type getIndexByPedBone(Ped* ped, HASH::PedBone bone) {
			return Call(
				SE::PED::GET_PED_BONE_INDEX,
				ped->getId(),
				(int)bone
			);
		}
	};


	class EntityBoneCollection
		: public IEntityCollection<EntityBone::Type, EntityBone>, public Class::IExportable<EntityBoneCollection>
	{
	public:
		//for export
		EntityBoneCollection* getPersistent() override {
			return EntityBoneCollection::constructor(getOwner());
		}

		static EntityBoneCollection* constructor(Entity* owner) {
			return new EntityBoneCollection(owner);
		}

		EntityBoneCollection(Entity* owner)
			: IEntityCollection(owner)
		{}

		///<summary></summary>
		EntityBone* createItem(EntityBone::Type index) override {
			return new EntityBone(index, getOwner());
		}

		///<summary></summary>
		bool hasItem(EntityBone::Type index) override {
			return true;
		}
	};


	class PedBoneCollection
		: public IPedCollection<HASH::PedBone, PedBone>, public Class::IExportable<PedBoneCollection>
	{
	public:
		//for export
		PedBoneCollection* getPersistent() override {
			return PedBoneCollection::constructor(getOwner());
		}

		static PedBoneCollection* constructor(Ped* owner) {
			return new PedBoneCollection(owner);
		}

		PedBoneCollection(Ped* owner)
			: IPedCollection(owner)
		{}

		///<summary></summary>
		PedBone* createItem(HASH::PedBone hash) override {
			return new PedBone(hash, getOwner());
		}

		///<summary></summary>
		bool hasItem(HASH::PedBone index) override {
			return true;
		}

		///<summary>Gets the last damaged Bone for this <see cref="Ped"/>.</summary>
		PedBone* getLastDamaged() {
			int outBone;
			
			if (Call(
				SE::PED::GET_PED_LAST_DAMAGE_BONE,
				getOwner()->getId(),
				&outBone
			))
			{
				return getItem(
					HASH::PedBone(outBone)
				);
			}

			return getItem(HASH::PedBone::SKEL_ROOT);
		}

		///<summary>Clears the last damage a bone on this <see cref="Ped"/> received.</summary>
		void clearLastDamaged() {
			Call(
				SE::PED::CLEAR_PED_LAST_DAMAGE_BONE,
				getOwner()->getId()
			);
		}
	};
};