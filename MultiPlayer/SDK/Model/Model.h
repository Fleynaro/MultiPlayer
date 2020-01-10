#pragma once


#include "../NativeCaller.h"
#include "../World/Ped/PedHashes.h"
#include "../World/Vehicle/VehicleHashes.h"

namespace SDK {
	//Generic model
	class Model : public Class::IExportable<Model>
	{
	public:
		using Hash = DWORD;

		//for export
		Model* getPersistent() override {
			return Model::constructor(getHash());
		}

		static Model* constructor(Hash hash) {
			return new Model(hash);
		}

		Model()
			: Model(0)
		{}

		Model(Hash hash)
			: m_hash(hash)
		{}
		
		Hash getHash() {
			return m_hash;
		}

		///<summary>Returns true if this <see cref="Model"/> is valid.</summary>
		bool isValid() {
			return Call(
				SE::STREAMING::IS_MODEL_VALID,
				getHash()
			) == TRUE;
		}

		///<summary>Returns true if this <see cref="Model"/> is in the cd image.</summary>
		bool isInCdImage() {
			return Call(
				SE::STREAMING::IS_MODEL_IN_CDIMAGE,
				getHash()
			) == TRUE;
		}

		///<summary>Returns true if this <see cref="Model"/> is loaded.</summary>
		bool isLoaded() {
			return Call(
				SE::STREAMING::HAS_MODEL_LOADED,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether the collision for this <see cref="Model"/> is loaded.</summary>
		bool isCollisionLoaded() {
			return Call(
				SE::STREAMING::HAS_COLLISION_FOR_MODEL_LOADED,
				getHash()
			) == TRUE;
		}

		///<summary>Attempt to load this <see cref="Model"/> into memory.</summary>
		virtual void request() {
			Call(
				SE::STREAMING::REQUEST_MODEL,
				getHash()
			);
		}

		///<summary>Attempt to load this <see cref="Model"/> into memory for a given period of time.</summary>
		bool load(std::size_t timeout = 2000) {
			if (!isInCdImage()) return false;
			if (!isValid()) return false;
			if (isLoaded()) return true;

			auto context = GameScriptEngine::getCurrentScriptExeContext();
			if (context == nullptr) {
				//throw ex
				return false;
			}

			request();
			
			std::size_t timeEnd = timeGetTime() + timeout;
			while (!isLoaded())
			{
				if (timeGetTime() > timeEnd)
					return false;
				context->yield();
			}
			return true;
		}

		///<summary>Attempt to load this <see cref="Model"/>`s collision into memory.</summary>
		virtual void requestCollision() {
			Call(
				SE::STREAMING::REQUEST_COLLISION_FOR_MODEL,
				getHash()
			);
		}

		///<summary>Attempt to load this <see cref="Model"/>`s collision into memory for a given period of time.</summary>
		bool loadCollision(std::size_t timeout = 2000) {
			if (!isInCdImage()) return false;
			if (!isValid()) return false;
			if (!isCollisionLoaded()) return true;

			auto context = GameScriptEngine::getCurrentScriptExeContext();
			if (context == nullptr) {
				//throw ex
				return false;
			}

			requestCollision();

			std::size_t timeEnd = timeGetTime() + timeout;
			while (!isCollisionLoaded())
			{
				if (timeGetTime() > timeEnd)
					return false;
				context->yield();
			}
			return true;
		}

		///<summary>Frees this <see cref="Model"/> from memory.</summary>
		void markAsNoLongerNeeded() {
			Call(
				SE::STREAMING::SET_MODEL_AS_NO_LONGER_NEEDED,
				getHash()
			);
		}
	private:
		Hash m_hash;
	};

	//Ped model
	class PedModel
		: public Model, public Class::IExportable<PedModel>
	{
	public:
		//for export
		PedModel* getPersistent() override {
			return PedModel::constructor(getHash());
		}

		static PedModel* constructor(Hash hash) {
			return new PedModel(hash);
		}

		PedModel() = default;

		PedModel(Hash hash)
			: Model(hash)
		{}

		PedModel(HASH::Ped hash)
			: Model(Model::Hash(hash))
		{}
		PedModel(Model model)
			: PedModel(model.getHash())
		{}

		void request() override {
			Call(
				SE::STREAMING::REQUEST_MENU_PED_MODEL,
				getHash()
			);
		}
	};

	//Vehicle model
	class VehicleModel
		: public Model, public Class::IExportable<VehicleModel>
	{
	public:
		//for export
		VehicleModel* getPersistent() override {
			return VehicleModel::constructor(getHash());
		}

		static VehicleModel* constructor(Hash hash) {
			return new VehicleModel(hash);
		}

		VehicleModel() = default;

		VehicleModel(Hash hash)
			: Model(hash)
		{}

		VehicleModel(HASH::Vehicle hash)
			: Model(Model::Hash(hash))
		{}
		VehicleModel(Model model)
			: Model(model.getHash())
		{}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a bicycle.</summary>
		bool isBicycle() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_BICYCLE,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a bike.</summary>
		bool isBike() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_BIKE,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a boat.</summary>
		bool isBoat() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_BOAT,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a car.</summary>
		bool isCar() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_CAR,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is an amphibious car.</summary>
		bool isAmphibiousCar() {
			return false;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a blimp.</summary>
		bool isBlimp() {
			return false;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a cargobob.</summary>
		bool isCargobob() {
			return false;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a helicopter.</summary>
		bool isHelicopter() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_HELI,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a jet ski.</summary>
		bool isJetSki() {
			return Call(
				SE::VEHICLE::_IS_THIS_MODEL_A_JETSKI,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a plane.</summary>
		bool isPlane() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_PLANE,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a quad bike.</summary>
		bool isQuadBike() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_QUADBIKE,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is an amphibious quad bike.</summary>
		bool isAmphibiousQuadBike() {
			return false;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a train.</summary>
		bool isTrain() {
			return Call(
				SE::VEHICLE::IS_THIS_MODEL_A_TRAIN,
				getHash()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Model"/> is a trailer.</summary>
		bool isTrailer() {
			HASH::Vehicle hash = (HASH::Vehicle)getHash();
			return hash == HASH::Vehicle::Cargobob || hash == HASH::Vehicle::Cargobob2 || hash == HASH::Vehicle::Cargobob3 || hash == HASH::Vehicle::Cargobob4;
		}

		///<summary></summary>
		std::string getName()
		{
			return Call(
				SE::VEHICLE::GET_DISPLAY_NAME_FROM_VEHICLE_MODEL,
				getHash()
			);
		}
	};
}