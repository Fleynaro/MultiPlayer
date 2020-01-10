#pragma once


#include "../Entity.h"
#include "../Ped/Ped.h"
#include "../../Model/Model.h"

namespace SDK {

	class Vehicle
		: public Entity, public Class::IExportable<Vehicle>
	{
	public:
		enum class LicensePlateStyle
		{
			BlueOnWhite1 = 3,
			BlueOnWhite2 = 0,
			BlueOnWhite3 = 4,
			YellowOnBlack = 1,
			YellowOnBlue = 2,
			NorthYankton = 5
		};
		enum class LicensePlateType
		{
			FrontAndRearPlates,
			FrontPlate,
			RearPlate,
			None
		};
		enum class Class
		{
			Compacts,
			Sedans,
			SUVs,
			Coupes,
			Muscle,
			SportsClassics,
			Sports,
			Super,
			Motorcycles,
			OffRoad,
			Industrial,
			Utility,
			Vans,
			Cycles,
			Boats,
			Helicopters,
			Planes,
			Service,
			Emergency,
			Military,
			Commercial,
			Trains
		};
		enum class Color
		{
			MetallicBlack,
			MetallicGraphiteBlack,
			MetallicBlackSteel,
			MetallicDarkSilver,
			MetallicSilver,
			MetallicBlueSilver,
			MetallicSteelGray,
			MetallicShadowSilver,
			MetallicStoneSilver,
			MetallicMidnightSilver,
			MetallicGunMetal,
			MetallicAnthraciteGray,
			MatteBlack,
			MatteGray,
			MatteLightGray,
			UtilBlack,
			UtilBlackPoly,
			UtilDarksilver,
			UtilSilver,
			UtilGunMetal,
			UtilShadowSilver,
			WornBlack,
			WornGraphite,
			WornSilverGray,
			WornSilver,
			WornBlueSilver,
			WornShadowSilver,
			MetallicRed,
			MetallicTorinoRed,
			MetallicFormulaRed,
			MetallicBlazeRed,
			MetallicGracefulRed,
			MetallicGarnetRed,
			MetallicDesertRed,
			MetallicCabernetRed,
			MetallicCandyRed,
			MetallicSunriseOrange,
			MetallicClassicGold,
			MetallicOrange,
			MatteRed,
			MatteDarkRed,
			MatteOrange,
			MatteYellow,
			UtilRed,
			UtilBrightRed,
			UtilGarnetRed,
			WornRed,
			WornGoldenRed,
			WornDarkRed,
			MetallicDarkGreen,
			MetallicRacingGreen,
			MetallicSeaGreen,
			MetallicOliveGreen,
			MetallicGreen,
			MetallicGasolineBlueGreen,
			MatteLimeGreen,
			UtilDarkGreen,
			UtilGreen,
			WornDarkGreen,
			WornGreen,
			WornSeaWash,
			MetallicMidnightBlue,
			MetallicDarkBlue,
			MetallicSaxonyBlue,
			MetallicBlue,
			MetallicMarinerBlue,
			MetallicHarborBlue,
			MetallicDiamondBlue,
			MetallicSurfBlue,
			MetallicNauticalBlue,
			MetallicBrightBlue,
			MetallicPurpleBlue,
			MetallicSpinnakerBlue,
			MetallicUltraBlue,
			MetallicBrightBlue2,
			UtilDarkBlue,
			UtilMidnightBlue,
			UtilBlue,
			UtilSeaFoamBlue,
			UtilLightningBlue,
			UtilMauiBluePoly,
			UtilBrightBlue,
			MatteDarkBlue,
			MatteBlue,
			MatteMidnightBlue,
			WornDarkBlue,
			WornBlue,
			WornLightBlue,
			MetallicTaxiYellow,
			MetallicRaceYellow,
			MetallicBronze,
			MetallicYellowBird,
			MetallicLime,
			MetallicChampagne,
			MetallicPuebloBeige,
			MetallicDarkIvory,
			MetallicChocoBrown,
			MetallicGoldenBrown,
			MetallicLightBrown,
			MetallicStrawBeige,
			MetallicMossBrown,
			MetallicBistonBrown,
			MetallicBeechwood,
			MetallicDarkBeechwood,
			MetallicChocoOrange,
			MetallicBeachSand,
			MetallicSunBleechedSand,
			MetallicCream,
			UtilBrown,
			UtilMediumBrown,
			UtilLightBrown,
			MetallicWhite,
			MetallicFrostWhite,
			WornHoneyBeige,
			WornBrown,
			WornDarkBrown,
			WornStrawBeige,
			BrushedSteel,
			BrushedBlackSteel,
			BrushedAluminium,
			Chrome,
			WornOffWhite,
			UtilOffWhite,
			WornOrange,
			WornLightOrange,
			MetallicSecuricorGreen,
			WornTaxiYellow,
			PoliceCarBlue,
			MatteGreen,
			MatteBrown,
			WornOrange2,
			MatteWhite,
			WornWhite,
			WornOliveArmyGreen,
			PureWhite,
			HotPink,
			Salmonpink,
			MetallicVermillionPink,
			Orange,
			Green,
			Blue,
			MettalicBlackBlue,
			MetallicBlackPurple,
			MetallicBlackRed,
			HunterGreen,
			MetallicPurple,
			MetaillicVDarkBlue,
			ModshopBlack1,
			MattePurple,
			MatteDarkPurple,
			MetallicLavaRed,
			MatteForestGreen,
			MatteOliveDrab,
			MatteDesertBrown,
			MatteDesertTan,
			MatteFoliageGreen,
			DefaultAlloyColor,
			EpsilonBlue,
			PureGold,
			BrushedGold
		};
		enum class LandingGearState
		{
			Deployed,
			Retracting,
			Deploying = 3,
			Retracted,
			Broken
		};
		enum class LockStatus
		{
			None,
			Unlocked,
			Locked,
			LockedForPlayer,
			StickPlayerInside,
			CanBeBrokenInto = 7,
			CanBeBrokenIntoPersist,
			CannotBeTriedToEnter = 10
		};
		enum class NeonLight
		{
			Left,
			Right,
			Front,
			Back
		};
		enum class RoofState
		{
			Closed,
			Opening,
			Opened,
			Closing
		};
		enum class Seat
		{
			None = -3,
			Any,
			Driver,
			Passenger,
			LeftFront = -1,
			RightFront,
			LeftRear,
			RightRear,
			ExtraSeat1,
			ExtraSeat2,
			ExtraSeat3,
			ExtraSeat4,
			ExtraSeat5,
			ExtraSeat6,
			ExtraSeat7,
			ExtraSeat8,
			ExtraSeat9,
			ExtraSeat10,
			ExtraSeat11,
			ExtraSeat12
		};
		enum class WindowTint
		{
			None,
			PureBlack,
			DarkSmoke,
			LightSmoke,
			Stock,
			Limo,
			Green
		};

		//for export
		Vehicle* getPersistent() override {
			return new Vehicle(getId());
		}

		Vehicle(SE::Vehicle id)
			: Entity(id)
		{};
		~Vehicle() {}

		///<summary>Gets the id of this <see cref="Vehicle"/>.</summary>
		SE::Vehicle getId() {
			return Entity::getId();
		}

		///<summary>Gets the display name of this <see cref="Vehicle"/>.</summary>
		std::string getName() {
			return getModel().getName();
		}

		///<summary>Gets the class name of this <see cref="Vehicle"/>.</summary>
		std::string getClassName() {
			return getVehicleClassName(getClass());
		}

		///<summary>Gets the model of this vehicle.</summary>
		VehicleModel getModel() {
			return Entity::getModel();
		}

		///<summary>Gets the class of this <see cref="Vehicle"/>.</summary>
		Class getClass() {
			return (Class)Call(
				SE::VEHICLE::GET_VEHICLE_CLASS,
				getId()
			);
		}

		///<summary></summary>
		static std::string getVehicleClassName(Class id)
		{
			/*
				Regex replace all:
				{
					Source:			(\w+),?
					Destinition:	case Class::$1:\nreturn "$1";\nbreak;
				}
			*/
			switch (id)
			{
			case Class::Compacts:
				return "Compacts";
				break;
			case Class::Sedans:
				return "Sedans";
				break;
			case Class::SUVs:
				return "SUVs";
				break;
			case Class::Coupes:
				return "Coupes";
				break;
			case Class::Muscle:
				return "Muscle";
				break;
			case Class::SportsClassics:
				return "SportsClassics";
				break;
			case Class::Sports:
				return "Sports";
				break;
			case Class::Super:
				return "Super";
				break;
			case Class::Motorcycles:
				return "Motorcycles";
				break;
			case Class::OffRoad:
				return "OffRoad";
				break;
			case Class::Industrial:
				return "Industrial";
				break;
			case Class::Utility:
				return "Utility";
				break;
			case Class::Vans:
				return "Vans";
				break;
			case Class::Cycles:
				return "Cycles";
				break;
			case Class::Boats:
				return "Boats";
				break;
			case Class::Helicopters:
				return "Helicopters";
				break;
			case Class::Planes:
				return "Planes";
				break;
			case Class::Service:
				return "Service";
				break;
			case Class::Emergency:
				return "Emergency";
				break;
			case Class::Military:
				return "Military";
				break;
			case Class::Commercial:
				return "Commercial";
				break;
			case Class::Trains:
				return "Trains";
				break;
			}
			return "not defined";
		}

		///<summary></summary>
		float getBodyHealth() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_BODY_HEALTH,
				getId()
			);
		}

		///<summary></summary>
		void setBodyHealth(float amount) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_BODY_HEALTH,
				getId(),
				amount
			);
		}

		///<summary></summary>
		virtual float getEngineHealth() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_ENGINE_HEALTH,
				getId()
			);
		}

		///<summary></summary>
		virtual void setEngineHealth(float amount) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_ENGINE_HEALTH,
				getId(),
				amount
			);
		}

		///<summary></summary>
		float getPetrolTankHealth() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_PETROL_TANK_HEALTH,
				getId()
			);
		}

		///<summary></summary>
		void setPetrolTankHealth(float amount) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_PETROL_TANK_HEALTH,
				getId(),
				amount
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/>s engine is running.</summary>
		bool isEngineRunning() {
			return Call(
				SE::VEHICLE::GET_IS_VEHICLE_ENGINE_RUNNING,
				getId()
			) == TRUE;
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/>s engine is running.</summary>
		void setEngineRunning(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_ENGINE_ON,
				getId(),
				state,
				TRUE, FALSE
			);
		}

		///<summary>Turns this <see cref="Vehicle"/>s radio on or off.</summary>
		void setRadioEnabled(bool state) {
			Call(
				SE::AUDIO::SET_VEHICLE_RADIO_ENABLED,
				getId(),
				state
			);
		}

		enum class RadioStation
		{
			LosSantosRockRadio,
			NonStopPopFM,
			RadioLosSantos,
			ChannelX,
			WestCoastTalkRadio,
			RebelRadio,
			SoulwaxFM,
			EastLosFM,
			WestCoastClassics,
			BlaineCountyRadio,
			TheBlueArk,
			WorldWideFM,
			FlyloFM,
			TheLowdown,
			RadioMirrorPark,
			Space,
			VinewoodBoulevardRadio,
			SelfRadio,
			TheLab,
			BlondedLosSantos,
			LosSantosUndergroundRadio,
			RadioOff = 255
		};
		///<summary>Turns this <see cref="Vehicle"/>s radio on or off.</summary>
		void setRadioStation(RadioStation station) {
			if (station == RadioStation::RadioOff)
			{
				Call(
					SE::AUDIO::SET_VEH_RADIO_STATION,
					getId(),
					"OFF"
				);
			}
			else {
				Call(
					SE::AUDIO::SET_VEH_RADIO_STATION,
					getId(),
					SE::AUDIO::radioNames[(int)station]
				);
			}
		}

		///<summary>Sets this <see cref="Vehicle"/>s forward speed.</summary>
		virtual void setForwardSpeed(float speed) {
			Call(
				SE::VEHICLE::SET_VEHICLE_FORWARD_SPEED,
				getId(),
				speed
			);
		}

		///<summary>Gets the speed the drive wheels are turning at, This is the value used for the dashboard speedometers(after being converted to mph).</summary>
		virtual float getWheelSpeed() { return 0.f; }

		///<summary>Gets the acceleration of this <see cref="Vehicle"/>.</summary>
		float getAcceleration() {}

		///<summary>Gets the current RPM of this <see cref="Vehicle"/>.</summary>
		virtual float getCurrentRPM() { return 0.f; }

		///<summary>Sets the current RPM of this <see cref="Vehicle"/>. The current RPM between <c>0.0f</c> and <c>1.0f</c>.</summary>
		virtual void setCurrentRPM(float RPM) {}

		///<summary></summary>
		virtual float getHighGear() { return 0.f; }

		///<summary></summary>
		virtual void setHighGear(float value) {}

		///<summary></summary>
		virtual float getGear() { return 0.f; }

		///<summary></summary>
		virtual void setGear(float value) {}

		///<summary>Gets the engine temperature of this <see cref="Vehicle"/>.</summary>
		float getEngineTemperature() { return 0.f; }

		///<summary></summary>
		virtual float getOilVolume() { return 0.f; }

		///<summary></summary>
		virtual float getPetrolTankVolume() { return 0.f; }

		///<summary></summary>
		virtual float getClutch() { return 0.f; }

		///<summary></summary>
		virtual void setClutch(float value) {}

		///<summary></summary>
		virtual float getTurbo() { return 0.f; }

		///<summary></summary>
		virtual void setTurbo(float value) {}

		///<summary></summary>
		virtual int getGears() { return 0; }

		///<summary></summary>
		virtual void setGears(int value) {}

		///<summary></summary>
		virtual bool isWanted() { return false; }

		///<summary></summary>
		virtual void setWanted(bool state) {}

		//...


		///<summary>Starts sounding the alarm on this <see cref="Vehicle"/>.</summary>
		void startAlarm() {
			Call(
				SE::VEHICLE::START_VEHICLE_ALARM,
				getId()
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has a siren.</summary>
		bool hasSiren() {}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its siren turned on.</summary>
		bool isSirenActive() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_SIREN_ON,
				getId()
			) == TRUE;
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its siren turned on.</summary>
		void setSirenActive(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_SIREN,
				getId(),
				state
			) ;
		}

		///<summary>Sets a value indicating whether the siren on this <see cref="Vehicle"/> plays sounds.</summary>
		void setSirenSilent(bool state) {
			Call(
				SE::VEHICLE::DISABLE_VEHICLE_IMPACT_EXPLOSION_ACTIVATION,
				getId(),
				state
			);
		}

		///<summary>Sounds the horn on this <see cref="Vehicle"/>.</summary>
		void soundHorn(int duration) {
			Call(
				SE::VEHICLE::START_VEHICLE_HORN,
				getId(),
				duration,
				0,//<<< generate hash
				0
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its lights on.</summary>
		bool areLightsOn() {
			BOOL lightState1, lightState2;
			Call(
				SE::VEHICLE::GET_VEHICLE_LIGHTS_STATE,
				getId(),
				&lightState1, &lightState2
			);
			return lightState1 == TRUE;
		}

		///<summary>Sets or sets a value indicating whether this <see cref="Vehicle"/> has its lights on.</summary>
		void setLightsOn(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_LIGHTS,
				getId(),
				state ? 3 : 4
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its lights on.</summary>
		bool areHighBeamsOn() {
			BOOL lightState1, lightState2;
			Call(
				SE::VEHICLE::GET_VEHICLE_LIGHTS_STATE,
				getId(),
				&lightState1, &lightState2
			);
			return lightState2 == TRUE;
		}

		///<summary>Sets or sets a value indicating whether this <see cref="Vehicle"/> has its lights on.</summary>
		void setHighBeamsOn(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_FULLBEAM,
				getId(),
				state
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its interior lights on.</summary>
		bool areLightsOnInInterior() { return false; }

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its interior lights on.</summary>
		void setLightsOnInInterior(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_INTERIORLIGHT,
				getId(),
				state
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its search light on.</summary>
		bool isSearchLightOn() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_SEARCHLIGHT_ON,
				getId()
			) == TRUE;
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its search light on.</summary>
		void setSearchLightOn(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_SEARCHLIGHT,
				getId(),
				state,
				FALSE
			);
		}

		///<summary>Gets a value indicating whether this <see cref="Vehicle"/> has its taxi light on.</summary>
		bool isTaxiLightOn() {
			return Call(
				SE::VEHICLE::IS_TAXI_LIGHT_ON,
				getId()
			) == TRUE;
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its taxi light on.</summary>
		void setTaxiLightOn(bool state) {
			Call(
				SE::VEHICLE::SET_TAXI_LIGHTS,
				getId(),
				state
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its indicators light on.</summary>
		void setIndicatorLightOn(bool indicator, bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_INDICATOR_LIGHTS,
				getId(),
				indicator, state
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its left indicator light on.</summary>
		void setLeftIndicatorLightOn(bool state) {
			setIndicatorLightOn(true, state);
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its right indicator light on.</summary>
		void setRightIndicatorLightOn(bool state) {
			setIndicatorLightOn(false, state);
		}

		///<summary>Sets a value indicating whether the Handbrake on this <see cref="Vehicle"/> is forced on.</summary>
		void setHandbrakeForcedOn(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_HANDBRAKE,
				getId(),
				state
			);
		}

		///<summary>Sets a value indicating whether this <see cref="Vehicle"/> has its brake light on.</summary>
		void setBrakeLightsOn(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_BRAKE_LIGHTS,
				getId(),
				state
			);
		}

		///<summary>Sets a value indicating whether the Handbrake on this <see cref="Vehicle"/> is forced on.</summary>
		void setCanBeVisiblyDamaged(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_CAN_BE_VISIBLY_DAMAGED,
				getId(),
				state
			);
		}

		///<summary></summary>
		bool isDamaged() {
			return Call(
				SE::VEHICLE::_IS_VEHICLE_DAMAGED,
				getId()
			) == TRUE;
		}

		///<summary></summary>
		bool isDriveable() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_DRIVEABLE,
				getId(),
				FALSE
			) == TRUE;
		}

		///<summary></summary>
		void setDriveable(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_UNDRIVEABLE,
				getId(),
				!state
			);
		}

		///<summary></summary>
		bool hasRoof() {
			return Call(
				SE::VEHICLE::DOES_VEHICLE_HAVE_ROOF,
				getId()
			) == TRUE;
		}

		///<summary></summary>
		bool isRearBumperBrokenOff() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_BUMPER_BROKEN_OFF,
				getId(),
				FALSE
			) == TRUE;
		}

		///<summary></summary>
		bool isFrontBumperBrokenOff() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_BUMPER_BROKEN_OFF,
				getId(),
				TRUE
			) == TRUE;
		}

		///<summary></summary>
		void setAxlesStrong(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_HAS_STRONG_AXLES,
				getId(),
				state
			);
		}

		///<summary></summary>
		void setCanEngineDegrade(bool state) {
			Call(
				SE::VEHICLE::SET_VEHICLE_ENGINE_CAN_DEGRADE,
				getId(),
				state
			);
		}

		///<summary></summary>
		LandingGearState getLandingGearState() {
			return (LandingGearState)Call(
				SE::VEHICLE::GET_LANDING_GEAR_STATE,
				getId()
			);
		}

		///<summary></summary>
		void setLandingGearState(LandingGearState value) {
			int state = 0;
			switch (value)
			{
			case LandingGearState::Deploying:
				state = 0;
				break;
			case LandingGearState::Retracting:
				state = 1;
				break;
			case LandingGearState::Deployed:
				state = 2;
				break;
			case LandingGearState::Retracted:
				state = 3;
				break;
			case LandingGearState::Broken:
				state = 4;
				break;
			default:
				return;
			}
			Call(
				SE::VEHICLE::SET_VEHICLE_HAS_STRONG_AXLES,
				getId(),
				state
			);
		}

		///<summary></summary>
		RoofState getRoofState() {
			return (RoofState)Call(
				SE::VEHICLE::GET_CONVERTIBLE_ROOF_STATE,
				getId()
			);
		}

		///<summary></summary>
		void setRoofState(RoofState state) {
			switch (state)
			{
			case RoofState::Closed:
				Call(
					SE::VEHICLE::RAISE_CONVERTIBLE_ROOF,
					getId(),
					TRUE
				);
				Call(
					SE::VEHICLE::RAISE_CONVERTIBLE_ROOF,
					getId(),
					FALSE
				);
				break;
			case RoofState::Closing:
				Call(
					SE::VEHICLE::RAISE_CONVERTIBLE_ROOF,
					getId(),
					FALSE
				);
				break;
			case RoofState::Opened:
				Call(
					SE::VEHICLE::LOWER_CONVERTIBLE_ROOF,
					getId(),
					TRUE
				);
				Call(
					SE::VEHICLE::LOWER_CONVERTIBLE_ROOF,
					getId(),
					FALSE
				);
				break;
			case RoofState::Opening:
				Call(
					SE::VEHICLE::LOWER_CONVERTIBLE_ROOF,
					getId(),
					FALSE
				);
				break;
			}
		}

		///<summary></summary>
		LockStatus getLockStatus() {
			return (LockStatus)Call(
				SE::VEHICLE::GET_VEHICLE_DOOR_LOCK_STATUS,
				getId()
			);
		}

		///<summary></summary>
		void setLockStatus(LockStatus status) {
			int id = getId();
			float fStatus = (float)status;
			Call(
				SE::VEHICLE::SET_VEHICLE_DOORS_LOCKED,
				&id,
				&fStatus
			);
		}

		///<summary></summary>
		float getMaxBraking() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_MAX_BRAKING,
				getId()
			);
		}
		///<summary></summary>
		float getMaxTraction() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_MAX_TRACTION,
				getId()
			);
		}

		///<summary></summary>
		bool isOnAllWheels() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_ON_ALL_WHEELS,
				getId()
			);
		}

		///<summary></summary>
		bool isStopped() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_STOPPED,
				getId()
			);
		}

		///<summary></summary>
		bool isStoppedAtTrafficLights() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_STOPPED_AT_TRAFFIC_LIGHTS,
				getId()
			);
		}

		///<summary></summary>
		bool isStolen() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_STOLEN,
				getId()
			);
		}

		///<summary></summary>
		void setStolen(bool state) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_IS_STOLEN,
				getId(),
				state
			);
		}

		///<summary></summary>
		bool isConvertible() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_A_CONVERTIBLE,
				getId(),
				FALSE
			);
		}

		///<summary></summary>
		void setBurnoutForced(bool state) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_BURNOUT,
				getId(),
				state
			);
		}

		///<summary></summary>
		bool isInBurnout() {
			return Call(
				SE::VEHICLE::IS_VEHICLE_IN_BURNOUT,
				getId()
			);
		}

		///<summary></summary>
		int getPassengerCapacity() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_MAX_NUMBER_OF_PASSENGERS,
				getId()
			);
		}

		///<summary></summary>
		int getPassengerCount() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_NUMBER_OF_PASSENGERS,
				getId()
			);
		}

		SDK::Ped* getPedOnSeat(Seat seat) { return nullptr; }

		///<summary></summary>
		bool isSeatFree(Seat seat) {
			return Call(
				SE::VEHICLE::IS_VEHICLE_SEAT_FREE,
				getId(),
				(int)seat
			);
		}

		///<summary></summary>
		float getDirtLevel() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_DIRT_LEVEL,
				getId()
			);
		}

		///<summary></summary>
		void setDirtLevel(float level) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_DIRT_LEVEL,
				getId(),
				level
			);
		}

		///<summary></summary>
		bool placeOnGround() {
			return Call(
				SE::VEHICLE::SET_VEHICLE_ON_GROUND_PROPERLY,
				getId()
			);
		}

		///<summary></summary>
		void repair() {
			return Call(
				SE::VEHICLE::SET_VEHICLE_FIXED,
				getId()
			);
		}

		///<summary></summary>
		void explode() {
			return Call(
				SE::VEHICLE::EXPLODE_VEHICLE,
				getId(),
				TRUE, FALSE
			);
		}

		///<summary></summary>
		bool getCanTiresBurst() {
			return Call(
				SE::VEHICLE::GET_VEHICLE_TYRES_CAN_BURST,
				getId()
			);
		}

		///<summary></summary>
		void setCanTiresBurst(bool state) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_TYRES_CAN_BURST,
				getId(),
				state
			);
		}

		///<summary></summary>
		void setCanWheelsBreak(bool state) {
			return Call(
				SE::VEHICLE::SET_VEHICLE_WHEELS_CAN_BREAK,
				getId(),
				state
			);
		}
	};


	class Helicopter : public Vehicle
	{
	public:
		Helicopter(SE::Vehicle id)
			: Vehicle(id)
		{};

		///<summary></summary>
		float getEngineHealth() override {
			return Call(
				SE::VEHICLE::_GET_HELI_ENGINE_HEALTH,
				getId()
			);
		}

		///<summary>Gets or sets the blades speed for this heli.</summary>
		float getBladesSpeed() {}
	};


	class Train : public Vehicle
	{
	public:
		///<summary>Sets this <see cref="Train"/>s forward speed.</summary>
		void setForwardSpeed(float speed) override {
			Call(
				SE::VEHICLE::SET_TRAIN_SPEED,
				getId(),
				speed
			);

			Call(
				SE::VEHICLE::SET_TRAIN_CRUISE_SPEED,
				getId(),
				speed
			);
		}
	};
};