#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class STREAMING : public IGameNativeGroup<STREAMING>
	{
	public:
		static GameNative<void(), 0xBD6E84632DD4CB3F> LOAD_ALL_OBJECTS_NOW;
		static GameNative<void(float x, float y, float z), 0x4448EB75B4904BDB> LOAD_SCENE;
		static GameNative<Vector3* (), 0xC4582015556D1C46> NETWORK_UPDATE_LOAD_SCENE;
		static GameNative<void(), 0x64E630FAF5F60F44> NETWORK_STOP_LOAD_SCENE;
		static GameNative<BOOL(), 0x41CA5A33160EA4AB> IS_NETWORK_LOADING_SCENE;
		static GameNative<void(int interiorID, BOOL toggle), 0xE37B76C387BE28ED> SET_INTERIOR_ACTIVE;
		static GameNative<void(Hash model), 0x963D27A58DF860AC> REQUEST_MODEL;
		static GameNative<void(Player model), 0xA0261AEF7ACFC51E> REQUEST_MENU_PED_MODEL;
		static GameNative<BOOL(Hash model), 0x98A4EB5D89A0C952> HAS_MODEL_LOADED;
		static GameNative<void(int interiorID, const char* roomName), 0x8A7A40100EDFEC58> _REQUEST_INTERIOR_ROOM_BY_NAME;
		static GameNative<void(Hash model), 0xE532F5D78798DAAB> SET_MODEL_AS_NO_LONGER_NEEDED;
		static GameNative<BOOL(Hash model), 0x35B9E0803292B641> IS_MODEL_IN_CDIMAGE;
		static GameNative<BOOL(Hash model), 0xC0296A2EDF545E92> IS_MODEL_VALID;
		static GameNative<BOOL(Hash model), 0x19AAC8F07BFEC53E> IS_MODEL_A_VEHICLE;
		static GameNative<void(float x, float y, float z), 0x07503F7948F491A7> REQUEST_COLLISION_AT_COORD;
		static GameNative<void(Hash model), 0x923CB32A3B874FCB> REQUEST_COLLISION_FOR_MODEL;
		static GameNative<BOOL(Hash model), 0x22CCA434E368F03A> HAS_COLLISION_FOR_MODEL_LOADED;
		static GameNative<void(float x, float y, float z), 0xC9156DC11411A9EA> REQUEST_ADDITIONAL_COLLISION_AT_COORD;
		static GameNative<BOOL(const char* animDict), 0x2DA49C3B79856961> DOES_ANIM_DICT_EXIST;
		static GameNative<void(const char* animDict), 0xD3BD40951412FEF6> REQUEST_ANIM_DICT;
		static GameNative<BOOL(const char* animDict), 0xD031A9162D01088C> HAS_ANIM_DICT_LOADED;
		static GameNative<void(const char* animDict), 0xF66A602F829E2A06> REMOVE_ANIM_DICT;
		static GameNative<void(const char* animSet), 0x6EA47DAE7FAD0EED> REQUEST_ANIM_SET;
		static GameNative<BOOL(const char* animSet), 0xC4EA073D86FB29B0> HAS_ANIM_SET_LOADED;
		static GameNative<void(const char* animSet), 0x16350528F93024B3> REMOVE_ANIM_SET;
		static GameNative<void(const char* clipSet), 0xD2A71E1A77418A49> REQUEST_CLIP_SET;
		static GameNative<BOOL(const char* clipSet), 0x318234F4F3738AF3> HAS_CLIP_SET_LOADED;
		static GameNative<void(const char* clipSet), 0x01F73A131C18CD94> REMOVE_CLIP_SET;
		static GameNative<void(const char* iplName), 0x41B4893843BBDB74> REQUEST_IPL;
		static GameNative<void(const char* iplName), 0xEE6C5AD3ECE0A82D> REMOVE_IPL;
		static GameNative<BOOL(const char* iplName), 0x88A741E44A2B3495> IS_IPL_ACTIVE;
		static GameNative<void(BOOL toggle), 0x6E0C692677008888> SET_STREAMING;
		static GameNative<void(BOOL toggle), 0x717CD6E6FAEBBEDC> SET_GAME_PAUSES_FOR_STREAMING;
		static GameNative<void(BOOL toggle), 0x77B5F9A36BF96710> SET_REDUCE_PED_MODEL_BUDGET;
		static GameNative<void(BOOL toggle), 0x80C527893080CCF3> SET_REDUCE_VEHICLE_MODEL_BUDGET;
		static GameNative<void(BOOL toggle), 0x42CBE54462D92634> SET_DITCH_POLICE_MODELS;
		static GameNative<int(), 0x4060057271CEBC89> GET_NUMBER_OF_STREAMING_REQUESTS;
		static GameNative<void(), 0x944955FB2A3935C8> REQUEST_PTFX_ASSET;
		static GameNative<BOOL(), 0xCA7D9B86ECA7481B> HAS_PTFX_ASSET_LOADED;
		static GameNative<void(), 0x88C6814073DD4A73> REMOVE_PTFX_ASSET;
		static GameNative<void(const char* assetName), 0xB80D8756B4668AB6> REQUEST_NAMED_PTFX_ASSET;
		static GameNative<BOOL(const char* assetName), 0x8702416E512EC454> HAS_NAMED_PTFX_ASSET_LOADED;
		static GameNative<void(const char* assetName), 0x5F61EBBE1A00F96D> _REMOVE_NAMED_PTFX_ASSET;
		static GameNative<void(int budget), 0xCB9E1EB3BE2AF4E9> SET_VEHICLE_POPULATION_BUDGET;
		static GameNative<void(int budget), 0x8C95333CFC3340F3> SET_PED_POPULATION_BUDGET;
		static GameNative<void(), 0x31B73D1EA9F01DA2> CLEAR_FOCUS;
		static GameNative<void(float x, float y, float z, float offsetX, float offsetY, float offsetZ), 0xBB7454BAFF08FE25> _SET_FOCUS_AREA;
		static GameNative<void(Entity entity), 0x198F77705FA0931D> SET_FOCUS_ENTITY;
		static GameNative<BOOL(Entity entity), 0x2DDFF3FB9075D747> IS_ENTITY_FOCUS;
		static GameNative<void(Entity p0), 0x0811381EF5062FEC> _0x0811381EF5062FEC;
		static GameNative<void(const char* p0, BOOL p1), 0xAF12610C644A35C9> _0xAF12610C644A35C9;
		static GameNative<void(Any p0), 0x4E52E752C76E7E7A> _0x4E52E752C76E7E7A;
		static GameNative<Any(float x, float y, float z, float rad, Any p4, Any p5), 0x219C7B8D53E429FD> FORMAT_FOCUS_HEADING;
		static GameNative<Any(float p0, float p1, float p2, float p3, float p4, float p5, float p6, Any p7, Any p8), 0x1F3F018BC3AFA77C> _0x1F3F018BC3AFA77C;
		static GameNative<Any(float p0, float p1, float p2, float p3, float p4, float p5, Any p6), 0x0AD9710CEE2F590F> _0x0AD9710CEE2F590F;
		static GameNative<void(Any p0), 0x1EE7D8DF4425F053> _0x1EE7D8DF4425F053;
		static GameNative<Any(Any p0), 0x7D41E9D2D17C5B2D> _0x7D41E9D2D17C5B2D;
		static GameNative<Any(Any p0), 0x07C313F94746702C> _0x07C313F94746702C;
		static GameNative<Any(), 0xBC9823AB80A3DCAC> _0xBC9823AB80A3DCAC;
		static GameNative<BOOL(float p0, float p1, float p2, float p3, float p4, float p5, float p6, Any p7), 0x212A8D0D2BABFAC2> NEW_LOAD_SCENE_START;
		static GameNative<BOOL(float x, float y, float z, float radius, Any p4), 0xACCFB4ACF53551B0> NEW_LOAD_SCENE_START_SPHERE;
		static GameNative<void(), 0xC197616D221FF4A4> NEW_LOAD_SCENE_STOP;
		static GameNative<BOOL(), 0xA41A05B6CB741B85> IS_NEW_LOAD_SCENE_ACTIVE;
		static GameNative<BOOL(), 0x01B8247A7A8B9AD1> IS_NEW_LOAD_SCENE_LOADED;
		static GameNative<BOOL(), 0x71E7B2E657449AAD> _0x71E7B2E657449AAD;
		static GameNative<void(Ped from, Ped to, int flags, int switchType), 0xFAA23F2CBA159D67> START_PLAYER_SWITCH;
		static GameNative<void(), 0x95C0A5BBDC189AA1> STOP_PLAYER_SWITCH;
		static GameNative<BOOL(), 0xD9D2CFFF49FAB35F> IS_PLAYER_SWITCH_IN_PROGRESS;
		static GameNative<int(), 0xB3C94A90D9FC9E62> GET_PLAYER_SWITCH_TYPE;
		static GameNative<int(float x1, float y1, float z1, float x2, float y2, float z2), 0xB5D7B26B45720E05> GET_IDEAL_PLAYER_SWITCH_TYPE;
		static GameNative<int(), 0x470555300D10B2A5> GET_PLAYER_SWITCH_STATE;
		static GameNative<int(), 0x20F898A5D9782800> GET_PLAYER_SHORT_SWITCH_STATE;
		static GameNative<void(Any* p0), 0x5F2013F8BC24EE69> _0x5F2013F8BC24EE69;
		static GameNative<int(), 0x78C0D93253149435> _0x78C0D93253149435;
		static GameNative<void(float camCoordX, float camCoordY, float camCoordZ, float camRotX, float camRotY, float camRotZ, float camFOV, float camFarClip, int p8), 0xC208B673CE446B61> SET_PLAYER_SWITCH_OUTRO;
		static GameNative<void(const char* p0), 0x0FDE9DBFC0A6BC65> _0x0FDE9DBFC0A6BC65;
		static GameNative<void(), 0x43D1680C6D19A8E9> _0x43D1680C6D19A8E9;
		static GameNative<void(), 0x74DE2E8739086740> _0x74DE2E8739086740;
		static GameNative<void(), 0x8E2A065ABDAE6994> _0x8E2A065ABDAE6994;
		static GameNative<void(), 0xAD5FDF34B81BFE79> _0xAD5FDF34B81BFE79;
		static GameNative<Any(), 0xDFA80CB25D0A19B3> _0xDFA80CB25D0A19B3;
		static GameNative<void(), 0xD4793DFF3AF2ABCD> _0xD4793DFF3AF2ABCD;
		static GameNative<void(), 0xBD605B8E0E18B3BB> _0xBD605B8E0E18B3BB;
		static GameNative<void(Ped ped, int flags, int switchType), 0xAAB3200ED59016BC> _SWITCH_OUT_PLAYER;
		static GameNative<void(Ped ped), 0xD8295AF639FD9CB8> _SWITCH_IN_PLAYER;
		static GameNative<BOOL(), 0x933BBEEB8C61B5F4> _0x933BBEEB8C61B5F4;
		static GameNative<int(), 0x08C2D6C52A3104BB> SET_PLAYER_INVERTED_UP;
		static GameNative<Any(), 0x5B48A06DD0E792A5> _0x5B48A06DD0E792A5;
		static GameNative<Any(), 0x5B74EA8CFD5E3E7E> DESTROY_PLAYER_IN_PAUSE_MENU;
		static GameNative<void(), 0x1E9057A74FD73E23> _0x1E9057A74FD73E23;
		static GameNative<Any(), 0x0C15B0E443B2349D> _0x0C15B0E443B2349D;
		static GameNative<void(float p0), 0xA76359FC80B2438E> _0xA76359FC80B2438E;
		static GameNative<void(float p0, float p1, float p2, float p3), 0xBED8CA5FF5E04113> _0xBED8CA5FF5E04113;
		static GameNative<void(), 0x472397322E92A856> _0x472397322E92A856;
		static GameNative<void(BOOL p0), 0x40AEFD1A244741F2> _0x40AEFD1A244741F2;
		static GameNative<void(), 0x03F1A106BDA7DD3E> _0x03F1A106BDA7DD3E;
		static GameNative<void(Any* p0, Any* p1), 0x95A7DABDDBB78AE7> _0x95A7DABDDBB78AE7;
		static GameNative<void(), 0x63EB2B972A218CAC> _0x63EB2B972A218CAC;
		static GameNative<Any(), 0xFB199266061F820A> _0xFB199266061F820A;
		static GameNative<void(), 0xF4A0DADB70F57FA6> _0xF4A0DADB70F57FA6;
		static GameNative<Any(), 0x5068F488DDB54DD8> _0x5068F488DDB54DD8;
		static GameNative<void(const char* srl), 0x3D245789CE12982C> PREFETCH_SRL;
		static GameNative<BOOL(), 0xD0263801A4C5B0BB> IS_SRL_LOADED;
		static GameNative<void(), 0x9BADDC94EF83B823> BEGIN_SRL;
		static GameNative<void(), 0x0A41540E63C9EE17> END_SRL;
		static GameNative<void(float p0), 0xA74A541C6884E7B8> SET_SRL_TIME;
		static GameNative<void(Any p0, Any p1, Any p2, Any p3, Any p4, Any p5), 0xEF39EE20C537E98C> _0xEF39EE20C537E98C;
		static GameNative<void(Any p0, Any p1, Any p2, Any p3), 0xBEB2D9A1D9A8F55A> _0xBEB2D9A1D9A8F55A;
		static GameNative<void(BOOL p0), 0x20C6C7E4EB082A7F> _0x20C6C7E4EB082A7F;
		static GameNative<void(Any p0), 0xF8155A7F03DDFC8E> _0xF8155A7F03DDFC8E;
		static GameNative<void(float x, float y, float z, float radius), 0xB85F26619073E775> SET_HD_AREA;
		static GameNative<void(), 0xCE58B1CFB9290813> CLEAR_HD_AREA;
		static GameNative<void(), 0xB5A4DB34FE89B88A> _LOAD_MISSION_CREATOR_DATA;
		static GameNative<void(), 0xCCE26000E9A6FAD7> SHUTDOWN_CREATOR_BUDGET;
		static GameNative<BOOL(Hash modelHash), 0x0BC3144DEB678666> _0x0BC3144DEB678666;
		static GameNative<void(Any p0), 0xF086AD9354FAC3A3> _0xF086AD9354FAC3A3;
		static GameNative<Any(), 0x3D3D8B3BE5A83D35> _0x3D3D8B3BE5A83D35;
	};
};