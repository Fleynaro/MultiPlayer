#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class AUDIO : public IGameNativeGroup<AUDIO>
	{
	public:
		static GameNative<void(const char* ringtoneName, Ped ped, BOOL p2), 0xF9E56683CA8E11A5> PLAY_PED_RINGTONE;
		static GameNative<BOOL(Ped ped), 0x1E8E5E20937E3137> IS_PED_RINGTONE_PLAYING;
		static GameNative<void(Ped ped), 0x6C5AE23EFA885092> STOP_PED_RINGTONE;
		static GameNative<BOOL(), 0x7497D2CE2C30D24C> IS_MOBILE_PHONE_CALL_ONGOING;
		static GameNative<BOOL(), 0xC8B1B2425604CDD0> _0xC8B1B2425604CDD0;
		static GameNative<void(), 0xD2C91A0B572AAE56> CREATE_NEW_SCRIPTED_CONVERSATION;
		static GameNative<void(int p0, const char* p1, const char* p2, int p3, int p4, BOOL p5, BOOL p6, BOOL p7, BOOL p8, int p9, BOOL p10, BOOL p11, BOOL p12), 0xC5EF963405593646> ADD_LINE_TO_CONVERSATION;
		static GameNative<void(int pedIndex, Ped ped, const char* name), 0x95D9F4BC443956E7> ADD_PED_TO_CONVERSATION;
		static GameNative<void(Any p0, float p1, float p2, float p3), 0x33E3C6C6F2F0B506> _0x33E3C6C6F2F0B506;
		static GameNative<void(Any p0, Any p1), 0x892B6AB8F33606F5> _0x892B6AB8F33606F5;
		static GameNative<void(BOOL p0, float x1, float y1, float z1, float x2, float y2, float z2, float x3, float y3, float z3), 0xB6AE90EDDE95C762> SET_MICROPHONE_POSITION;
		static GameNative<void(BOOL p0), 0x0B568201DD99F0EB> _0x0B568201DD99F0EB;
		static GameNative<void(BOOL p0), 0x61631F5DF50D1C34> _0x61631F5DF50D1C34;
		static GameNative<void(BOOL p0, BOOL p1), 0x252E5F915EABB675> START_SCRIPT_PHONE_CONVERSATION;
		static GameNative<void(BOOL p0, BOOL p1), 0x6004BCB0E226AAEA> PRELOAD_SCRIPT_PHONE_CONVERSATION;
		static GameNative<void(BOOL p0, BOOL p1, BOOL p2, BOOL p3), 0x6B17C62C9635D2DC> START_SCRIPT_CONVERSATION;
		static GameNative<void(BOOL p0, BOOL p1, BOOL p2, BOOL p3), 0x3B3CAD6166916D87> PRELOAD_SCRIPT_CONVERSATION;
		static GameNative<void(), 0x23641AFE870AF385> START_PRELOADED_CONVERSATION;
		static GameNative<BOOL(), 0xE73364DB90778FFA> _0xE73364DB90778FFA;
		static GameNative<BOOL(), 0x16754C556D2EDE3D> IS_SCRIPTED_CONVERSATION_ONGOING;
		static GameNative<BOOL(), 0xDF0D54BE7A776737> IS_SCRIPTED_CONVERSATION_LOADED;
		static GameNative<Any(), 0x480357EE890C295A> GET_CURRENT_SCRIPTED_CONVERSATION_LINE;
		static GameNative<void(BOOL p0), 0x8530AD776CD72B12> PAUSE_SCRIPTED_CONVERSATION;
		static GameNative<void(), 0x9AEB285D1818C9AC> RESTART_SCRIPTED_CONVERSATION;
		static GameNative<Any(BOOL p0), 0xD79DEEFB53455EBA> STOP_SCRIPTED_CONVERSATION;
		static GameNative<void(), 0x9663FE6B7A61EB00> SKIP_TO_NEXT_SCRIPTED_CONVERSATION_LINE;
		static GameNative<void(Any p0, Any* p1, Any* p2), 0xA018A12E5C5C2FA6> INTERRUPT_CONVERSATION;
		static GameNative<void(Ped p0, const char* p1, const char* p2), 0x8A694D7A68F8DC38> _0x8A694D7A68F8DC38;
		static GameNative<Any(Any* p0), 0xAA19F5572C38B564> _0xAA19F5572C38B564;
		static GameNative<void(BOOL p0), 0xB542DE8C3D1CB210> _0xB542DE8C3D1CB210;
		static GameNative<void(int p0), 0xC6ED9D5092438D91> REGISTER_SCRIPT_WITH_AUDIO;
		static GameNative<void(), 0xA8638BE228D4751A> UNREGISTER_SCRIPT_WITH_AUDIO;
		static GameNative<BOOL(const char* p0, BOOL p1), 0x7345BDD95E62E0F2> REQUEST_MISSION_AUDIO_BANK;
		static GameNative<BOOL(const char* p0, BOOL p1), 0xFE02FFBED8CA9D99> REQUEST_AMBIENT_AUDIO_BANK;
		static GameNative<BOOL(const char* p0, BOOL p1), 0x2F844A8B08D76685> REQUEST_SCRIPT_AUDIO_BANK;
		static GameNative<Any(Any p0, Any p1), 0x8F8C0E370AE62F5C> HINT_AMBIENT_AUDIO_BANK;
		static GameNative<Any(Any p0, Any p1), 0xFB380A29641EC31A> HINT_SCRIPT_AUDIO_BANK;
		static GameNative<void(), 0x0EC92A1BF0857187> RELEASE_MISSION_AUDIO_BANK;
		static GameNative<void(), 0x65475A218FFAA93D> RELEASE_AMBIENT_AUDIO_BANK;
		static GameNative<void(const char* audioBank), 0x77ED170667F50170> RELEASE_NAMED_SCRIPT_AUDIO_BANK;
		static GameNative<void(), 0x7A2D8AD0A9EB9C3F> RELEASE_SCRIPT_AUDIO_BANK;
		static GameNative<void(), 0x19AF7ED9B9D23058> _0x19AF7ED9B9D23058;
		static GameNative<void(), 0x9AC92EED5E4793AB> _0x9AC92EED5E4793AB;
		static GameNative<int(), 0x430386FE9BF80B45> GET_SOUND_ID;
		static GameNative<void(int soundId), 0x353FC880830B88FA> RELEASE_SOUND_ID;
		static GameNative<void(Player soundId, const char* audioName, const char* audioRef, BOOL p3, Any p4, BOOL p5), 0x7FF4944CC209192D> PLAY_SOUND;
		static GameNative<void(int soundId, const char* audioName, const char* audioRef, BOOL p3), 0x67C540AA08E4A6F5> PLAY_SOUND_FRONTEND;
		static GameNative<void(const char* p0, const char* soundset), 0xCADA5A0D0702381E> _0xCADA5A0D0702381E;
		static GameNative<void(int soundId, const char* audioName, Entity entity, const char* audioRef, BOOL p4, Any p5), 0xE65F427EB70AB1ED> PLAY_SOUND_FROM_ENTITY;
		static GameNative<void(int soundId, const char* audioName, float x, float y, float z, const char* audioRef, BOOL p6, int range, BOOL p8), 0x8D8686B622B88120> PLAY_SOUND_FROM_COORD;
		static GameNative<void(int soundId), 0xA3B0C41BA5CC0BB5> STOP_SOUND;
		static GameNative<int(int soundId), 0x2DE3F0A134FFBC0D> GET_NETWORK_ID_FROM_SOUND_ID;
		static GameNative<int(int netId), 0x75262FD12D0A1C84> GET_SOUND_ID_FROM_NETWORK_ID;
		static GameNative<void(int soundId, const char* variableName, float value), 0xAD6B3148A78AE9B6> SET_VARIABLE_ON_SOUND;
		static GameNative<void(const char* p0, float p1), 0x2F9D3834AEB9EF79> SET_VARIABLE_ON_STREAM;
		static GameNative<void(Any* p0, BOOL p1), 0xF2A9CDABCEA04BD6> OVERRIDE_UNDERWATER_STREAM;
		static GameNative<void(const char* name, float p1), 0x733ADF241531E5C2> _0x733ADF241531E5C2;
		static GameNative<BOOL(int soundId), 0xFCBDCE714A7C88E5> HAS_SOUND_FINISHED;
		static GameNative<void(Ped ped, const char* speechName, const char* speechParam), 0x8E04FEDD28D42462> _PLAY_AMBIENT_SPEECH1;
		static GameNative<void(Ped ped, const char* speechName, const char* speechParam), 0xC6941B4A3A8FBBB9> _PLAY_AMBIENT_SPEECH2;
		static GameNative<void(Ped p0, const char* speechName, const char* voiceName, const char* speechParam, BOOL p4), 0x3523634255FC3318> _PLAY_AMBIENT_SPEECH_WITH_VOICE;
		static GameNative<void(const char* speechName, const char* voiceName, float x, float y, float z, const char* speechParam), 0xED640017ED337E45> _PLAY_AMBIENT_SPEECH_AT_COORDS;
		static GameNative<void(const char* p0), 0x13AD665062541A7E> OVERRIDE_TREVOR_RAGE;
		static GameNative<void(), 0xE78503B10C4314E0> RESET_TREVOR_RAGE;
		static GameNative<void(Ped playerPed, BOOL value), 0xEA241BB04110F091> SET_PLAYER_ANGRY;
		static GameNative<void(Ped ped, int painID, float p1), 0xBC9AE166038A5CEC> PLAY_PAIN;
		static GameNative<void(const char* p0), 0xD01005D2BA2EB778> _0xD01005D2BA2EB778;
		static GameNative<void(const char* p0), 0xDDC635D5B3262C56> _0xDDC635D5B3262C56;
		static GameNative<void(Ped ped, const char* name), 0x6C8065A3B780185B> SET_AMBIENT_VOICE_NAME;
		static GameNative<void(Ped ped), 0x40CF0D12D142A9E8> _RESET_AMBIENT_VOICE;
		static GameNative<void(Ped playerPed, Hash p1), 0x7CDC8C3B89F661B3> _0x7CDC8C3B89F661B3;
		static GameNative<void(Any p0, BOOL p1), 0xA5342D390CDA41D6> _0xA5342D390CDA41D6;
		static GameNative<void(Ped ped), 0x7A73D05A607734C7> _SET_PED_MUTE;
		static GameNative<void(Ped ped), 0xB8BEC0CA6F0EDB0F> STOP_CURRENT_PLAYING_AMBIENT_SPEECH;
		static GameNative<BOOL(Ped p0), 0x9072C8B49907BFAD> IS_AMBIENT_SPEECH_PLAYING;
		static GameNative<BOOL(Any p0), 0xCC9AA18DCC7084F4> IS_SCRIPTED_SPEECH_PLAYING;
		static GameNative<BOOL(Ped ped), 0x729072355FA39EC9> IS_ANY_SPEECH_PLAYING;
		static GameNative<BOOL(Ped ped, const char* speechName, BOOL unk), 0x49B99BF3FDA89A7A> _CAN_PED_SPEAK;
		static GameNative<BOOL(Ped ped), 0x049E937F18F4020C> IS_PED_IN_CURRENT_CONVERSATION;
		static GameNative<void(Ped ped, BOOL toggle), 0x95D2D383D5396B8A> SET_PED_IS_DRUNK;
		static GameNative<void(Entity entity, int unk, const char* speech), 0xEE066C7006C49C0A> _0xEE066C7006C49C0A;
		static GameNative<BOOL(Any p0), 0xC265DF9FB44A9FBD> _0xC265DF9FB44A9FBD;
		static GameNative<void(Ped animal, int mood), 0xCC97B29285B1DC3B> SET_ANIMAL_MOOD;
		static GameNative<BOOL(), 0xB35CE999E8EF317E> IS_MOBILE_PHONE_RADIO_ACTIVE;
		static GameNative<void(BOOL state), 0xBF286C554784F3DF> SET_MOBILE_PHONE_RADIO_STATE;
		static GameNative<int(), 0xE8AF77C4C06ADC93> GET_PLAYER_RADIO_STATION_INDEX;
		static GameNative<const char* (), 0xF6D733C32076AD03> GET_PLAYER_RADIO_STATION_NAME;
		static GameNative<const char* (int radioStation), 0xB28ECA15046CA8B9> GET_RADIO_STATION_NAME;
		static GameNative<Any(), 0xA571991A7FE6CCEB> GET_PLAYER_RADIO_STATION_GENRE;
		static GameNative<BOOL(), 0xA151A7394A214E65> IS_RADIO_RETUNING;
		static GameNative<BOOL(), 0x0626A247D2405330> _0x0626A247D2405330;
		static GameNative<void(), 0xFF266D1D0EB1195D> _0xFF266D1D0EB1195D;
		static GameNative<void(), 0xDD6BCF9E94425DF9> _0xDD6BCF9E94425DF9;
		static GameNative<void(const char* stationName), 0xC69EDA28699D5107> SET_RADIO_TO_STATION_NAME;
		static GameNative<void(Vehicle vehicle, const char* radioStation), 0x1B9C0099CB942AC6> SET_VEH_RADIO_STATION;
		static GameNative<void(Vehicle vehicle), 0xC1805D05E6D4FE10> _SET_VEHICLE_AS_AMBIENT_EMMITTER;
		static GameNative<void(const char* emitterName, const char* radioStation), 0xACF57305B12AF907> SET_EMITTER_RADIO_STATION;
		static GameNative<void(const char* emitterName, BOOL toggle), 0x399D2D3B33F1B8EB> SET_STATIC_EMITTER_ENABLED;
		static GameNative<void(int radioStation), 0xA619B168B8A8570F> SET_RADIO_TO_STATION_INDEX;
		static GameNative<void(BOOL active), 0xF7F26C6E9CC9EBB8> SET_FRONTEND_RADIO_ACTIVE;
		static GameNative<void(int newsStory), 0xB165AB7C248B2DC1> UNLOCK_MISSION_NEWS_STORY;
		static GameNative<int(Any p0), 0x66E49BF55B4B1874> GET_NUMBER_OF_PASSENGER_VOICE_VARIATIONS;
		static GameNative<int(), 0x50B196FC9ED6545B> GET_AUDIBLE_MUSIC_TRACK_TEXT_ID;
		static GameNative<void(BOOL play), 0xCD536C4D33DCC900> PLAY_END_CREDITS_MUSIC;
		static GameNative<void(), 0x6DDBBDD98E2E9C25> SKIP_RADIO_FORWARD;
		static GameNative<void(const char* radioStation), 0x344F393B027E38C3> FREEZE_RADIO_STATION;
		static GameNative<void(const char* radioStation), 0xFC00454CF60B91DD> UNFREEZE_RADIO_STATION;
		static GameNative<void(BOOL toggle), 0xC1AA9F53CE982990> SET_RADIO_AUTO_UNFREEZE;
		static GameNative<void(const char* radioStation), 0x88795F13FACDA88D> SET_INITIAL_PLAYER_STATION;
		static GameNative<void(BOOL toggle), 0x19F21E63AE6EAE4E> SET_USER_RADIO_CONTROL_ENABLED;
		static GameNative<void(const char* radioStation, const char* radioTrack), 0xB39786F201FEE30B> SET_RADIO_TRACK;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0xBB6F1CAEC68B0BCE> SET_VEHICLE_RADIO_LOUD;
		static GameNative<BOOL(Vehicle vehicle), 0x032A116663A4D5AC> _IS_VEHICLE_RADIO_LOUD;
		static GameNative<void(BOOL Toggle), 0x1098355A16064BB3> SET_MOBILE_RADIO_ENABLED_DURING_GAMEPLAY;
		static GameNative<BOOL(), 0x109697E2FFBAC8A1> _0x109697E2FFBAC8A1;
		static GameNative<BOOL(), 0x5F43D83FD6738741> _IS_PLAYER_VEHICLE_RADIO_ENABLED;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0x3B988190C0AA6C0B> SET_VEHICLE_RADIO_ENABLED;
		static GameNative<void(const char* radioStation, const char* p1, BOOL p2), 0x4E404A9361F75BB2> _0x4E404A9361F75BB2;
		static GameNative<void(const char* radioStation), 0x1654F24A88A8E3FE> _0x1654F24A88A8E3FE;
		static GameNative<int(), 0xF1620ECB50E01DE7> _MAX_RADIO_STATION_INDEX;
		static GameNative<int(int station), 0x8D67489793FF428B> FIND_RADIO_STATION_INDEX;
		static GameNative<void(const char* radioStation, BOOL p1), 0x774BD811F656A122> _0x774BD811F656A122;
		static GameNative<void(float p0), 0x2C96CDB04FCA358E> _0x2C96CDB04FCA358E;
		static GameNative<void(const char* radioStation, const char* p1), 0x031ACB6ABA18C729> _0x031ACB6ABA18C729;
		static GameNative<void(Any p0, BOOL p1), 0xF3365489E0DD50F9> _0xF3365489E0DD50F9;
		static GameNative<void(Any* p0, BOOL p1, BOOL p2), 0xBDA07E5950085E46> SET_AMBIENT_ZONE_STATE;
		static GameNative<void(const char* zoneName, BOOL p1), 0x218DD44AAAC964FF> CLEAR_AMBIENT_ZONE_STATE;
		static GameNative<void(const char* p0, BOOL p1, BOOL p2), 0x9748FA4DE50CCE3E> SET_AMBIENT_ZONE_LIST_STATE;
		static GameNative<void(Any* p0, BOOL p1), 0x120C48C614909FA4> CLEAR_AMBIENT_ZONE_LIST_STATE;
		static GameNative<void(const char* ambientZone, BOOL p1, BOOL p2), 0x1D6650420CEC9D3B> SET_AMBIENT_ZONE_STATE_PERSISTENT;
		static GameNative<void(const char* ambientZone, BOOL p1, BOOL p2), 0xF3638DAE8C4045E1> SET_AMBIENT_ZONE_LIST_STATE_PERSISTENT;
		static GameNative<BOOL(const char* ambientZone), 0x01E2817A479A7F9B> IS_AMBIENT_ZONE_ENABLED;
		static GameNative<void(const char* p0), 0x3B4BF5F0859204D9> SET_CUTSCENE_AUDIO_OVERRIDE;
		static GameNative<void(const char* p0, float p1), 0xBCC29F935ED07688> GET_PLAYER_HEADSET_SOUND_ALTERNATE;
		static GameNative<Any(const char* name, float p1), 0xDFEBD56D9BD1EB16> PLAY_POLICE_REPORT;
		static GameNative<void(), 0xB4F90FAF7670B16F> _DISABLE_POLICE_REPORTS;
		static GameNative<void(Vehicle vehicle), 0x1B9025BDA76822B6> BLIP_SIREN;
		static GameNative<void(Vehicle vehicle, BOOL mute, int p2), 0x3CDC1E622CCE0356> OVERRIDE_VEH_HORN;
		static GameNative<BOOL(Vehicle vehicle), 0x9D6BFC12B05C6121> IS_HORN_ACTIVE;
		static GameNative<void(BOOL toggle), 0x395BF71085D1B1D9> SET_AGGRESSIVE_HORNS;
		static GameNative<void(BOOL p0), 0x02E93C796ABD3A97> _0x02E93C796ABD3A97;
		static GameNative<void(BOOL p0, BOOL p1), 0x58BB377BEC7CD5F4> _0x58BB377BEC7CD5F4;
		static GameNative<BOOL(), 0xD11FA52EB849D978> IS_STREAM_PLAYING;
		static GameNative<int(), 0x4E72BBDBCA58A3DB> GET_STREAM_PLAY_TIME;
		static GameNative<BOOL(const char* streamName, const char* soundSet), 0x1F1F957154EC51DF> LOAD_STREAM;
		static GameNative<BOOL(const char* streamName, int startOffset, const char* soundSet), 0x59C16B79F53B3712> LOAD_STREAM_WITH_START_OFFSET;
		static GameNative<void(Ped ped), 0x89049DD63C08B5D1> PLAY_STREAM_FROM_PED;
		static GameNative<void(Vehicle vehicle), 0xB70374A758007DFA> PLAY_STREAM_FROM_VEHICLE;
		static GameNative<void(Object object), 0xEBAA9B64D76356FD> PLAY_STREAM_FROM_OBJECT;
		static GameNative<void(), 0x58FCE43488F9F5F4> PLAY_STREAM_FRONTEND;
		static GameNative<void(float x, float y, float z), 0x21442F412E8DE56B> SPECIAL_FRONTEND_EQUAL;
		static GameNative<void(), 0xA4718A1419D18151> STOP_STREAM;
		static GameNative<void(Ped ped, BOOL speaking), 0x9D64D7405520E3D3> STOP_PED_SPEAKING;
		static GameNative<void(Ped ped, BOOL toggle), 0xA9A41C1E940FB0E8> DISABLE_PED_PAIN_AUDIO;
		static GameNative<BOOL(Ped ped), 0x932C2D096A2C3FFF> IS_AMBIENT_SPEECH_DISABLED;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0x1FEF0683B96EBCF2> SET_SIREN_WITH_NO_DRIVER;
		static GameNative<void(Vehicle vehicle), 0x9C11908013EA4715> _SOUND_VEHICLE_HORN_THIS_FRAME;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0x76D683C108594D0E> SET_HORN_ENABLED;
		static GameNative<void(Vehicle vehicle, Any p1), 0xE5564483E407F914> SET_AUDIO_VEHICLE_PRIORITY;
		static GameNative<void(Any p0, float p1), 0x9D3AF56E94C9AE98> _0x9D3AF56E94C9AE98;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0xFA932DE350266EF8> USE_SIREN_AS_HORN;
		static GameNative<void(Vehicle vehicle, const char* audioName), 0x4F0C413926060B38> _FORCE_VEHICLE_ENGINE_AUDIO;
		static GameNative<void(Any p0, const char* p1, const char* p2), 0xF1F8157B8C3F171C> _0xF1F8157B8C3F171C;
		static GameNative<void(Any p0), 0xD2DCCD8E16E20997> _0xD2DCCD8E16E20997;
		static GameNative<BOOL(Vehicle vehicle), 0x5DB8010EE71FDEF2> _0x5DB8010EE71FDEF2;
		static GameNative<void(Any p0, float p1), 0x59E7B488451F4D3A> _0x59E7B488451F4D3A;
		static GameNative<void(Any p0, float p1), 0x01BB4D577D38BD9E> _0x01BB4D577D38BD9E;
		static GameNative<void(Any p0, BOOL p1), 0x1C073274E065C6D2> _0x1C073274E065C6D2;
		static GameNative<void(Any p0, BOOL p1), 0x2BE4BC731D039D5A> _0x2BE4BC731D039D5A;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0x4A04DE7CAB2739A1> SET_VEHICLE_BOOST_ACTIVE;
		static GameNative<void(Any p0, BOOL p1), 0x6FDDAD856E36988A> _0x6FDDAD856E36988A;
		static GameNative<void(Any p0, BOOL p1), 0x06C0023BED16DD6B> _0x06C0023BED16DD6B;
		static GameNative<void(Vehicle vehicle, int p1), 0x3A539D52857EA82D> PLAY_VEHICLE_DOOR_OPEN_SOUND;
		static GameNative<void(Vehicle vehicle, int p1), 0x62A456AA4769EF34> PLAY_VEHICLE_DOOR_CLOSE_SOUND;
		static GameNative<void(Vehicle vehicle, BOOL toggle), 0xC15907D667F7CFB2> _0xC15907D667F7CFB2;
		static GameNative<BOOL(), 0x6D28DC1671E334FD> IS_GAME_IN_CONTROL_OF_MUSIC;
		static GameNative<void(BOOL active), 0x3BD3F52BA9B1E4E8> SET_GPS_ACTIVE;
		static GameNative<void(const char* audioName), 0xB138AAB8A70D3C69> PLAY_MISSION_COMPLETE_AUDIO;
		static GameNative<BOOL(), 0x19A30C23F5827F8A> IS_MISSION_COMPLETE_PLAYING;
		static GameNative<BOOL(), 0x6F259F82D873B8B8> _0x6F259F82D873B8B8;
		static GameNative<void(BOOL p0), 0xF154B8D1775B2DEC> _0xF154B8D1775B2DEC;
		static GameNative<BOOL(const char* scene), 0x013A80FC08F6E4F2> START_AUDIO_SCENE;
		static GameNative<void(const char* scene), 0xDFE8422B3B94E688> STOP_AUDIO_SCENE;
		static GameNative<void(), 0xBAC7FC81A75EC1A1> STOP_AUDIO_SCENES;
		static GameNative<BOOL(const char* scene), 0xB65B60556E2A9225> IS_AUDIO_SCENE_ACTIVE;
		static GameNative<void(const char* scene, const char* variable, float value), 0xEF21A9EF089A2668> SET_AUDIO_SCENE_VARIABLE;
		static GameNative<void(Any p0), 0xA5F377B175A699C5> _0xA5F377B175A699C5;
		static GameNative<void(Entity p0, const char* p1, float p2), 0x153973AB99FE8980> _DYNAMIC_MIXER_RELATED_FN;
		static GameNative<void(Any p0, float p1), 0x18EB48CFC41F2EA0> _0x18EB48CFC41F2EA0;
		static GameNative<BOOL(), 0x845FFC3A4FEEFA3E> AUDIO_IS_SCRIPTED_MUSIC_PLAYING;
		static GameNative<BOOL(const char* eventName), 0x1E5185B72EF5158A> PREPARE_MUSIC_EVENT;
		static GameNative<BOOL(const char* eventName), 0x5B17A90291133DA5> CANCEL_MUSIC_EVENT;
		static GameNative<BOOL(const char* eventName), 0x706D57B0F50DA710> TRIGGER_MUSIC_EVENT;
		static GameNative<Any(), 0xA097AB275061FB21> _0xA097AB275061FB21;
		static GameNative<Any(), 0xE7A0D23DC414507B> GET_MUSIC_PLAYTIME;
		static GameNative<void(Any p0, Any p1, Any p2, Any p3), 0xFBE20329593DEC9D> _0xFBE20329593DEC9D;
		static GameNative<void(), 0xB32209EFFDC04913> CLEAR_ALL_BROKEN_GLASS;
		static GameNative<void(BOOL p0, Any p1), 0x70B8EC8FC108A634> _0x70B8EC8FC108A634;
		static GameNative<void(float p0, float p1), 0x149AEE66F0CB3A99> _0x149AEE66F0CB3A99;
		static GameNative<void(float p0, float p1), 0x8BF907833BE275DE> _0x8BF907833BE275DE;
		static GameNative<void(), 0x062D5EAD4DA2FA6A> _0x062D5EAD4DA2FA6A;
		static GameNative<BOOL(const char* alarmName), 0x9D74AE343DB65533> PREPARE_ALARM;
		static GameNative<void(const char* alarmName, BOOL p2), 0x0355EF116C4C97B2> START_ALARM;
		static GameNative<void(const char* alarmName, BOOL toggle), 0xA1CADDCD98415A41> STOP_ALARM;
		static GameNative<void(BOOL stop), 0x2F794A877ADD4C92> STOP_ALL_ALARMS;
		static GameNative<BOOL(const char* alarmName), 0x226435CB96CCFC8C> IS_ALARM_PLAYING;
		static GameNative<Hash(Vehicle vehicle), 0x02165D55000219AC> GET_VEHICLE_DEFAULT_HORN;
		static GameNative<Hash(Vehicle vehicle), 0xACB5DCCA1EC76840> _GET_VEHICLE_HORN_HASH;
		static GameNative<void(Ped ped), 0xF54BB7B61036F335> RESET_PED_AUDIO_FLAGS;
		static GameNative<void(Any p0, BOOL p1), 0xD2CC78CD3D0B50F9> _0xD2CC78CD3D0B50F9;
		static GameNative<void(Any p0, BOOL p1, Any p2), 0xBF4DC1784BE94DFA> _0xBF4DC1784BE94DFA;
		static GameNative<void(Any p0, BOOL p1), 0x75773E11BA459E90> _0x75773E11BA459E90;
		static GameNative<void(), 0xD57AAAE0E2214D11> _0xD57AAAE0E2214D11;
		static GameNative<void(BOOL value), 0x552369F549563AD5> _FORCE_AMBIENT_SIREN;
		static GameNative<void(Vehicle vehicle, BOOL p1), 0x43FA0DFC5DF87815> _0x43FA0DFC5DF87815;
		static GameNative<void(const char* flagName, BOOL toggle), 0xB9EFD5C25018725A> SET_AUDIO_FLAG;
		static GameNative<Any(const char* audioName, BOOL unk), 0xC7ABCACA4985A766> PREPARE_SYNCHRONIZED_AUDIO_EVENT;
		static GameNative<BOOL(int SceneID, const char* audioName), 0x029FE7CD1B7E2E75> PREPARE_SYNCHRONIZED_AUDIO_EVENT_FOR_SCENE;
		static GameNative<BOOL(int SceneID), 0x8B2FD4560E55DD2D> PLAY_SYNCHRONIZED_AUDIO_EVENT;
		static GameNative<BOOL(int SceneID), 0x92D6A88E64A94430> STOP_SYNCHRONIZED_AUDIO_EVENT;
		static GameNative<void(Any* p0, float p1, float p2, float p3), 0xC8EDE9BDBCCBA6D4> _0xC8EDE9BDBCCBA6D4;
		static GameNative<void(const char* p0, Entity p1), 0x950A154B8DAB6185> _SET_SYNCHRONIZED_AUDIO_EVENT_POSITION_THIS_FRAME;
		static GameNative<void(int p0), 0x12561FCBB62D5B9C> _0x12561FCBB62D5B9C;
		static GameNative<void(const char* p0, const char* p1), 0x044DBAD7A7FA2BE5> _0x044DBAD7A7FA2BE5;
		static GameNative<void(const char* p0), 0xB4BBFD9CD8B3922B> _0xB4BBFD9CD8B3922B;
		static GameNative<void(), 0xE4E6DD5566D28C82> _0xE4E6DD5566D28C82;
		static GameNative<BOOL(), 0x3A48AB4445D499BE> _0x3A48AB4445D499BE;
		static GameNative<void(Ped ped), 0x4ADA3F19BE4A6047> _SET_PED_TALK;
		static GameNative<void(), 0x0150B6FF25A9E2E5> _0x0150B6FF25A9E2E5;
		static GameNative<void(BOOL p0), 0xBEF34B1D9624D5DD> _0xBEF34B1D9624D5DD;
		static GameNative<void(), 0x806058BBDC136E06> _0x806058BBDC136E06;
		static GameNative<BOOL(), 0x544810ED9DB6BBE6> _0x544810ED9DB6BBE6;
		static GameNative<BOOL(), 0x5B50ABB1FE3746F4> _0x5B50ABB1FE3746F4;
		
		//radio names
		inline static const char* radioNames[] =
		{
			"RADIO_01_CLASS_ROCK",
			"RADIO_02_POP",
			"RADIO_03_HIPHOP_NEW",
			"RADIO_04_PUNK",
			"RADIO_05_TALK_01",
			"RADIO_06_COUNTRY",
			"RADIO_07_DANCE_01",
			"RADIO_08_MEXICAN",
			"RADIO_09_HIPHOP_OLD",
			"RADIO_11_TALK_02",
			"RADIO_12_REGGAE",
			"RADIO_13_JAZZ",
			"RADIO_14_DANCE_02",
			"RADIO_15_MOTOWN",
			"RADIO_16_SILVERLAKE",
			"RADIO_17_FUNK",
			"RADIO_18_90S_ROCK",
			"RADIO_19_USER",
			"RADIO_20_THELAB",
			"RADIO_21_DLC_XM17",
			"RADIO_22_DLC_BATTLE_MIX1_RADIO",
			"RADIO_OFF"
		};
	};
};