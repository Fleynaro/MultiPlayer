#pragma once



#include "../IGameNativeGroup.h"


namespace SE {
	class ROPE : public IGameNativeGroup<ROPE>
	{
	public:
		static GameNative<Object(float x, float y, float z, float rotX, float rotY, float rotZ, float length, int ropeType, float maxLength, float minLength, float p10, BOOL p11, BOOL p12, BOOL rigid, float p14, BOOL breakWhenShot, Any* unkPtr), 0xE832D760399EB220> ADD_ROPE;
		static GameNative<void(Object* rope), 0x52B4829281364649> DELETE_ROPE;
		static GameNative<void(Object rope), 0xAA5D6B1888E4DB20> DELETE_CHILD_ROPE;
		static GameNative<BOOL(Object* rope), 0xFD5448BE3111ED96> DOES_ROPE_EXIST;
		static GameNative<void(Object* rope, BOOL toggle), 0xF159A63806BB5BA8> ROPE_DRAW_SHADOW_ENABLED;
		static GameNative<void(Object rope, char* rope_preset), 0xCBB203C04D1ABD27> LOAD_ROPE_DATA;
		static GameNative<void(Object rope, int vertex, float x, float y, float z), 0x2B320CF14146B69A> PIN_ROPE_VERTEX;
		static GameNative<void(Object rope, int vertex), 0x4B5AE2EEE4A8F180> UNPIN_ROPE_VERTEX;
		static GameNative<int(Object rope), 0x3655F544CD30F0B5> GET_ROPE_VERTEX_COUNT;
		static GameNative<void(Object rope, Entity ent1, Entity ent2, float ent1_x, float ent1_y, float ent1_z, float ent2_x, float ent2_y, float ent2_z, float length, BOOL p10, BOOL p11, char* boneName1, char* boneName2), 0x3D95EC8B6D940AC3> ATTACH_ENTITIES_TO_ROPE;
		static GameNative<void(Object rope, Entity entity, float x, float y, float z, BOOL p5), 0x4B490A6832559A65> ATTACH_ROPE_TO_ENTITY;
		static GameNative<void(Object rope, Entity entity), 0xBCF3026912A8647D> DETACH_ROPE_FROM_ENTITY;
		static GameNative<void(Object rope), 0xC8D667EE52114ABA> ROPE_SET_UPDATE_PINVERTS;
		static GameNative<void(Object rope, int value), 0xDC57A637A20006ED> _HIDE_ROPE;
		static GameNative<void(Object rope, BOOL p1), 0x36CCB9BE67B970FD> _0x36CCB9BE67B970FD;
		static GameNative<BOOL(Object rope), 0x84DE3B5FB3E666F0> _0x84DE3B5FB3E666F0;
		static GameNative<Vector3(Object rope), 0x21BB0FBD3E217C2D> GET_ROPE_LAST_VERTEX_COORD;
		static GameNative<Vector3(Object rope, int vertex), 0xEA61CA8E80F09E4D> GET_ROPE_VERTEX_COORD;
		static GameNative<void(Object rope), 0x1461C72C889E343E> START_ROPE_WINDING;
		static GameNative<void(Object rope), 0xCB2D4AB84A19AA7C> STOP_ROPE_WINDING;
		static GameNative<void(Object rope), 0x538D1179EC1AA9A9> START_ROPE_UNWINDING_FRONT;
		static GameNative<void(Object rope), 0xFFF3A50779EFBBB3> STOP_ROPE_UNWINDING_FRONT;
		static GameNative<void(Object rope), 0x5389D48EFA2F079A> ROPE_CONVERT_TO_SIMPLE;
		static GameNative<void(), 0x9B9039DBF2D258C1> ROPE_LOAD_TEXTURES;
		static GameNative<BOOL(), 0xF2D0E6A75CC05597> ROPE_ARE_TEXTURES_LOADED;
		static GameNative<void(), 0x6CE36C35C1AC8163> ROPE_UNLOAD_TEXTURES;
		static GameNative<BOOL(Object rope), 0x271C9D3ACA5D6409> _0x271C9D3ACA5D6409;
		static GameNative<void(Object rope, int unk, float x1, float y1, float z1, float x2, float y2, float z2, float x3, float y3, float z3, float x4, float y4, float z4), 0xBC0CE682D4D05650> _0xBC0CE682D4D05650;
		static GameNative<void(Any p0, BOOL p1, BOOL p2), 0xB1B6216CA2E7B55E> _0xB1B6216CA2E7B55E;
		static GameNative<void(Any p0, Any p1), 0xB743F735C03D7810> _0xB743F735C03D7810;
		static GameNative<float(Object rope), 0x73040398DFF9A4A6> _GET_ROPE_LENGTH;
		static GameNative<void(Object rope, float length), 0xD009F759A723DB1B> ROPE_FORCE_LENGTH;
		static GameNative<void(Object rope, float length), 0xC16DE94D9BEA14A0> ROPE_RESET_LENGTH;
		static GameNative<void(float posX, float posY, float posZ, float vecX, float vecY, float vecZ, float impulse), 0xE37F721824571784> APPLY_IMPULSE_TO_CLOTH;
		static GameNative<void(Object ropeorobject, int vertex, float value), 0xEEA3B200A6FEB65B> SET_DAMPING;
		static GameNative<void(Entity entity), 0x710311ADF0E20730> ACTIVATE_PHYSICS;
		static GameNative<void(Object rope, float x, float y, float z), 0xD8FA3908D7B86904> SET_CGOFFSET;
		static GameNative<Vector3(Object rope), 0x8214A4B5A7A33612> GET_CGOFFSET;
		static GameNative<void(Object rope), 0xBE520D9761FF811F> SET_CG_AT_BOUNDCENTER;
		static GameNative<void(Object object, float posX, float posY, float posZ, float p4, float offsetX, float offsetY, float offsetZ, float p8, int p9, BOOL p10), 0x2E648D16F6E308F3> BREAK_ENTITY_GLASS;
		static GameNative<void(Object rope, BOOL enabled), 0x5CEC1A84620E7D5B> SET_DISABLE_BREAKING;
		static GameNative<void(Object object), 0xCC6E963682533882> _0xCC6E963682533882;
		static GameNative<void(Object object, BOOL toggle), 0x01BA3AED21C16CFB> SET_DISABLE_FRAG_DAMAGE;
	};
};