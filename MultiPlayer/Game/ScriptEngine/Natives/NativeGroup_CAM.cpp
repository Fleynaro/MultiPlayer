#include "NativeGroup_CAM.h"



//Native init
#define NATIVE(name) GAME_NATIVE_INIT(CAM, ##name)

using namespace SE;

//Natives
NATIVE(RENDER_SCRIPT_CAMS)
NATIVE(_RENDER_FIRST_PERSON_CAM)
NATIVE(CREATE_CAM)
NATIVE(CREATE_CAM_WITH_PARAMS)
NATIVE(CREATE_CAMERA)
NATIVE(CREATE_CAMERA_WITH_PARAMS)
NATIVE(DESTROY_CAM)
NATIVE(DESTROY_ALL_CAMS)
NATIVE(DOES_CAM_EXIST)
NATIVE(SET_CAM_ACTIVE)
NATIVE(IS_CAM_ACTIVE)
NATIVE(IS_CAM_RENDERING)
NATIVE(GET_RENDERING_CAM)
NATIVE(GET_CAM_COORD)
NATIVE(GET_CAM_ROT)
NATIVE(GET_CAM_FOV)
NATIVE(GET_CAM_NEAR_CLIP)
NATIVE(GET_CAM_FAR_CLIP)
NATIVE(GET_CAM_FAR_DOF)
NATIVE(SET_CAM_PARAMS)
NATIVE(SET_CAM_COORD)
NATIVE(SET_CAM_ROT)
NATIVE(SET_CAM_FOV)
NATIVE(SET_CAM_NEAR_CLIP)
NATIVE(SET_CAM_FAR_CLIP)
NATIVE(SET_CAM_MOTION_BLUR_STRENGTH)
NATIVE(SET_CAM_NEAR_DOF)
NATIVE(SET_CAM_FAR_DOF)
NATIVE(SET_CAM_DOF_STRENGTH)
NATIVE(SET_CAM_DOF_PLANES)
NATIVE(SET_CAM_USE_SHALLOW_DOF_MODE)
NATIVE(SET_USE_HI_DOF)
NATIVE(_0xF55E4046F6F831DC)
NATIVE(_0xE111A7C0D200CBC5)
NATIVE(_SET_CAM_DOF_FNUMBER_OF_LENS)
NATIVE(_SET_CAM_DOF_FOCUS_DISTANCE_BIAS)
NATIVE(_SET_CAM_DOF_MAX_NEAR_IN_FOCUS_DISTANCE)
NATIVE(_SET_CAM_DOF_MAX_NEAR_IN_FOCUS_DISTANCE_BLEND_LEVEL)
NATIVE(ATTACH_CAM_TO_ENTITY)
NATIVE(ATTACH_CAM_TO_PED_BONE)
NATIVE(DETACH_CAM)
NATIVE(SET_CAM_INHERIT_ROLL_VEHICLE)
NATIVE(POINT_CAM_AT_COORD)
NATIVE(POINT_CAM_AT_ENTITY)
NATIVE(POINT_CAM_AT_PED_BONE)
NATIVE(STOP_CAM_POINTING)
NATIVE(SET_CAM_AFFECTS_AIMING)
NATIVE(_0x661B5C8654ADD825)
NATIVE(_0xA2767257A320FC82)
NATIVE(_0x271017B9BA825366)
NATIVE(SET_CAM_DEBUG_NAME)
NATIVE(ADD_CAM_SPLINE_NODE)
NATIVE(_0x0A9F2A468B328E74)
NATIVE(_0x0FB82563989CF4FB)
NATIVE(_0x609278246A29CA34)
NATIVE(SET_CAM_SPLINE_PHASE)
NATIVE(GET_CAM_SPLINE_PHASE)
NATIVE(GET_CAM_SPLINE_NODE_PHASE)
NATIVE(SET_CAM_SPLINE_DURATION)
NATIVE(_0xD1B0F412F109EA5D)
NATIVE(GET_CAM_SPLINE_NODE_INDEX)
NATIVE(_0x83B8201ED82A9A2D)
NATIVE(_0xA6385DEB180F319F)
NATIVE(OVERRIDE_CAM_SPLINE_VELOCITY)
NATIVE(OVERRIDE_CAM_SPLINE_MOTION_BLUR)
NATIVE(_0x7BF1A54AE67AC070)
NATIVE(IS_CAM_SPLINE_PAUSED)
NATIVE(SET_CAM_ACTIVE_WITH_INTERP)
NATIVE(IS_CAM_INTERPOLATING)
NATIVE(SHAKE_CAM)
NATIVE(ANIMATED_SHAKE_CAM)
NATIVE(IS_CAM_SHAKING)
NATIVE(SET_CAM_SHAKE_AMPLITUDE)
NATIVE(STOP_CAM_SHAKING)
NATIVE(_0xF4C8CF9E353AFECA)
NATIVE(_0xC2EAE3FB8CDBED31)
NATIVE(IS_SCRIPT_GLOBAL_SHAKING)
NATIVE(STOP_SCRIPT_GLOBAL_SHAKING)
NATIVE(PLAY_CAM_ANIM)
NATIVE(IS_CAM_PLAYING_ANIM)
NATIVE(SET_CAM_ANIM_CURRENT_PHASE)
NATIVE(GET_CAM_ANIM_CURRENT_PHASE)
NATIVE(PLAY_SYNCHRONIZED_CAM_ANIM)
NATIVE(_0x503F5920162365B2)
NATIVE(_SET_CAMERA_RANGE)
NATIVE(_0xC91C6C55199308CA)
NATIVE(_0xC8B5C4A79CC18B94)
NATIVE(_0x5C48A1D6E3B33179)
NATIVE(IS_SCREEN_FADED_OUT)
NATIVE(IS_SCREEN_FADED_IN)
NATIVE(IS_SCREEN_FADING_OUT)
NATIVE(IS_SCREEN_FADING_IN)
NATIVE(DO_SCREEN_FADE_IN)
NATIVE(DO_SCREEN_FADE_OUT)
NATIVE(SET_WIDESCREEN_BORDERS)
NATIVE(GET_GAMEPLAY_CAM_COORD)
NATIVE(GET_GAMEPLAY_CAM_ROT)
NATIVE(GET_GAMEPLAY_CAM_FOV)
NATIVE(CUSTOM_MENU_COORDINATES)
NATIVE(_0x0225778816FDC28C)
NATIVE(GET_GAMEPLAY_CAM_RELATIVE_HEADING)
NATIVE(SET_GAMEPLAY_CAM_RELATIVE_HEADING)
NATIVE(GET_GAMEPLAY_CAM_RELATIVE_PITCH)
NATIVE(SET_GAMEPLAY_CAM_RELATIVE_PITCH)
NATIVE(_SET_GAMEPLAY_CAM_RAW_YAW)
NATIVE(_SET_GAMEPLAY_CAM_RAW_PITCH)
NATIVE(_0x469F2ECDEC046337)
NATIVE(SHAKE_GAMEPLAY_CAM)
NATIVE(IS_GAMEPLAY_CAM_SHAKING)
NATIVE(SET_GAMEPLAY_CAM_SHAKE_AMPLITUDE)
NATIVE(STOP_GAMEPLAY_CAM_SHAKING)
NATIVE(_0x8BBACBF51DA047A8)
NATIVE(IS_GAMEPLAY_CAM_RENDERING)
NATIVE(_0x3044240D2E0FA842)
NATIVE(_0x705A276EBFF3133D)
NATIVE(_0xDB90C6CCA48940F1)
NATIVE(_ENABLE_CROSSHAIR_THIS_FRAME)
NATIVE(IS_GAMEPLAY_CAM_LOOKING_BEHIND)
NATIVE(_0x2AED6301F67007D5)
NATIVE(_0x49482F9FCD825AAA)
NATIVE(_0xFD3151CD37EA2245)
NATIVE(_0xDD79DF9F4D26E1C9)
NATIVE(IS_SPHERE_VISIBLE)
NATIVE(IS_FOLLOW_PED_CAM_ACTIVE)
NATIVE(SET_FOLLOW_PED_CAM_CUTSCENE_CHAT)
NATIVE(_0x271401846BD26E92)
NATIVE(_0xC8391C309684595A)
NATIVE(_CLAMP_GAMEPLAY_CAM_YAW)
NATIVE(_CLAMP_GAMEPLAY_CAM_PITCH)
NATIVE(_ANIMATE_GAMEPLAY_CAM_ZOOM)
NATIVE(_0xE9EA16D6E54CDCA4)
NATIVE(_DISABLE_FIRST_PERSON_CAM_THIS_FRAME)
NATIVE(_0x59424BD75174C9B1)
NATIVE(GET_FOLLOW_PED_CAM_ZOOM_LEVEL)
NATIVE(GET_FOLLOW_PED_CAM_VIEW_MODE)
NATIVE(SET_FOLLOW_PED_CAM_VIEW_MODE)
NATIVE(IS_FOLLOW_VEHICLE_CAM_ACTIVE)
NATIVE(_0x91EF6EE6419E5B97)
NATIVE(SET_TIME_IDLE_DROP)
NATIVE(GET_FOLLOW_VEHICLE_CAM_ZOOM_LEVEL)
NATIVE(SET_FOLLOW_VEHICLE_CAM_ZOOM_LEVEL)
NATIVE(GET_FOLLOW_VEHICLE_CAM_VIEW_MODE)
NATIVE(SET_FOLLOW_VEHICLE_CAM_VIEW_MODE)
NATIVE(_0xEE778F8C7E1142E2)
NATIVE(_0x2A2173E46DAECD12)
NATIVE(_0x19CAFA3C87F7C2FF)
NATIVE(IS_AIM_CAM_ACTIVE)
NATIVE(_0x74BD83EA840F6BC9)
NATIVE(IS_FIRST_PERSON_AIM_CAM_ACTIVE)
NATIVE(DISABLE_AIM_CAM_THIS_UPDATE)
NATIVE(_GET_GAMEPLAY_CAM_ZOOM)
NATIVE(_0x70894BD0915C5BCA)
NATIVE(_0xCED08CBE8EBB97C7)
NATIVE(_0x2F7F2B26DD3F18EE)
NATIVE(_SET_FIRST_PERSON_CAM_PITCH_RANGE)
NATIVE(_SET_FIRST_PERSON_CAM_NEAR_CLIP)
NATIVE(_SET_THIRD_PERSON_AIM_CAM_NEAR_CLIP)
NATIVE(_0x4008EDF7D6E48175)
NATIVE(_GET_GAMEPLAY_CAM_COORDS)
NATIVE(_GET_GAMEPLAY_CAM_ROT)
NATIVE(_0x26903D9CD1175F2C)
NATIVE(_0x80EC114669DAEFF4)
NATIVE(_0x5F35F6732C3FBBA0)
NATIVE(_0xD0082607100D7193)
NATIVE(_GET_GAMEPLAY_CAM_FAR_CLIP)
NATIVE(_GET_GAMEPLAY_CAM_NEAR_DOF)
NATIVE(_GET_GAMEPLAY_CAM_FAR_DOF)
NATIVE(_0x162F9D995753DC19)
NATIVE(SET_GAMEPLAY_COORD_HINT)
NATIVE(SET_GAMEPLAY_PED_HINT)
NATIVE(SET_GAMEPLAY_VEHICLE_HINT)
NATIVE(SET_GAMEPLAY_OBJECT_HINT)
NATIVE(SET_GAMEPLAY_ENTITY_HINT)
NATIVE(IS_GAMEPLAY_HINT_ACTIVE)
NATIVE(STOP_GAMEPLAY_HINT)
NATIVE(_0xCCD078C2665D2973)
NATIVE(_0x247ACBC4ABBC9D1C)
NATIVE(_0xBF72910D0F26F025)
NATIVE(SET_GAMEPLAY_HINT_FOV)
NATIVE(_0xF8BDBF3D573049A1)
NATIVE(_0xD1F8363DFAD03848)
NATIVE(_0x5D7B620DAE436138)
NATIVE(_0xC92717EF615B6704)
NATIVE(GET_IS_MULTIPLAYER_BRIEF)
NATIVE(SET_CINEMATIC_BUTTON_ACTIVE)
NATIVE(IS_CINEMATIC_CAM_RENDERING)
NATIVE(SHAKE_CINEMATIC_CAM)
NATIVE(IS_CINEMATIC_CAM_SHAKING)
NATIVE(SET_CINEMATIC_CAM_SHAKE_AMPLITUDE)
NATIVE(STOP_CINEMATIC_CAM_SHAKING)
NATIVE(_DISABLE_VEHICLE_FIRST_PERSON_CAM_THIS_FRAME)
NATIVE(_0x62ECFCFDEE7885D6)
NATIVE(_0x9E4CFFF989258472)
NATIVE(_F4F2C0D4EE209E20)
NATIVE(_0xCA9D2AA3E326D720)
NATIVE(_IS_IN_VEHICLE_CAM_DISABLED)
NATIVE(CREATE_CINEMATIC_SHOT)
NATIVE(IS_CINEMATIC_SHOT_ACTIVE)
NATIVE(STOP_CINEMATIC_SHOT)
NATIVE(_0xA41BCD7213805AAC)
NATIVE(_0xDC9DA9E8789F5246)
NATIVE(SET_CINEMATIC_MODE_ACTIVE)
NATIVE(_0x1F2300CB7FA7B7F6)
NATIVE(_0x17FCA7199A530203)
NATIVE(STOP_CUTSCENE_CAM_SHAKING)
NATIVE(_0x12DED8CA53D47EA5)
NATIVE(_0x89215EC747DF244A)
NATIVE(_0x5A43C76F7FC7BA5F)
NATIVE(_SET_CAM_EFFECT)
NATIVE(_0x5C41E6BABC9E2112)
NATIVE(_0x21E253A7F8DA5DFB)
NATIVE(_0x11FA5D3479C7DD47)
NATIVE(_0xEAF0FA793D05C592)
NATIVE(_GET_REPLAY_FREE_CAM_MAX_RANGE)

//Native list
STATIC_FIELD_INIT(IGameNativeGroup<CAM>::m_natives)
{
	&CAM::RENDER_SCRIPT_CAMS,
	&CAM::_RENDER_FIRST_PERSON_CAM,
	&CAM::CREATE_CAM,
	&CAM::CREATE_CAM_WITH_PARAMS,
	&CAM::CREATE_CAMERA,
	&CAM::CREATE_CAMERA_WITH_PARAMS,
	&CAM::DESTROY_CAM,
	&CAM::DESTROY_ALL_CAMS,
	&CAM::DOES_CAM_EXIST,
	&CAM::SET_CAM_ACTIVE,
	&CAM::IS_CAM_ACTIVE,
	&CAM::IS_CAM_RENDERING,
	&CAM::GET_RENDERING_CAM,
	&CAM::GET_CAM_COORD,
	&CAM::GET_CAM_ROT,
	&CAM::GET_CAM_FOV,
	&CAM::GET_CAM_NEAR_CLIP,
	&CAM::GET_CAM_FAR_CLIP,
	&CAM::GET_CAM_FAR_DOF,
	&CAM::SET_CAM_PARAMS,
	&CAM::SET_CAM_COORD,
	&CAM::SET_CAM_ROT,
	&CAM::SET_CAM_FOV,
	&CAM::SET_CAM_NEAR_CLIP,
	&CAM::SET_CAM_FAR_CLIP,
	&CAM::SET_CAM_MOTION_BLUR_STRENGTH,
	&CAM::SET_CAM_NEAR_DOF,
	&CAM::SET_CAM_FAR_DOF,
	&CAM::SET_CAM_DOF_STRENGTH,
	&CAM::SET_CAM_DOF_PLANES,
	&CAM::SET_CAM_USE_SHALLOW_DOF_MODE,
	&CAM::SET_USE_HI_DOF,
	&CAM::_0xF55E4046F6F831DC,
	&CAM::_0xE111A7C0D200CBC5,
	&CAM::_SET_CAM_DOF_FNUMBER_OF_LENS,
	&CAM::_SET_CAM_DOF_FOCUS_DISTANCE_BIAS,
	&CAM::_SET_CAM_DOF_MAX_NEAR_IN_FOCUS_DISTANCE,
	&CAM::_SET_CAM_DOF_MAX_NEAR_IN_FOCUS_DISTANCE_BLEND_LEVEL,
	&CAM::ATTACH_CAM_TO_ENTITY,
	&CAM::ATTACH_CAM_TO_PED_BONE,
	&CAM::DETACH_CAM,
	&CAM::SET_CAM_INHERIT_ROLL_VEHICLE,
	&CAM::POINT_CAM_AT_COORD,
	&CAM::POINT_CAM_AT_ENTITY,
	&CAM::POINT_CAM_AT_PED_BONE,
	&CAM::STOP_CAM_POINTING,
	&CAM::SET_CAM_AFFECTS_AIMING,
	&CAM::_0x661B5C8654ADD825,
	&CAM::_0xA2767257A320FC82,
	&CAM::_0x271017B9BA825366,
	&CAM::SET_CAM_DEBUG_NAME,
	&CAM::ADD_CAM_SPLINE_NODE,
	&CAM::_0x0A9F2A468B328E74,
	&CAM::_0x0FB82563989CF4FB,
	&CAM::_0x609278246A29CA34,
	&CAM::SET_CAM_SPLINE_PHASE,
	&CAM::GET_CAM_SPLINE_PHASE,
	&CAM::GET_CAM_SPLINE_NODE_PHASE,
	&CAM::SET_CAM_SPLINE_DURATION,
	&CAM::_0xD1B0F412F109EA5D,
	&CAM::GET_CAM_SPLINE_NODE_INDEX,
	&CAM::_0x83B8201ED82A9A2D,
	&CAM::_0xA6385DEB180F319F,
	&CAM::OVERRIDE_CAM_SPLINE_VELOCITY,
	&CAM::OVERRIDE_CAM_SPLINE_MOTION_BLUR,
	&CAM::_0x7BF1A54AE67AC070,
	&CAM::IS_CAM_SPLINE_PAUSED,
	&CAM::SET_CAM_ACTIVE_WITH_INTERP,
	&CAM::IS_CAM_INTERPOLATING,
	&CAM::SHAKE_CAM,
	&CAM::ANIMATED_SHAKE_CAM,
	&CAM::IS_CAM_SHAKING,
	&CAM::SET_CAM_SHAKE_AMPLITUDE,
	&CAM::STOP_CAM_SHAKING,
	&CAM::_0xF4C8CF9E353AFECA,
	&CAM::_0xC2EAE3FB8CDBED31,
	&CAM::IS_SCRIPT_GLOBAL_SHAKING,
	&CAM::STOP_SCRIPT_GLOBAL_SHAKING,
	&CAM::PLAY_CAM_ANIM,
	&CAM::IS_CAM_PLAYING_ANIM,
	&CAM::SET_CAM_ANIM_CURRENT_PHASE,
	&CAM::GET_CAM_ANIM_CURRENT_PHASE,
	&CAM::PLAY_SYNCHRONIZED_CAM_ANIM,
	&CAM::_0x503F5920162365B2,
	&CAM::_SET_CAMERA_RANGE,
	&CAM::_0xC91C6C55199308CA,
	&CAM::_0xC8B5C4A79CC18B94,
	&CAM::_0x5C48A1D6E3B33179,
	&CAM::IS_SCREEN_FADED_OUT,
	&CAM::IS_SCREEN_FADED_IN,
	&CAM::IS_SCREEN_FADING_OUT,
	&CAM::IS_SCREEN_FADING_IN,
	&CAM::DO_SCREEN_FADE_IN,
	&CAM::DO_SCREEN_FADE_OUT,
	&CAM::SET_WIDESCREEN_BORDERS,
	&CAM::GET_GAMEPLAY_CAM_COORD,
	&CAM::GET_GAMEPLAY_CAM_ROT,
	&CAM::GET_GAMEPLAY_CAM_FOV,
	&CAM::CUSTOM_MENU_COORDINATES,
	&CAM::_0x0225778816FDC28C,
	&CAM::GET_GAMEPLAY_CAM_RELATIVE_HEADING,
	&CAM::SET_GAMEPLAY_CAM_RELATIVE_HEADING,
	&CAM::GET_GAMEPLAY_CAM_RELATIVE_PITCH,
	&CAM::SET_GAMEPLAY_CAM_RELATIVE_PITCH,
	&CAM::_SET_GAMEPLAY_CAM_RAW_YAW,
	&CAM::_SET_GAMEPLAY_CAM_RAW_PITCH,
	&CAM::_0x469F2ECDEC046337,
	&CAM::SHAKE_GAMEPLAY_CAM,
	&CAM::IS_GAMEPLAY_CAM_SHAKING,
	&CAM::SET_GAMEPLAY_CAM_SHAKE_AMPLITUDE,
	&CAM::STOP_GAMEPLAY_CAM_SHAKING,
	&CAM::_0x8BBACBF51DA047A8,
	&CAM::IS_GAMEPLAY_CAM_RENDERING,
	&CAM::_0x3044240D2E0FA842,
	&CAM::_0x705A276EBFF3133D,
	&CAM::_0xDB90C6CCA48940F1,
	&CAM::_ENABLE_CROSSHAIR_THIS_FRAME,
	&CAM::IS_GAMEPLAY_CAM_LOOKING_BEHIND,
	&CAM::_0x2AED6301F67007D5,
	&CAM::_0x49482F9FCD825AAA,
	&CAM::_0xFD3151CD37EA2245,
	&CAM::_0xDD79DF9F4D26E1C9,
	&CAM::IS_SPHERE_VISIBLE,
	&CAM::IS_FOLLOW_PED_CAM_ACTIVE,
	&CAM::SET_FOLLOW_PED_CAM_CUTSCENE_CHAT,
	&CAM::_0x271401846BD26E92,
	&CAM::_0xC8391C309684595A,
	&CAM::_CLAMP_GAMEPLAY_CAM_YAW,
	&CAM::_CLAMP_GAMEPLAY_CAM_PITCH,
	&CAM::_ANIMATE_GAMEPLAY_CAM_ZOOM,
	&CAM::_0xE9EA16D6E54CDCA4,
	&CAM::_DISABLE_FIRST_PERSON_CAM_THIS_FRAME,
	&CAM::_0x59424BD75174C9B1,
	&CAM::GET_FOLLOW_PED_CAM_ZOOM_LEVEL,
	&CAM::GET_FOLLOW_PED_CAM_VIEW_MODE,
	&CAM::SET_FOLLOW_PED_CAM_VIEW_MODE,
	&CAM::IS_FOLLOW_VEHICLE_CAM_ACTIVE,
	&CAM::_0x91EF6EE6419E5B97,
	&CAM::SET_TIME_IDLE_DROP,
	&CAM::GET_FOLLOW_VEHICLE_CAM_ZOOM_LEVEL,
	&CAM::SET_FOLLOW_VEHICLE_CAM_ZOOM_LEVEL,
	&CAM::GET_FOLLOW_VEHICLE_CAM_VIEW_MODE,
	&CAM::SET_FOLLOW_VEHICLE_CAM_VIEW_MODE,
	&CAM::_0xEE778F8C7E1142E2,
	&CAM::_0x2A2173E46DAECD12,
	&CAM::_0x19CAFA3C87F7C2FF,
	&CAM::IS_AIM_CAM_ACTIVE,
	&CAM::_0x74BD83EA840F6BC9,
	&CAM::IS_FIRST_PERSON_AIM_CAM_ACTIVE,
	&CAM::DISABLE_AIM_CAM_THIS_UPDATE,
	&CAM::_GET_GAMEPLAY_CAM_ZOOM,
	&CAM::_0x70894BD0915C5BCA,
	&CAM::_0xCED08CBE8EBB97C7,
	&CAM::_0x2F7F2B26DD3F18EE,
	&CAM::_SET_FIRST_PERSON_CAM_PITCH_RANGE,
	&CAM::_SET_FIRST_PERSON_CAM_NEAR_CLIP,
	&CAM::_SET_THIRD_PERSON_AIM_CAM_NEAR_CLIP,
	&CAM::_0x4008EDF7D6E48175,
	&CAM::_GET_GAMEPLAY_CAM_COORDS,
	&CAM::_GET_GAMEPLAY_CAM_ROT,
	&CAM::_0x26903D9CD1175F2C,
	&CAM::_0x80EC114669DAEFF4,
	&CAM::_0x5F35F6732C3FBBA0,
	&CAM::_0xD0082607100D7193,
	&CAM::_GET_GAMEPLAY_CAM_FAR_CLIP,
	&CAM::_GET_GAMEPLAY_CAM_NEAR_DOF,
	&CAM::_GET_GAMEPLAY_CAM_FAR_DOF,
	&CAM::_0x162F9D995753DC19,
	&CAM::SET_GAMEPLAY_COORD_HINT,
	&CAM::SET_GAMEPLAY_PED_HINT,
	&CAM::SET_GAMEPLAY_VEHICLE_HINT,
	&CAM::SET_GAMEPLAY_OBJECT_HINT,
	&CAM::SET_GAMEPLAY_ENTITY_HINT,
	&CAM::IS_GAMEPLAY_HINT_ACTIVE,
	&CAM::STOP_GAMEPLAY_HINT,
	&CAM::_0xCCD078C2665D2973,
	&CAM::_0x247ACBC4ABBC9D1C,
	&CAM::_0xBF72910D0F26F025,
	&CAM::SET_GAMEPLAY_HINT_FOV,
	&CAM::_0xF8BDBF3D573049A1,
	&CAM::_0xD1F8363DFAD03848,
	&CAM::_0x5D7B620DAE436138,
	&CAM::_0xC92717EF615B6704,
	&CAM::GET_IS_MULTIPLAYER_BRIEF,
	&CAM::SET_CINEMATIC_BUTTON_ACTIVE,
	&CAM::IS_CINEMATIC_CAM_RENDERING,
	&CAM::SHAKE_CINEMATIC_CAM,
	&CAM::IS_CINEMATIC_CAM_SHAKING,
	&CAM::SET_CINEMATIC_CAM_SHAKE_AMPLITUDE,
	&CAM::STOP_CINEMATIC_CAM_SHAKING,
	&CAM::_DISABLE_VEHICLE_FIRST_PERSON_CAM_THIS_FRAME,
	&CAM::_0x62ECFCFDEE7885D6,
	&CAM::_0x9E4CFFF989258472,
	&CAM::_F4F2C0D4EE209E20,
	&CAM::_0xCA9D2AA3E326D720,
	&CAM::_IS_IN_VEHICLE_CAM_DISABLED,
	&CAM::CREATE_CINEMATIC_SHOT,
	&CAM::IS_CINEMATIC_SHOT_ACTIVE,
	&CAM::STOP_CINEMATIC_SHOT,
	&CAM::_0xA41BCD7213805AAC,
	&CAM::_0xDC9DA9E8789F5246,
	&CAM::SET_CINEMATIC_MODE_ACTIVE,
	&CAM::_0x1F2300CB7FA7B7F6,
	&CAM::_0x17FCA7199A530203,
	&CAM::STOP_CUTSCENE_CAM_SHAKING,
	&CAM::_0x12DED8CA53D47EA5,
	&CAM::_0x89215EC747DF244A,
	&CAM::_0x5A43C76F7FC7BA5F,
	&CAM::_SET_CAM_EFFECT,
	&CAM::_0x5C41E6BABC9E2112,
	&CAM::_0x21E253A7F8DA5DFB,
	&CAM::_0x11FA5D3479C7DD47,
	&CAM::_0xEAF0FA793D05C592,
	&CAM::_GET_REPLAY_FREE_CAM_MAX_RANGE,
};