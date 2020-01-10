#pragma once


#include "../NativeCaller.h"



namespace SDK {
	class Screen
	{
	public:
		Screen() = default;

		using Size = Size2;

		enum class Effect
		{
			SwitchHudIn,
			SwitchHudOut,
			FocusIn,
			FocusOut,
			MinigameEndNeutral,
			MinigameEndTrevor,
			MinigameEndFranklin,
			MinigameEndMichael,
			MinigameTransitionOut,
			MinigameTransitionIn,
			SwitchShortNeutralIn,
			SwitchShortFranklinIn,
			SwitchShortTrevorIn,
			SwitchShortMichaelIn,
			SwitchOpenMichaelIn,
			SwitchOpenFranklinIn,
			SwitchOpenTrevorIn,
			SwitchHudMichaelOut,
			SwitchHudFranklinOut,
			SwitchHudTrevorOut,
			SwitchShortFranklinMid,
			SwitchShortMichaelMid,
			SwitchShortTrevorMid,
			DeathFailOut,
			CamPushInNeutral,
			CamPushInFranklin,
			CamPushInMichael,
			CamPushInTrevor,
			SwitchSceneFranklin,
			SwitchSceneTrevor,
			SwitchSceneMichael,
			SwitchSceneNeutral,
			MpCelebWin,
			MpCelebWinOut,
			MpCelebLose,
			MpCelebLoseOut,
			DeathFailNeutralIn,
			DeathFailMpDark,
			DeathFailMpIn,
			MpCelebPreloadFade,
			PeyoteEndOut,
			PeyoteEndIn,
			PeyoteIn,
			PeyoteOut,
			MpRaceCrash,
			SuccessFranklin,
			SuccessTrevor,
			SuccessMichael,
			DrugsMichaelAliensFightIn,
			DrugsMichaelAliensFight,
			DrugsMichaelAliensFightOut,
			DrugsTrevorClownsFightIn,
			DrugsTrevorClownsFight,
			DrugsTrevorClownsFightOut,
			HeistCelebPass,
			HeistCelebPassBw,
			HeistCelebEnd,
			HeistCelebToast,
			MenuMgHeistIn,
			MenuMgTournamentIn,
			MenuMgSelectionIn,
			ChopVision,
			DmtFlightIntro,
			DmtFlight,
			DrugsDrivingIn,
			DrugsDrivingOut,
			SwitchOpenNeutralFib5,
			HeistLocate,
			MpJobLoad,
			RaceTurbo,
			MpIntroLogo,
			HeistTripSkipFade,
			MenuMgHeistOut,
			MpCoronaSwitch,
			MenuMgSelectionTint,
			SuccessNeutral,
			ExplosionJosh3,
			SniperOverlay,
			RampageOut,
			Rampage,
			DontTazemeBro,
		};

		inline static std::vector<const char*> m_effects = {
			"SwitchHUDIn",
			"SwitchHUDOut",
			"FocusIn",
			"FocusOut",
			"MinigameEndNeutral",
			"MinigameEndTrevor",
			"MinigameEndFranklin",
			"MinigameEndMichael",
			"MinigameTransitionOut",
			"MinigameTransitionIn",
			"SwitchShortNeutralIn",
			"SwitchShortFranklinIn",
			"SwitchShortTrevorIn",
			"SwitchShortMichaelIn",
			"SwitchOpenMichaelIn",
			"SwitchOpenFranklinIn",
			"SwitchOpenTrevorIn",
			"SwitchHUDMichaelOut",
			"SwitchHUDFranklinOut",
			"SwitchHUDTrevorOut",
			"SwitchShortFranklinMid",
			"SwitchShortMichaelMid",
			"SwitchShortTrevorMid",
			"DeathFailOut",
			"CamPushInNeutral",
			"CamPushInFranklin",
			"CamPushInMichael",
			"CamPushInTrevor",
			"SwitchSceneFranklin",
			"SwitchSceneTrevor",
			"SwitchSceneMichael",
			"SwitchSceneNeutral",
			"MP_Celeb_Win",
			"MP_Celeb_Win_Out",
			"MP_Celeb_Lose",
			"MP_Celeb_Lose_Out",
			"DeathFailNeutralIn",
			"DeathFailMPDark",
			"DeathFailMPIn",
			"MP_Celeb_Preload_Fade",
			"PeyoteEndOut",
			"PeyoteEndIn",
			"PeyoteIn",
			"PeyoteOut",
			"MP_race_crash",
			"SuccessFranklin",
			"SuccessTrevor",
			"SuccessMichael",
			"DrugsMichaelAliensFightIn",
			"DrugsMichaelAliensFight",
			"DrugsMichaelAliensFightOut",
			"DrugsTrevorClownsFightIn",
			"DrugsTrevorClownsFight",
			"DrugsTrevorClownsFightOut",
			"HeistCelebPass",
			"HeistCelebPassBW",
			"HeistCelebEnd",
			"HeistCelebToast",
			"MenuMGHeistIn",
			"MenuMGTournamentIn",
			"MenuMGSelectionIn",
			"ChopVision",
			"DMT_flight_intro",
			"DMT_flight",
			"DrugsDrivingIn",
			"DrugsDrivingOut",
			"SwitchOpenNeutralFIB5",
			"HeistLocate",
			"MP_job_load",
			"RaceTurbo",
			"MP_intro_logo",
			"HeistTripSkipFade",
			"MenuMGHeistOut",
			"MP_corona_switch",
			"MenuMGSelectionTint",
			"SuccessNeutral",
			"ExplosionJosh3",
			"SniperOverlay",
			"RampageOut",
			"Rampage",
			"Dont_tazeme_bro"
		};

		/// <summary>
		/// The base width of the screen used for all UI Calculations, unless ScaledDraw is used
		/// </summary>
		inline static const float Width = 1280.f;

		/// <summary>
		/// The base height of the screen used for all UI Calculations
		/// </summary>
		inline static const float Height = 720.f;

		/// <summary>
		/// Gets the actual screen resolution the game is being rendered at
		/// </summary>
		static Size GetResolution()
		{
			int width, height;
			Call(SE::GRAPHICS::_GET_ACTIVE_SCREEN_RESOLUTION, &width, &height);
			return Size((float)width, (float)height);
		}

		/// <summary>
		/// Gets the current screen aspect ratio
		/// </summary>		
		static float GetAspectRatio()
		{
			return Call(SE::GRAPHICS::_GET_ASPECT_RATIO, 0);
		}

		/// <summary>
		/// Gets the screen width scaled against a 720pixel height base.
		/// </summary>
		static float GetScaledHeight()
		{
			return Height * GetAspectRatio();
		}

		/// <summary>
		/// Gets a value indicating whether the screen is faded in.
		/// </summary>
		static bool IsFadedIn()
		{
			return Call(SE::CAM::IS_SCREEN_FADED_IN) == TRUE;
		}

		/// <summary>
		/// Gets a value indicating whether the screen is faded out.
		/// </summary>
		static bool IsFadedOut()
		{
			return Call(SE::CAM::IS_SCREEN_FADED_OUT) == TRUE;
		}

		/// <summary>
		/// Gets a value indicating whether the screen is fading in.
		/// </summary>
		static bool IsFadingIn()
		{
			return Call(SE::CAM::IS_SCREEN_FADING_IN) == TRUE;
		}

		/// <summary>
		/// Gets a value indicating whether the screen is fading out.
		/// </summary>
		static bool IsFadingOut()
		{
			return Call(SE::CAM::IS_SCREEN_FADING_OUT) == TRUE;
		}

		/// <summary>
		/// Fades the screen in over a specific time, useful for transitioning
		/// </summary>
		static void FadeIn(int duration)
		{
			Call(SE::CAM::DO_SCREEN_FADE_IN, duration);
		}

		/// <summary>
		/// Fades the screen out over a specific time, useful for transitioning
		/// </summary>
		static void FadeOut(int duration)
		{
			Call(SE::CAM::DO_SCREEN_FADE_OUT, duration);
		}

		/// <summary>
		/// Gets a value indicating whether the specific screen effect is running.
		/// </summary>
		static bool IsEffectActive(Effect effect)
		{
			return Call(SE::GRAPHICS::ANIMPOSTFX_IS_RUNNING, m_effects[(int)effect]);
		}

		/// <summary>
		/// Starts applying the specified effect to the screen. 
		/// </summary>
		static void StartEffect(Effect effect, int duration = 0, bool looped = false)
		{
			Call(SE::GRAPHICS::ANIMPOSTFX_PLAY, m_effects[(int)effect], duration, looped);
		}

		/// <summary>
		/// Stops applying the specified effect to the screen.
		/// </summary>
		static void StopEffect(Effect effect)
		{
			Call(SE::GRAPHICS::ANIMPOSTFX_STOP, m_effects[(int)effect]);
		}

		/// <summary>
		/// Stops all currently running effects.
		/// </summary>
		static void StopEffects()
		{
			Call(SE::GRAPHICS::ANIMPOSTFX_STOP_ALL);
		}

		/// <summary>
		/// Translates a point in WorldSpace to its given Coordinates on the <see cref="Screen"/>
		/// </summary>
		static Point2 WorldToScreen(Pos coord)
		{
			Point2 point;
			if (Call(SE::GRAPHICS::GET_SCREEN_COORD_FROM_WORLD_COORD, coord.x, coord.y, coord.z, &point.x, &point.y) == FALSE) {
				point.setX(-1.f);
				point.setY(-1.f);
			}
			point.x *= Width;
			point.y *= Height;
			return point;
		}
	};
};