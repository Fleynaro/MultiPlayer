#include "GameScripts.h"


//Singletones
//STATIC_FIELD_INIT(ISingleton<GameScriptsHook_Gen>::m_pSingleton) = NULL;

//Hooks
//STATIC_FIELD_INIT(GameScripts::executeScript) = NULL;

//Structure
//STATIC_FIELD_INIT(Memory::IDynStructure<GameScripts::Data>::m_offsets);

//Other
//STATIC_FIELD_INIT(GameScripts::m_curExeGameScript) = nullptr;

GameScripts::scriptList GameScripts::m_scriptList({
	
	new GameScript("abigail1"),
	new GameScript("abigail2"),
	new GameScript("achievement_controller"),
	new GameScript("act_cinema"),
	new GameScript("af_intro_t_sandy"),
	new GameScript("agency_heist1"),
	new GameScript("agency_heist2"),
	new GameScript("agency_heist3a"),
	new GameScript("agency_heist3b"),
	new GameScript("agency_prep1"),
	new GameScript("agency_prep2amb"),
	new GameScript("aicover_test"),
	new GameScript("ainewengland_test"),
	new GameScript("altruist_cult"),
	new GameScript("ambientblimp"),
	new GameScript("ambient_diving"),
	new GameScript("ambient_mrsphilips"),
	new GameScript("ambient_solomon"),
	new GameScript("ambient_sonar"),
	new GameScript("ambient_tonya"),
	new GameScript("ambient_tonyacall"),
	new GameScript("ambient_tonyacall2"),
	new GameScript("ambient_tonyacall5"),
	new GameScript("ambient_ufos"),
	new GameScript("am_airstrike"),
	new GameScript("am_ammo_drop"),
	new GameScript("am_armwrestling"),
	new GameScript("am_armybase"),
	new GameScript("am_backup_heli"),
	new GameScript("am_boat_taxi"),
	new GameScript("am_bru_box"),
	new GameScript("am_car_mod_tut"),
	new GameScript("am_challenges"),
	new GameScript("am_contact_requests"),
	new GameScript("am_cp_collection"),
	new GameScript("am_crate_drop"),
	new GameScript("am_criminal_damage"),
	new GameScript("am_cr_securityvan"),
	new GameScript("am_darts"),
	new GameScript("am_dead_drop"),
	new GameScript("am_destroy_veh"),
	new GameScript("am_distract_cops"),
	new GameScript("am_doors"),
	new GameScript("am_ferriswheel"),
	new GameScript("am_gang_call"),
	new GameScript("am_ga_pickups"),
	new GameScript("am_heist_int"),
	new GameScript("am_heli_taxi"),
	new GameScript("am_hold_up"),
	new GameScript("am_hot_property"),
	new GameScript("am_hot_target"),
	new GameScript("am_hunt_the_beast"),
	new GameScript("am_imp_exp"),
	new GameScript("am_joyrider"),
	new GameScript("am_kill_list"),
	new GameScript("am_king_of_the_castle"),
	new GameScript("am_launcher"),
	new GameScript("am_lester_cut"),
	new GameScript("am_lowrider_int"),
	new GameScript("am_mission_launch"),
	new GameScript("am_mp_carwash_launch"),
	new GameScript("am_mp_garage_control"),
	new GameScript("am_mp_property_ext"),
	new GameScript("am_mp_property_int"),
	new GameScript("am_mp_yacht"),
	new GameScript("am_npc_invites"),
	new GameScript("am_pass_the_parcel"),
	new GameScript("am_penned_in"),
	new GameScript("am_pi_menu"),
	new GameScript("am_plane_takedown"),
	new GameScript("am_prison"),
	new GameScript("am_prostitute"),
	new GameScript("am_rollercoaster"),
	new GameScript("am_rontrevor_cut"),
	new GameScript("am_taxi"),
	new GameScript("am_vehicle_spawn"),
	new GameScript("animal_controller"),
	new GameScript("appbroadcast"),
	new GameScript("appcamera"),
	new GameScript("appchecklist"),
	new GameScript("appcontacts"),
	new GameScript("appemail"),
	new GameScript("appextraction"),
	new GameScript("apphs_sleep"),
	new GameScript("appinternet"),
	new GameScript("appjipmp"),
	new GameScript("appmedia"),
	new GameScript("appmpbossagency"),
	new GameScript("appmpemail"),
	new GameScript("appmpjoblistnew"),
	new GameScript("apporganiser"),
	new GameScript("apprepeatplay"),
	new GameScript("appsettings"),
	new GameScript("appsidetask"),
	new GameScript("apptextmessage"),
	new GameScript("apptrackify"),
	new GameScript("appvlsi"),
	new GameScript("appzit"),
	new GameScript("armenian1"),
	new GameScript("armenian2"),
	new GameScript("armenian3"),
	new GameScript("assassin_bus"),
	new GameScript("assassin_construction"),
	new GameScript("assassin_hooker"),
	new GameScript("assassin_multi"),
	new GameScript("assassin_rankup"),
	new GameScript("assassin_valet"),
	new GameScript("atm_trigger"),
	new GameScript("audiotest"),
	new GameScript("autosave_controller"),
	new GameScript("bailbond1"),
	new GameScript("bailbond2"),
	new GameScript("bailbond3"),
	new GameScript("bailbond4"),
	new GameScript("bailbond_launcher"),
	new GameScript("barry1"),
	new GameScript("barry2"),
	new GameScript("barry3"),
	new GameScript("barry3a"),
	new GameScript("barry3c"),
	new GameScript("barry4"),
	new GameScript("benchmark"),
	new GameScript("bigwheel"),
	new GameScript("bj"),
	new GameScript("blimptest"),
	new GameScript("blip_controller"),
	new GameScript("bootycallhandler"),
	new GameScript("bootycall_debug_controller"),
	new GameScript("buddydeathresponse"),
	new GameScript("bugstar_mission_export"),
	new GameScript("buildingsiteambience"),
	new GameScript("building_controller"),
	new GameScript("cablecar"),
	new GameScript("camera_test"),
	new GameScript("cam_coord_sender"),
	new GameScript("candidate_controller"),
	new GameScript("carmod_shop"),
	new GameScript("carsteal1"),
	new GameScript("carsteal2"),
	new GameScript("carsteal3"),
	new GameScript("carsteal4"),
	new GameScript("carwash1"),
	new GameScript("carwash2"),
	new GameScript("car_roof_test"),
	new GameScript("celebrations"),
	new GameScript("celebration_editor"),
	new GameScript("cellphone_controller"),
	new GameScript("cellphone_flashhand"),
	new GameScript("charactergoals"),
	new GameScript("charanimtest"),
	new GameScript("cheat_controller"),
	new GameScript("chinese1"),
	new GameScript("chinese2"),
	new GameScript("chop"),
	new GameScript("clothes_shop_mp"),
	new GameScript("clothes_shop_sp"),
	new GameScript("code_controller"),
	new GameScript("combat_test"),
	new GameScript("comms_controller"),
	new GameScript("completionpercentage_controller"),
	new GameScript("component_checker"),
	new GameScript("context_controller"),
	new GameScript("controller_ambientarea"),
	new GameScript("controller_races"),
	new GameScript("controller_taxi"),
	new GameScript("controller_towing"),
	new GameScript("controller_trafficking"),
	new GameScript("coordinate_recorder"),
	new GameScript("country_race"),
	new GameScript("country_race_controller"),
	new GameScript("creation_startup"),
	new GameScript("creator"),
	new GameScript("custom_config"),
	new GameScript("cutscenemetrics"),
	new GameScript("cutscenesamples"),
	new GameScript("cutscene_test"),
	new GameScript("darts"),
	new GameScript("debug"),
	new GameScript("debug_app_select_screen"),
	new GameScript("debug_launcher"),
	new GameScript("density_test"),
	new GameScript("dialogue_handler"),
	new GameScript("director_mode"),
	new GameScript("docks2asubhandler"),
	new GameScript("docks_heista"),
	new GameScript("docks_heistb"),
	new GameScript("docks_prep1"),
	new GameScript("docks_prep2b"),
	new GameScript("docks_setup"),
	new GameScript("dreyfuss1"),
	new GameScript("drf1"),
	new GameScript("drf2"),
	new GameScript("drf3"),
	new GameScript("drf4"),
	new GameScript("drf5"),
	new GameScript("drunk"),
	new GameScript("drunk_controller"),
	new GameScript("dynamixtest"),
	new GameScript("email_controller"),
	new GameScript("emergencycall"),
	new GameScript("emergencycalllauncher"),
	new GameScript("epscars"),
	new GameScript("epsdesert"),
	new GameScript("epsilon1"),
	new GameScript("epsilon2"),
	new GameScript("epsilon3"),
	new GameScript("epsilon4"),
	new GameScript("epsilon5"),
	new GameScript("epsilon6"),
	new GameScript("epsilon7"),
	new GameScript("epsilon8"),
	new GameScript("epsilontract"),
	new GameScript("epsrobes"),
	new GameScript("event_controller"),
	new GameScript("exile1"),
	new GameScript("exile2"),
	new GameScript("exile3"),
	new GameScript("exile_city_denial"),
	new GameScript("extreme1"),
	new GameScript("extreme2"),
	new GameScript("extreme3"),
	new GameScript("extreme4"),
	new GameScript("fairgroundhub"),
	new GameScript("fake_interiors"),
	new GameScript("fameorshame_eps"),
	new GameScript("fameorshame_eps_1"),
	new GameScript("fame_or_shame_set"),
	new GameScript("family1"),
	new GameScript("family1taxi"),
	new GameScript("family2"),
	new GameScript("family3"),
	new GameScript("family4"),
	new GameScript("family5"),
	new GameScript("family6"),
	new GameScript("family_scene_f0"),
	new GameScript("family_scene_f1"),
	new GameScript("family_scene_m"),
	new GameScript("family_scene_t0"),
	new GameScript("family_scene_t1"),
	new GameScript("fanatic1"),
	new GameScript("fanatic2"),
	new GameScript("fanatic3"),
	new GameScript("fbi1"),
	new GameScript("fbi2"),
	new GameScript("fbi3"),
	new GameScript("fbi4"),
	new GameScript("fbi4_intro"),
	new GameScript("fbi4_prep1"),
	new GameScript("fbi4_prep2"),
	new GameScript("fbi4_prep3"),
	new GameScript("fbi4_prep3amb"),
	new GameScript("fbi4_prep4"),
	new GameScript("fbi4_prep5"),
	new GameScript("fbi5a"),
	new GameScript("filenames.txt"),
	new GameScript("finalea"),
	new GameScript("finaleb"),
	new GameScript("finalec1"),
	new GameScript("finalec2"),
	new GameScript("finale_choice"),
	new GameScript("finale_credits"),
	new GameScript("finale_endgame"),
	new GameScript("finale_heist1"),
	new GameScript("finale_heist2a"),
	new GameScript("finale_heist2b"),
	new GameScript("finale_heist2_intro"),
	new GameScript("finale_heist_prepa"),
	new GameScript("finale_heist_prepb"),
	new GameScript("finale_heist_prepc"),
	new GameScript("finale_heist_prepd"),
	new GameScript("finale_heist_prepeamb"),
	new GameScript("finale_intro"),
	new GameScript("floating_help_controller"),
	new GameScript("flowintrotitle"),
	new GameScript("flowstartaccept"),
	new GameScript("flow_autoplay"),
	new GameScript("flow_controller"),
	new GameScript("flow_help"),
	new GameScript("flyunderbridges"),
	new GameScript("fmmc_launcher"),
	new GameScript("fmmc_playlist_controller"),
	new GameScript("fm_bj_race_controler"),
	new GameScript("fm_capture_creator"),
	new GameScript("fm_deathmatch_controler"),
	new GameScript("fm_deathmatch_creator"),
	new GameScript("fm_hideout_controler"),
	new GameScript("fm_hold_up_tut"),
	new GameScript("fm_horde_controler"),
	new GameScript("fm_impromptu_dm_controler"),
	new GameScript("fm_intro"),
	new GameScript("fm_intro_cut_dev"),
	new GameScript("fm_lts_creator"),
	new GameScript("fm_maintain_cloud_header_data"),
	new GameScript("fm_maintain_transition_players"),
	new GameScript("fm_main_menu"),
	new GameScript("fm_mission_controller"),
	new GameScript("fm_mission_creator"),
	new GameScript("fm_race_controler"),
	new GameScript("fm_race_creator"),
	new GameScript("forsalesigns"),
	new GameScript("fps_test"),
	new GameScript("fps_test_mag"),
	new GameScript("franklin0"),
	new GameScript("franklin1"),
	new GameScript("franklin2"),
	new GameScript("freemode"),
	new GameScript("freemode_init"),
	new GameScript("friendactivity"),
	new GameScript("friends_controller"),
	new GameScript("friends_debug_controller"),
	new GameScript("fullmap_test"),
	new GameScript("fullmap_test_flow"),
	new GameScript("game_server_test"),
	new GameScript("gb_assault"),
	new GameScript("gb_bellybeast"),
	new GameScript("gb_carjacking"),
	new GameScript("gb_collect_money"),
	new GameScript("gb_deathmatch"),
	new GameScript("gb_finderskeepers"),
	new GameScript("gb_fivestar"),
	new GameScript("gb_hunt_the_boss"),
	new GameScript("gb_point_to_point"),
	new GameScript("gb_rob_shop"),
	new GameScript("gb_sightseer"),
	new GameScript("gb_terminate"),
	new GameScript("gb_yacht_rob"),
	new GameScript("general_test"),
	new GameScript("golf"),
	new GameScript("golf_ai_foursome"),
	new GameScript("golf_ai_foursome_putting"),
	new GameScript("golf_mp"),
	new GameScript("gpb_andymoon"),
	new GameScript("gpb_baygor"),
	new GameScript("gpb_billbinder"),
	new GameScript("gpb_clinton"),
	new GameScript("gpb_griff"),
	new GameScript("gpb_jane"),
	new GameScript("gpb_jerome"),
	new GameScript("gpb_jesse"),
	new GameScript("gpb_mani"),
	new GameScript("gpb_mime"),
	new GameScript("gpb_pameladrake"),
	new GameScript("gpb_superhero"),
	new GameScript("gpb_tonya"),
	new GameScript("gpb_zombie"),
	new GameScript("gtest_airplane"),
	new GameScript("gtest_avoidance"),
	new GameScript("gtest_boat"),
	new GameScript("gtest_divingfromcar"),
	new GameScript("gtest_divingfromcarwhilefleeing"),
	new GameScript("gtest_helicopter"),
	new GameScript("gtest_nearlymissedbycar"),
	new GameScript("gunclub_shop"),
	new GameScript("gunfighttest"),
	new GameScript("hairdo_shop_mp"),
	new GameScript("hairdo_shop_sp"),
	new GameScript("hao1"),
	new GameScript("headertest"),
	new GameScript("heatmap_test"),
	new GameScript("heatmap_test_flow"),
	new GameScript("heist_ctrl_agency"),
	new GameScript("heist_ctrl_docks"),
	new GameScript("heist_ctrl_finale"),
	new GameScript("heist_ctrl_jewel"),
	new GameScript("heist_ctrl_rural"),
	new GameScript("heli_gun"),
	new GameScript("heli_streaming"),
	new GameScript("hud_creator"),
	new GameScript("hunting1"),
	new GameScript("hunting2"),
	new GameScript("hunting_ambient"),
	new GameScript("idlewarper"),
	new GameScript("ingamehud"),
	new GameScript("initial"),
	new GameScript("jewelry_heist"),
	new GameScript("jewelry_prep1a"),
	new GameScript("jewelry_prep1b"),
	new GameScript("jewelry_prep2a"),
	new GameScript("jewelry_setup1"),
	new GameScript("josh1"),
	new GameScript("josh2"),
	new GameScript("josh3"),
	new GameScript("josh4"),
	new GameScript("lamar1"),
	new GameScript("laptop_trigger"),
	new GameScript("launcher_abigail"),
	new GameScript("launcher_barry"),
	new GameScript("launcher_basejumpheli"),
	new GameScript("launcher_basejumppack"),
	new GameScript("launcher_carwash"),
	new GameScript("launcher_darts"),
	new GameScript("launcher_dreyfuss"),
	new GameScript("launcher_epsilon"),
	new GameScript("launcher_extreme"),
	new GameScript("launcher_fanatic"),
	new GameScript("launcher_golf"),
	new GameScript("launcher_hao"),
	new GameScript("launcher_hunting"),
	new GameScript("launcher_hunting_ambient"),
	new GameScript("launcher_josh"),
	new GameScript("launcher_maude"),
	new GameScript("launcher_minute"),
	new GameScript("launcher_mrsphilips"),
	new GameScript("launcher_nigel"),
	new GameScript("launcher_offroadracing"),
	new GameScript("launcher_omega"),
	new GameScript("launcher_paparazzo"),
	new GameScript("launcher_pilotschool"),
	new GameScript("launcher_racing"),
	new GameScript("launcher_rampage"),
	new GameScript("launcher_range"),
	new GameScript("launcher_stunts"),
	new GameScript("launcher_tennis"),
	new GameScript("launcher_thelastone"),
	new GameScript("launcher_tonya"),
	new GameScript("launcher_triathlon"),
	new GameScript("launcher_yoga"),
	new GameScript("lester1"),
	new GameScript("lesterhandler"),
	new GameScript("letterscraps"),
	new GameScript("line_activation_test"),
	new GameScript("liverecorder"),
	new GameScript("locates_tester"),
	new GameScript("luxe_veh_activity"),
	new GameScript("magdemo"),
	new GameScript("magdemo2"),
	new GameScript("main"),
	new GameScript("maintransition"),
	new GameScript("main_install"),
	new GameScript("main_persistent"),
	new GameScript("martin1"),
	new GameScript("maude1"),
	new GameScript("maude_postbailbond"),
	new GameScript("me_amanda1"),
	new GameScript("me_jimmy1"),
	new GameScript("me_tracey1"),
	new GameScript("mg_race_to_point"),
	new GameScript("michael1"),
	new GameScript("michael2"),
	new GameScript("michael3"),
	new GameScript("michael4"),
	new GameScript("michael4leadout"),
	new GameScript("minigame_ending_stinger"),
	new GameScript("minigame_stats_tracker"),
	new GameScript("minute1"),
	new GameScript("minute2"),
	new GameScript("minute3"),
	new GameScript("mission_race"),
	new GameScript("mission_repeat_controller"),
	new GameScript("mission_stat_alerter"),
	new GameScript("mission_stat_watcher"),
	new GameScript("mission_triggerer_a"),
	new GameScript("mission_triggerer_b"),
	new GameScript("mission_triggerer_c"),
	new GameScript("mission_triggerer_d"),
	new GameScript("mpstatsinit"),
	new GameScript("mptestbed"),
	new GameScript("mp_awards"),
	new GameScript("mp_fm_registration"),
	new GameScript("mp_menuped"),
	new GameScript("mp_prop_global_block"),
	new GameScript("mp_prop_special_global_block"),
	new GameScript("mp_registration"),
	new GameScript("mp_save_game_global_block"),
	new GameScript("mp_unlocks"),
	new GameScript("mp_weapons"),
	new GameScript("mrsphilips1"),
	new GameScript("mrsphilips2"),
	new GameScript("murdermystery"),
	new GameScript("navmeshtest"),
	new GameScript("net_bot_brain"),
	new GameScript("net_bot_simplebrain"),
	new GameScript("net_cloud_mission_loader"),
	new GameScript("net_combat_soaktest"),
	new GameScript("net_jacking_soaktest"),
	new GameScript("net_rank_tunable_loader"),
	new GameScript("net_session_soaktest"),
	new GameScript("net_tunable_check"),
	new GameScript("nigel1"),
	new GameScript("nigel1a"),
	new GameScript("nigel1b"),
	new GameScript("nigel1c"),
	new GameScript("nigel1d"),
	new GameScript("nigel2"),
	new GameScript("nigel3"),
	new GameScript("nodeviewer"),
	new GameScript("ob_abatdoor"),
	new GameScript("ob_abattoircut"),
	new GameScript("ob_airdancer"),
	new GameScript("ob_bong"),
	new GameScript("ob_cashregister"),
	new GameScript("ob_drinking_shots"),
	new GameScript("ob_foundry_cauldron"),
	new GameScript("ob_franklin_beer"),
	new GameScript("ob_franklin_tv"),
	new GameScript("ob_franklin_wine"),
	new GameScript("ob_huffing_gas"),
	new GameScript("ob_mp_bed_high"),
	new GameScript("ob_mp_bed_low"),
	new GameScript("ob_mp_bed_med"),
	new GameScript("ob_mp_shower_med"),
	new GameScript("ob_mp_stripper"),
	new GameScript("ob_mr_raspberry_jam"),
	new GameScript("ob_poledancer"),
	new GameScript("ob_sofa_franklin"),
	new GameScript("ob_sofa_michael"),
	new GameScript("ob_telescope"),
	new GameScript("ob_tv"),
	new GameScript("ob_vend1"),
	new GameScript("ob_vend2"),
	new GameScript("ob_wheatgrass"),
	new GameScript("offroad_races"),
	new GameScript("omega1"),
	new GameScript("omega2"),
	new GameScript("paparazzo1"),
	new GameScript("paparazzo2"),
	new GameScript("paparazzo3"),
	new GameScript("paparazzo3a"),
	new GameScript("paparazzo3b"),
	new GameScript("paparazzo4"),
	new GameScript("paradise"),
	new GameScript("paradise2"),
	new GameScript("pausemenu"),
	new GameScript("pausemenu_example"),
	new GameScript("pausemenu_map"),
	new GameScript("pausemenu_multiplayer"),
	new GameScript("pausemenu_sp_repeat"),
	new GameScript("pb_busker"),
	new GameScript("pb_homeless"),
	new GameScript("pb_preacher"),
	new GameScript("pb_prostitute"),
	new GameScript("photographymonkey"),
	new GameScript("photographywildlife"),
	new GameScript("physics_perf_test"),
	new GameScript("physics_perf_test_launcher"),
	new GameScript("pickuptest"),
	new GameScript("pickupvehicles"),
	new GameScript("pickup_controller"),
	new GameScript("pilot_school"),
	new GameScript("pilot_school_mp"),
	new GameScript("pi_menu"),
	new GameScript("placeholdermission"),
	new GameScript("placementtest"),
	new GameScript("planewarptest"),
	new GameScript("player_controller"),
	new GameScript("player_controller_b"),
	new GameScript("player_scene_ft_franklin1"),
	new GameScript("player_scene_f_lamgraff"),
	new GameScript("player_scene_f_lamtaunt"),
	new GameScript("player_scene_f_taxi"),
	new GameScript("player_scene_mf_traffic"),
	new GameScript("player_scene_m_cinema"),
	new GameScript("player_scene_m_fbi2"),
	new GameScript("player_scene_m_kids"),
	new GameScript("player_scene_m_shopping"),
	new GameScript("player_scene_t_bbfight"),
	new GameScript("player_scene_t_chasecar"),
	new GameScript("player_scene_t_insult"),
	new GameScript("player_scene_t_park"),
	new GameScript("player_scene_t_tie"),
	new GameScript("player_timetable_scene"),
	new GameScript("playthrough_builder"),
	new GameScript("pm_defend"),
	new GameScript("pm_delivery"),
	new GameScript("pm_gang_attack"),
	new GameScript("pm_plane_promotion"),
	new GameScript("pm_recover_stolen"),
	new GameScript("postkilled_bailbond2"),
	new GameScript("postrc_barry1and2"),
	new GameScript("postrc_barry4"),
	new GameScript("postrc_epsilon4"),
	new GameScript("postrc_nigel3"),
	new GameScript("profiler_registration"),
	new GameScript("prologue1"),
	new GameScript("prop_drop"),
	new GameScript("racetest"),
	new GameScript("rampage1"),
	new GameScript("rampage2"),
	new GameScript("rampage3"),
	new GameScript("rampage4"),
	new GameScript("rampage5"),
	new GameScript("rampage_controller"),
	new GameScript("randomchar_controller"),
	new GameScript("range_modern"),
	new GameScript("range_modern_mp"),
	new GameScript("rerecord_recording"),
	new GameScript("respawn_controller"),
	new GameScript("restrictedareas"),
	new GameScript("re_abandonedcar"),
	new GameScript("re_accident"),
	new GameScript("re_armybase"),
	new GameScript("re_arrests"),
	new GameScript("re_atmrobbery"),
	new GameScript("re_bikethief"),
	new GameScript("re_border"),
	new GameScript("re_burials"),
	new GameScript("re_bus_tours"),
	new GameScript("re_cartheft"),
	new GameScript("re_chasethieves"),
	new GameScript("re_crashrescue"),
	new GameScript("re_cultshootout"),
	new GameScript("re_dealgonewrong"),
	new GameScript("re_domestic"),
	new GameScript("re_drunkdriver"),
	new GameScript("re_duel"),
	new GameScript("re_gangfight"),
	new GameScript("re_gang_intimidation"),
	new GameScript("re_getaway_driver"),
	new GameScript("re_hitch_lift"),
	new GameScript("re_homeland_security"),
	new GameScript("re_lossantosintl"),
	new GameScript("re_lured"),
	new GameScript("re_monkey"),
	new GameScript("re_mountdance"),
	new GameScript("re_muggings"),
	new GameScript("re_paparazzi"),
	new GameScript("re_prison"),
	new GameScript("re_prisonerlift"),
	new GameScript("re_prisonvanbreak"),
	new GameScript("re_rescuehostage"),
	new GameScript("re_seaplane"),
	new GameScript("re_securityvan"),
	new GameScript("re_shoprobbery"),
	new GameScript("re_snatched"),
	new GameScript("re_stag_do"),
	new GameScript("re_yetarian"),
	new GameScript("rollercoaster"),
	new GameScript("rural_bank_heist"),
	new GameScript("rural_bank_prep1"),
	new GameScript("rural_bank_setup"),
	new GameScript("savegame_bed"),
	new GameScript("save_anywhere"),
	new GameScript("scaleformgraphictest"),
	new GameScript("scaleformminigametest"),
	new GameScript("scaleformprofiling"),
	new GameScript("scaleformtest"),
	new GameScript("scene_builder"),
	new GameScript("sclub_front_bouncer"),
	new GameScript("scripted_cam_editor"),
	new GameScript("scriptplayground"),
	new GameScript("scripttest1"),
	new GameScript("scripttest2"),
	new GameScript("scripttest3"),
	new GameScript("scripttest4"),
	new GameScript("script_metrics"),
	new GameScript("sctv"),
	new GameScript("sc_lb_global_block"),
	new GameScript("selector"),
	new GameScript("selector_example"),
	new GameScript("selling_short_1"),
	new GameScript("selling_short_2"),
	new GameScript("shooting_camera"),
	new GameScript("shoprobberies"),
	new GameScript("shop_controller"),
	new GameScript("shot_bikejump"),
	new GameScript("shrinkletter"),
	new GameScript("sh_intro_f_hills"),
	new GameScript("sh_intro_m_home"),
	new GameScript("smoketest"),
	new GameScript("social_controller"),
	new GameScript("solomon1"),
	new GameScript("solomon2"),
	new GameScript("solomon3"),
	new GameScript("spaceshipparts"),
	new GameScript("spawn_activities"),
	new GameScript("speech_reverb_tracker"),
	new GameScript("spmc_instancer"),
	new GameScript("spmc_preloader"),
	new GameScript("sp_dlc_registration"),
	new GameScript("sp_editor_mission_instance"),
	new GameScript("sp_menuped"),
	new GameScript("sp_pilotschool_reg"),
	new GameScript("standard_global_init"),
	new GameScript("standard_global_reg"),
	new GameScript("startup"),
	new GameScript("startup_install"),
	new GameScript("startup_locationtest"),
	new GameScript("startup_positioning"),
	new GameScript("startup_smoketest"),
	new GameScript("stats_controller"),
	new GameScript("stock_controller"),
	new GameScript("streaming"),
	new GameScript("stripclub"),
	new GameScript("stripclub_drinking"),
	new GameScript("stripclub_mp"),
	new GameScript("stripperhome"),
	new GameScript("stunt_plane_races"),
	new GameScript("tasklist_1"),
	new GameScript("tattoo_shop"),
	new GameScript("taxilauncher"),
	new GameScript("taxiservice"),
	new GameScript("taxitutorial"),
	new GameScript("taxi_clowncar"),
	new GameScript("taxi_cutyouin"),
	new GameScript("taxi_deadline"),
	new GameScript("taxi_followcar"),
	new GameScript("taxi_gotyounow"),
	new GameScript("taxi_gotyourback"),
	new GameScript("taxi_needexcitement"),
	new GameScript("taxi_procedural"),
	new GameScript("taxi_takeiteasy"),
	new GameScript("taxi_taketobest"),
	new GameScript("tempalpha"),
	new GameScript("temptest"),
	new GameScript("tennis"),
	new GameScript("tennis_ambient"),
	new GameScript("tennis_family"),
	new GameScript("tennis_network_mp"),
	new GameScript("test_startup"),
	new GameScript("thelastone"),
	new GameScript("timershud"),
	new GameScript("title_update_registration"),
	new GameScript("tonya1"),
	new GameScript("tonya2"),
	new GameScript("tonya3"),
	new GameScript("tonya4"),
	new GameScript("tonya5"),
	new GameScript("towing"),
	new GameScript("traffickingsettings"),
	new GameScript("traffickingteleport"),
	new GameScript("traffick_air"),
	new GameScript("traffick_ground"),
	new GameScript("train_create_widget"),
	new GameScript("train_tester"),
	new GameScript("trevor1"),
	new GameScript("trevor2"),
	new GameScript("trevor3"),
	new GameScript("trevor4"),
	new GameScript("triathlonsp"),
	new GameScript("tunables_registration"),
	new GameScript("tuneables_processing"),
	new GameScript("ufo"),
	new GameScript("ugc_global_registration"),
	new GameScript("underwaterpickups"),
	new GameScript("utvc"),
	new GameScript("vehicle_ai_test"),
	new GameScript("vehicle_force_widget"),
	new GameScript("vehicle_gen_controller"),
	new GameScript("vehicle_plate"),
	new GameScript("veh_play_widget"),
	new GameScript("walking_ped"),
	new GameScript("wardrobe_mp"),
	new GameScript("wardrobe_sp"),
	new GameScript("weapon_audio_widget"),
	new GameScript("wp_partyboombox"),
	new GameScript("xml_menus"),
	new GameScript("yoga")
	
});