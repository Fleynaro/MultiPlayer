#pragma once


#include "../NativeCaller.h"


namespace SDK::ANIM {

	enum class Flags : DWORD
	{
		None = 0,
		Loop = 1,
		StayInEndFrame = 2,
		UpperBodyOnly = 16,
		AllowRotation = 32,
		CancelableWithMovement = 128,
		RagdollOnCollision = 4194304
	};

	class Anim : public Class::IExportable<Anim>
	{
	public:
		struct Config : public Class::IExportable<Config> {
			//for export
			Config* getPersistent() override {
				return Config::constructor(m_fInSpeed, m_fOutSpeed, m_Duration, m_flags, m_fPlaybackRate);
			}

			static Config* constructor(float fInSpeed, float fOutSpeed, int Duration, Flags flags, float fPlaybackRate) {
				return new Config(fInSpeed, fOutSpeed, Duration, flags, fPlaybackRate);
			}
			
			float m_fPlaybackRate;
			float m_fInSpeed;
			float m_fOutSpeed;
			int m_Duration;
			Flags m_flags;

			///<summary></summary>
			Config(float fInSpeed = 0.f, float fOutSpeed = 0.f, int Duration = 0, Flags flags = Flags::None, float fPlaybackRate = 0.f)
				:
				m_fInSpeed(fInSpeed),
				m_fOutSpeed(fOutSpeed),
				m_Duration(Duration),
				m_flags(flags),
				m_fPlaybackRate(fPlaybackRate)
			{};
		};

		//for export
		Anim* getPersistent() override {
			return Anim::constructor(getDict(), getName());
		}

		static Anim* constructor(std::string animDict, std::string animName) {
			return new Anim(animDict, animName);
		}

		Anim() = default;

		Anim(std::string animDict, std::string animName)
			:
			m_animDict(animDict),
			m_animName(animName)
		{};

		///<summary></summary>
		Anim& setConfig(Config cfg) {
			m_fInSpeed = cfg.m_fInSpeed;
			m_fOutSpeed = cfg.m_fOutSpeed;
			m_Duration = cfg.m_Duration;
			m_flags = cfg.m_flags;
			m_fPlaybackRate = cfg.m_fPlaybackRate;
			return *this;
		}

		///<summary></summary>
		Anim& setPlaybackRate(float amount) {
			m_fPlaybackRate = amount;
			return *this;
		}

		///<summary></summary>
		Anim& setInSpeed(float fInSpeed) {
			m_fInSpeed = fInSpeed;
			return *this;
		}

		///<summary></summary>
		Anim& setOutSpeed(float fOutSpeed) {
			m_fOutSpeed = fOutSpeed;
			return *this;
		}

		///<summary></summary>
		Anim& setSpeed(float fSpeed) {
			setInSpeed(fSpeed);
			setOutSpeed(-fSpeed);
			return *this;
		}

		///<summary></summary>
		Anim& setDuration(int Duration) {
			m_Duration = Duration;
			return *this;
		}

		///<summary></summary>
		Anim& setFlags(Flags flags) {
			m_flags = flags;
			return *this;
		}

		///<summary></summary>
		float getPlaybackRate() {
			return m_fPlaybackRate;
		}

		///<summary></summary>
		float getInSpeed() {
			return m_fInSpeed;
		}

		///<summary></summary>
		float getOutSpeed() {
			return m_fOutSpeed;
		}

		///<summary></summary>
		float getSpeed() {
			return getInSpeed();
		}

		///<summary></summary>
		int getDuration() {
			return m_Duration;
		}

		///<summary></summary>
		Flags getFlags() {
			return m_flags;
		}

		///<summary></summary>
		std::string getName() {
			return m_animName;
		}

		///<summary></summary>
		std::string getDict() {
			return m_animDict;
		}
	private:
		float m_fPlaybackRate = 0.0;
		float m_fInSpeed = 8.f;
		float m_fOutSpeed = -8.f;
		int m_Duration = -1;
		Flags m_flags = Flags::None;
		std::string m_animName;
		std::string m_animDict;
	};

	class Dict : public Class::IExportable<Dict>
	{
	public:
		//for export
		Dict* getPersistent() override {
			return Dict::constructor(getPath());
		}

		static Dict* constructor(std::string path) {
			return new Dict(path);
		}

		Dict() {}
		Dict(std::string path)
			: m_path(path)
		{}

		///<summary></summary>
		Dict operator [](std::string path) {
			return Dict(
				m_path + ('@' + path)
			);
		}

		///<summary></summary>
		Anim get(std::string name) {
			return Anim(
				getPath(),
				name
			);
		}

		///<summary></summary>
		std::string getPath() {
			return m_path;
		}

		///<summary></summary>
		bool isLoaded() {
			return Call(
				SE::STREAMING::HAS_ANIM_DICT_LOADED,
				getPath().c_str()
			);
		}

		///<summary></summary>
		bool isValid() {
			return Call(
				SE::STREAMING::DOES_ANIM_DICT_EXIST,
				getPath().c_str()
			);
		}

		///<summary></summary>
		void request() {
			Call(
				SE::STREAMING::REQUEST_ANIM_DICT,
				getPath().c_str()
			);
		}

		///<summary></summary>
		bool load(std::size_t timeout = 2000) {
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
	private:
		std::string m_path;
	};


	///<summary>create a new animation object</summary>
	static Anim NEW(Dict dict, std::string anim) {
		return Anim(dict.getPath(), anim);
	}

	//standart config for animations
	inline static Anim::Config CFG_Standart(
		8.f, 10.f, -1, Flags::None, -8.f
	);
	
	//weapon anim dictionary
	inline static Dict weapons("weapons");
	//
	inline static Dict amb("amb");
	//
	inline static Dict heists("anim@heists");
};