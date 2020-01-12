#pragma once


#include "Game/GameInput.h"
#include "Game/DirectX/Direct3D11.h"
#include "Game/ScriptEngine/GameScriptEngine.h"
#include "ScriptManager.h"
#include "SDK/SDK.h"


class ContextUpdateMessage : public IGameEventMessage
{
public:
	IGameScriptContext* m_context;
	ContextUpdateMessage(IGameScriptContext* context)
		: m_context(context), IGameEventMessage(GameEventMessageId::CONTEXT_UPDATER)
	{}
};

class IScriptLangContext
	: public IGameScriptContext, public IGameEventPublisher<IScriptLangContext>
{
public:
	IScriptLangContext(std::shared_ptr<Script::Mod> mod)
		: m_mod(mod)
	{
		addConsoleMessage("the script directory is " + mod->getDirectory().getPath());
		addConsoleMessage("the config file is " + mod->getConfigFile().getFullname());
		addConsoleMessage("the entry point is " + mod->getMainExecutionFile().getFullname() + " / " + mod->getEntryFunction());
	}

	virtual void OnInit() {
		GameScriptEngine::registerScriptExecutingContext(this);
	}

	void OnTick() override {
		if (!sendEventToAll(
			IGameEventMessage::Type(new ContextUpdateMessage(this))
		)) {}
	}

	virtual void OnAnyCallback(void* externalPtr, std::string name, Class::Adapter::ICallback* callback) = 0;

	Script::Mod* getScriptMod() {
		return m_mod.get();
	}

	std::shared_ptr<Script::Mod>& getScriptModShrPtr() {
		return m_mod;
	}
protected:
	std::shared_ptr<Script::Mod> m_mod = nullptr;
};

namespace ScriptContextCallback
{
	class DoCallback
	{
	protected:
		DoCallback(IScriptLangContext* scriptContext, void* externalPtr)
			: m_scriptContext(scriptContext), m_externalPtr(externalPtr)
		{}

		template<typename... params>
		void doCallback(std::string name, std::tuple<params...> params) {
			Class::Adapter::Callback callback(params);
			getScriptContext()->OnAnyCallback(m_externalPtr, name, &callback);
		}
	public:
		IScriptLangContext* getScriptContext() {
			return m_scriptContext;
		}
	private:
		void* m_externalPtr;
		IScriptLangContext* m_scriptContext;
	};

	template<typename T>
	class IScriptLangContextCallback : public GameEventProxyHandler<T>, public DoCallback
	{
	public:
		IScriptLangContextCallback(IScriptLangContext* scriptContext, void* externalPtr)
			: DoCallback(scriptContext, externalPtr)
		{
			GameEventProxyHandler<T>::setProxyMessageAgregator(scriptContext->getProxyAgregator());
		}
	};

	class Direct3D_PresentHandler : public IScriptLangContextCallback<IGameEventD3D_Present>
	{
	public:
		Direct3D_PresentHandler(IScriptLangContext* scriptContext, void* externalPtr)
			: IScriptLangContextCallback<IGameEventD3D_Present>(scriptContext, externalPtr) {}
		
		void OnInit() override {
			doCallback("onInit", std::make_tuple(1));
		}

		void OnPresent(UINT SyncInterval, UINT Flags) override {
			doCallback("onPresent", std::make_tuple(SyncInterval, Flags));
		}
	};

	class InputHandler : public IScriptLangContextCallback<IGameEventInput>
	{
	public:
		InputHandler(IScriptLangContext* scriptContext, void* externalPtr)
			: IScriptLangContextCallback<IGameEventInput>(scriptContext, externalPtr) {}
		
		void keyUp(KEY keyCode) override {
			doCallback("keyUp", std::make_tuple((int)keyCode));
		}

		void keyDown(KEY keyCode) override {
			doCallback("keyDown", std::make_tuple((int)keyCode));
		}

		void mLeftBtnDblClick() override {
			doCallback("mLeftBtnDblClick", std::make_tuple(1));
		}

		void mRightBtnDblClick() override {
			doCallback("mRightBtnDblClick", std::make_tuple(1));
		}

		void mLeftBtnDown() override {
			doCallback("mLeftBtnDown", std::make_tuple(1));
		}

		void mLeftBtnUp() override {
			doCallback("mLeftBtnUp", std::make_tuple(1));
		}

		void mMiddleBtnDown() override {
			doCallback("mMiddleBtnDown", std::make_tuple(1));
		}

		void mMiddleBtnUp() override {
			doCallback("mMiddleBtnUp", std::make_tuple(1));
		}

		void mRightBtnDown() override {
			doCallback("mRightBtnDown", std::make_tuple(1));
		}

		void mRightBtnUp() override {
			doCallback("mRightBtnUp", std::make_tuple(1));
		}

		void mMove(short x, short y) override {
			doCallback("mMove", std::make_tuple(x, y));
		}

		void mWheel(short delta) override {
			doCallback("mWheel", std::make_tuple(delta));
		}
	};

	class ContextUpdater : public IGameEventHandler, protected DoCallback
	{
	public:
		ContextUpdater(IScriptLangContext* scriptContext, void* externalPtr)
			: DoCallback(scriptContext, externalPtr)
		{}

		bool filter(IGameEventMessage::Type& message) override {
			if (message->getMessageId() != GameEventMessageId::CONTEXT_UPDATER)
				return false;
			if (((ContextUpdateMessage*)message.get())->m_context != getScriptContext())
				return false;

			return true;
		}

		void callback(IGameEventMessage::Type& message, bool& result, bool& doContinue) override
		{
			if (!filter(message))
				return;
			doCallback("upd", std::make_tuple(1));
		}
	};

	static IGameEventHandler* createEventListenerByName(IScriptLangContext* scriptContext, void* externalPtr, std::string name)
	{
		static std::map<std::string, std::function<IGameEventHandler* (IScriptLangContext*, void*)>> items =
		{
			{
				"KeyInput", [](IScriptLangContext* ctx, void* ptr) {
					return new InputHandler(ctx, ptr);
				}
			},

			{
				"Update", [](IScriptLangContext* ctx, void* ptr) {
					return new ContextUpdater(ctx, ptr);
				}
			},

			{
				"Direct3D", [](IScriptLangContext* ctx, void* ptr) {
					return new Direct3D_PresentHandler(ctx, ptr);
				}
			}
		};

		if (items.find(name) == items.end()) {
			//throw ex
		}
		
		scriptContext->addConsoleMessage("the listener " + name + " has been registered by a script.");
		return items[name](scriptContext, externalPtr);
	}
};