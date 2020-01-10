#pragma once

//gen
#include "Game/IGameHook.h"
#include "Game/IGameHooked.h"
#include "Game/GameHookList.h"
#include "Game/GameEvent.h"
#include "Utility/ISingleton.h"
#include "Utility/IDynStructure.h"

//d3d
#include <d3d11.h>
#include <d3d10.h>









//Present message
class GameEventD3DPresentMessage : public IGameEventMessage
{
public:
	UINT m_SyncInterval;
	UINT m_Flags;
	GameEventD3DPresentMessage(UINT SyncInterval, UINT Flags) :
		m_SyncInterval(SyncInterval), m_Flags(Flags), IGameEventMessage(GameEventMessage::GAME_D3D_PRESENT) {}
};

//Init message
class GameEventD3DInitMessage : public IGameEventMessage
{
public:
	GameEventD3DInitMessage() : IGameEventMessage(GameEventMessage::GAME_D3D_INIT) {}
};

//D3D event interface
class IGameEventD3D_Present : public IGameEventHandler
{
public:
	IGameEventD3D_Present() = default;

	bool filter(IGameEventMessage::Type &message) override {
		if (message->getMessage() == GameEventMessage::GAME_D3D_INIT || message->getMessage() == GameEventMessage::GAME_D3D_PRESENT)
			return true;
		return false;
	}

	void callback(IGameEventMessage::Type &message) override
	{
		if (!filter(message))
			return;
		if (message->getMessage() == GameEventMessage::GAME_D3D_INIT)
			OnInit();

		auto mes = (GameEventD3DPresentMessage*)message.get();
		OnPresent(mes->m_SyncInterval, mes->m_Flags);
	}
	virtual void OnPresent(UINT SyncInterval, UINT Flags) = 0;
	virtual void OnInit() {}
};





class Direct3D11 : public IGameEventPublisher<IGameEventD3D_Present>, public IGameStaticHooked
{
	friend class Direct3D11Hook_Gen;
public:
	static ID3D11DeviceContext* getDeviceContext() {
		return m_DeviceContext;
	}
	static ID3D11Device* getDevice() {
		return m_Device;
	}
	static ID3D11RenderTargetView* getRenderTargetView() {
		return m_RenderTargetView;
	}
	static IDXGISwapChain* getSwapChain() {
		return m_SwapChain;
	}
	static bool isInited() {
		return getDevice() != nullptr;
	}
private:
	static HRESULT WINAPI PresentHook(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
	{
		static bool init = false;
		if (!init) {
			if (sendEventToAll(
				IGameEventMessage::Type(new GameEventD3DInitMessage)
			)) {
				firstInit(pSwapChain);
			}
			init = true;
		}
		
		if (!sendEventToAll(std::move(
			IGameEventMessage::Type(new GameEventD3DPresentMessage(SyncInterval, Flags))
		))) {
			return 0;
		}

		return Present(pSwapChain, SyncInterval, Flags);
	}
	inline static Memory::Function<decltype(PresentHook)> Present;

	//init d3d device and context
	static void firstInit(IDXGISwapChain* pSwapChain)
	{
		m_SwapChain = pSwapChain;
		pSwapChain->GetDevice(__uuidof(m_Device), (void**)& m_Device);
		m_Device->GetImmediateContext(&m_DeviceContext);
	}

	inline static ID3D11DeviceContext*			m_DeviceContext;
	inline static ID3D11Device*					m_Device;
	inline static ID3D11RenderTargetView*		m_RenderTargetView;
	inline static IDXGISwapChain*				m_SwapChain;
};





class Direct3D11Hook_Gen : public IGameHook, public ISingleton<Direct3D11Hook_Gen>
{
public:
	class SwapChain : public Memory::IDynStructureVT<SwapChain>
	{
	public:
		enum VIRTUAL_FUNC
		{
			Present,
			vtSize
		};
		enum FIELD
		{
			VTable
		};

		static void init() {
			m_vt_offsets.reserve(2);
			setVTFieldIndex(Present, 8);

			//count of virtual functions in C lang mode
			setVTFieldIndex(vtSize, 18);
		}

		SwapChain(Memory::Handle base) : IDynStructureVT(base) {}

		//clone the virtual table
		void cloneVTable()
		{
			auto* newVTable = new std::uintptr_t[getVTableSize() / sizeof(std::uintptr_t)];
			getVTable().copyTo(newVTable, getVTableSize());
			//setFieldValue(VTable, newVTable);
			*(DWORD64*)(getBase().as<DWORD64*>()) = (DWORD64)newVTable;//todo: remove and create other
		}

		//get size in bytes
		std::size_t getVTableSize()
		{
			return getVTFieldOffset(vtSize);
		}
	};

	static HRESULT WINAPI D3D11CreateDeviceAndSwapChain_proxy(
		_In_opt_ IDXGIAdapter* pAdapter,
		D3D_DRIVER_TYPE DriverType,
		HMODULE Software,
		UINT Flags,
		_In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL* pFeatureLevels,
		UINT FeatureLevels,
		UINT SDKVersion,
		_In_opt_ CONST DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
		_COM_Outptr_opt_ IDXGISwapChain** ppSwapChain,
		_COM_Outptr_opt_ ID3D11Device** ppDevice,
		_Out_opt_ D3D_FEATURE_LEVEL* pFeatureLevel,
		_COM_Outptr_opt_ ID3D11DeviceContext** ppImmediateContext
	)
	{
		if (FAILED(D3D11CreateDeviceAndSwapChain(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext)))
		{
			return E_FAIL;
		}

		//replace the virtual table
		SwapChain swapChain = (Memory::Handle)*ppSwapChain;
		swapChain.cloneVTable();

		Direct3D11::Present = swapChain.getVirtualFunction(SwapChain::VIRTUAL_FUNC::Present);
		swapChain.setVirtualFunction(SwapChain::VIRTUAL_FUNC::Present, &Direct3D11::PresentHook);
		return S_OK;
	}



	void Install()
	{
		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("49 8B F8 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 *?? ?? ?? ?? 85 C0"),
				&D3D_Init
			)
		);

		GameHookList::Add(
			new Memory::FoundPattern(
				Memory::Pattern("89 7C 24 28 48 89 44 24 20 FF 15 *?? ?? ?? ??"),
				&CreateDeviceAndSwapChain
			)
		);
	}

	static void D3D_Init(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		Direct3D11Hook_Gen::m_init = Memory::FunctionHook<decltype(Direct3D11Hook_Gen::initHook)>(pattern.getResult().rip(4));
		Direct3D11Hook_Gen::m_init.setFunctionHook(Direct3D11Hook_Gen::initHook);
		Direct3D11Hook_Gen::m_init.hook();
	}

	static void CreateDeviceAndSwapChain(Memory::FoundPattern& pattern)
	{
		if (!pattern.hasResult()) {
			throw GameHookException(
				GAME_HOOK_EXCEPTION_STD
			);
			return;
		}

		Direct3D11Hook_Gen::m_createDeviceAndSwapChain = pattern.getResult().rip(4);
	}

	static std::uintptr_t initHook()
	{
		std::uintptr_t result = m_init.executeOrigFunc();

		//change the origin pointer to pointer to proxy
		m_createDeviceAndSwapChain = Memory::Handle(
			&D3D11CreateDeviceAndSwapChain_proxy
		).as<std::uintptr_t>();

		return result;
	}
	inline static Memory::FunctionHook<decltype(initHook)> m_init;
	inline static Memory::Object<std::uintptr_t> m_createDeviceAndSwapChain;

	void Remove()
	{
	}
};