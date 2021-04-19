#include <GUI/DecompilerDemoWindow.h>

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int, HWND&);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	// TODO: Place code here.

	// Initialize global strings
	MyRegisterClass(hInstance);

	// Perform application initialization:
	HWND hWnd;
	if (!InitInstance(hInstance, nCmdShow, hWnd))
	{
		return FALSE;
	}

	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
	ID3D11Device* m_pd3dDevice = NULL;						// Устройство (для создания объектов)
	ID3D11DeviceContext* m_pImmediateContext = NULL;		// Контекст (устройство рисования)
	IDXGISwapChain* m_pSwapChain = NULL;					// Цепь связи (буфера с экраном)
	ID3D11RenderTargetView* m_pRenderTargetView = NULL;		// Объект вида, задний буфер
	ID3D11Texture2D* m_pDepthStencil = NULL;				// Текстура буфера глубин
	ID3D11DepthStencilView* m_pDepthStencilView = NULL;		// Объект вида, буфер глубин
	D3D_DRIVER_TYPE m_driverType = D3D_DRIVER_TYPE_NULL;
	HRESULT hr = S_OK;

	RECT rc;
	GetClientRect(hWnd, &rc);
	UINT width = rc.right - rc.left;	// получаем ширину
	UINT height = rc.bottom - rc.top;	// и высоту окна

	UINT createDeviceFlags = 0;
#ifdef _DEBUG
	createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

	D3D_DRIVER_TYPE driverTypes[] =
	{
		D3D_DRIVER_TYPE_HARDWARE,
		D3D_DRIVER_TYPE_WARP,
		D3D_DRIVER_TYPE_REFERENCE,
	};
	UINT numDriverTypes = ARRAYSIZE(driverTypes);

	// Тут мы создаем список поддерживаемых версий DirectX
	D3D_FEATURE_LEVEL featureLevels[] =
	{
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0,
	};
	UINT numFeatureLevels = ARRAYSIZE(featureLevels);

	// Сейчас мы создадим устройства DirectX. Для начала заполним структуру,
	// которая описывает свойства переднего буфера и привязывает его к нашему окну.
	DXGI_SWAP_CHAIN_DESC sd;			// Структура, описывающая цепь связи (Swap Chain)
	ZeroMemory(&sd, sizeof(sd));	// очищаем ее
	sd.BufferCount = 1;					// у нас один буфер
	sd.BufferDesc.Width = width;		// ширина буфера
	sd.BufferDesc.Height = height;		// высота буфера
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;	// формат пикселя в буфере
	sd.BufferDesc.RefreshRate.Numerator = 60;			// частота обновления экрана
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;	// назначение буфера - задний буфер
	sd.OutputWindow = hWnd;							// привязываем к нашему окну
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;						// не полноэкранный режим

	for (UINT driverTypeIndex = 0; driverTypeIndex < numDriverTypes; driverTypeIndex++)
	{
		m_driverType = driverTypes[driverTypeIndex];
		hr = D3D11CreateDeviceAndSwapChain(NULL, m_driverType, NULL, createDeviceFlags, featureLevels, numFeatureLevels,
			D3D11_SDK_VERSION, &sd, &m_pSwapChain, &m_pd3dDevice, &featureLevel, &m_pImmediateContext);
		if (SUCCEEDED(hr))  // Если устройства созданы успешно, то выходим из цикла
			break;
	}
	if (FAILED(hr)) return hr;


	// Теперь создаем задний буфер. Обратите внимание, в SDK
		// RenderTargetOutput - это передний буфер, а RenderTargetView - задний.
		// Извлекаем описание заднего буфера
	ID3D11Texture2D* pBackBuffer = NULL;
	hr = m_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)&pBackBuffer);
	if (FAILED(hr)) return hr;

	// По полученному описанию создаем поверхность рисования
	hr = m_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &m_pRenderTargetView);
	pBackBuffer->Release();
	if (FAILED(hr)) return hr;


	// Переходим к созданию буфера глубин
		// Создаем текстуру-описание буфера глубин
	D3D11_TEXTURE2D_DESC descDepth;	// Структура с параметрами
	ZeroMemory(&descDepth, sizeof(descDepth));
	descDepth.Width = width;		// ширина и
	descDepth.Height = height;		// высота текстуры
	descDepth.MipLevels = 1;		// уровень интерполяции
	descDepth.ArraySize = 1;
	descDepth.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;	// формат (размер пикселя)
	descDepth.SampleDesc.Count = 1;
	descDepth.SampleDesc.Quality = 0;
	descDepth.Usage = D3D11_USAGE_DEFAULT;
	descDepth.BindFlags = D3D11_BIND_DEPTH_STENCIL;		// вид - буфер глубин
	descDepth.CPUAccessFlags = 0;
	descDepth.MiscFlags = 0;
	// При помощи заполненной структуры-описания создаем объект текстуры
	hr = m_pd3dDevice->CreateTexture2D(&descDepth, NULL, &m_pDepthStencil);
	if (FAILED(hr)) return hr;

	// Теперь надо создать сам объект буфера глубин
	D3D11_DEPTH_STENCIL_VIEW_DESC descDSV;	// Структура с параметрами
	ZeroMemory(&descDSV, sizeof(descDSV));
	descDSV.Format = descDepth.Format;		// формат как в текстуре
	descDSV.ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D;
	descDSV.Texture2D.MipSlice = 0;
	// При помощи заполненной структуры-описания и текстуры создаем объект буфера глубин
	hr = m_pd3dDevice->CreateDepthStencilView(m_pDepthStencil, &descDSV, &m_pDepthStencilView);
	if (FAILED(hr)) return hr;

	// Подключаем объект заднего буфера и объект буфера глубин к контексту устройства
	m_pImmediateContext->OMSetRenderTargets(1, &m_pRenderTargetView, m_pDepthStencilView);


	// our gui app
	GUI::GUI gui;
	gui.m_windowManager->addWindow(new GUI::DecompilerDemoWindow);
	gui.init(hWnd, m_pd3dDevice, m_pImmediateContext);


	MSG msg;
	// Main message loop:
	while (GetMessage(&msg, nullptr, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);

		static ULONGLONG prevTime;
		ULONGLONG curTime = GetTickCount64();
		if (curTime - prevTime > 1000 / 60) {
			float ClearColor[4] = { 0.0f, 0.0f, 1.0f, 1.0f };
			m_pImmediateContext->ClearRenderTargetView(m_pRenderTargetView, ClearColor);
			gui.render();
			m_pSwapChain->Present(0, 0);
		}
	}

	return (int)msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex = {};

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.hInstance = hInstance;
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszClassName = L"Main";

	return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow, HWND& hWnd)
{
	int width = 1280;
	int height = 720;

	RECT rc = { 0, 0, width, height };
	AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
	hWnd = CreateWindowW(L"Main", L"SDA", WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInstance, nullptr);

	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	// UpdateWindow(hWnd);

	return TRUE;
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, message, wParam, lParam)) {
		return 0;
	}

	switch (message)
	{
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code that uses hdc here...
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}

	return DefWindowProc(hWnd, message, wParam, lParam);
}