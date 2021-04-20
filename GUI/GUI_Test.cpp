// GUI.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include <iostream>
#include <winsock2.h>
#include <immintrin.h>
#include <d3d11.h>
#include "GUI_Test.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int, HWND&);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_GUI, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
	HWND hWnd;
    if (!InitInstance (hInstance, nCmdShow, hWnd))
    {
        return FALSE;
    }

	D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
	ID3D11Device* m_pd3dDevice = NULL;						// ���������� (��� �������� ��������)
	ID3D11DeviceContext* m_pImmediateContext = NULL;		// �������� (���������� ���������)
	IDXGISwapChain* m_pSwapChain = NULL;					// ���� ����� (������ � �������)
	ID3D11RenderTargetView* m_pRenderTargetView = NULL;		// ������ ����, ������ �����
	ID3D11Texture2D* m_pDepthStencil = NULL;				// �������� ������ ������
	ID3D11DepthStencilView* m_pDepthStencilView = NULL;		// ������ ����, ����� ������
	D3D_DRIVER_TYPE m_driverType = D3D_DRIVER_TYPE_NULL;
	HRESULT hr = S_OK;

	RECT rc;
	GetClientRect(hWnd, &rc);
	UINT width = rc.right - rc.left;	// �������� ������
	UINT height = rc.bottom - rc.top;	// � ������ ����

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

	// ��� �� ������� ������ �������������� ������ DirectX
	D3D_FEATURE_LEVEL featureLevels[] =
	{
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0,
	};
	UINT numFeatureLevels = ARRAYSIZE(featureLevels);

	// ������ �� �������� ���������� DirectX. ��� ������ �������� ���������,
	// ������� ��������� �������� ��������� ������ � ����������� ��� � ������ ����.
	DXGI_SWAP_CHAIN_DESC sd;			// ���������, ����������� ���� ����� (Swap Chain)
	ZeroMemory(&sd, sizeof(sd));	// ������� ��
	sd.BufferCount = 1;					// � ��� ���� �����
	sd.BufferDesc.Width = width;		// ������ ������
	sd.BufferDesc.Height = height;		// ������ ������
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;	// ������ ������� � ������
	sd.BufferDesc.RefreshRate.Numerator = 60;			// ������� ���������� ������
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;	// ���������� ������ - ������ �����
	sd.OutputWindow = hWnd;							// ����������� � ������ ����
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;						// �� ������������� �����

	for (UINT driverTypeIndex = 0; driverTypeIndex < numDriverTypes; driverTypeIndex++)
	{
		m_driverType = driverTypes[driverTypeIndex];
		hr = D3D11CreateDeviceAndSwapChain(NULL, m_driverType, NULL, createDeviceFlags, featureLevels, numFeatureLevels,
			D3D11_SDK_VERSION, &sd, &m_pSwapChain, &m_pd3dDevice, &featureLevel, &m_pImmediateContext);
		if (SUCCEEDED(hr))  // ���� ���������� ������� �������, �� ������� �� �����
			break;
	}
	if (FAILED(hr)) return hr;


	// ������ ������� ������ �����. �������� ��������, � SDK
		// RenderTargetOutput - ��� �������� �����, � RenderTargetView - ������.
		// ��������� �������� ������� ������
	ID3D11Texture2D* pBackBuffer = NULL;
	hr = m_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (LPVOID*)& pBackBuffer);
	if (FAILED(hr)) return hr;

	// �� ����������� �������� ������� ����������� ���������
	hr = m_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &m_pRenderTargetView);
	pBackBuffer->Release();
	if (FAILED(hr)) return hr;


	// ��������� � �������� ������ ������
		// ������� ��������-�������� ������ ������
	D3D11_TEXTURE2D_DESC descDepth;	// ��������� � �����������
	ZeroMemory(&descDepth, sizeof(descDepth));
	descDepth.Width = width;		// ������ �
	descDepth.Height = height;		// ������ ��������
	descDepth.MipLevels = 1;		// ������� ������������
	descDepth.ArraySize = 1;
	descDepth.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;	// ������ (������ �������)
	descDepth.SampleDesc.Count = 1;
	descDepth.SampleDesc.Quality = 0;
	descDepth.Usage = D3D11_USAGE_DEFAULT;
	descDepth.BindFlags = D3D11_BIND_DEPTH_STENCIL;		// ��� - ����� ������
	descDepth.CPUAccessFlags = 0;
	descDepth.MiscFlags = 0;
	// ��� ������ ����������� ���������-�������� ������� ������ ��������
	hr = m_pd3dDevice->CreateTexture2D(&descDepth, NULL, &m_pDepthStencil);
	if (FAILED(hr)) return hr;

	// ������ ���� ������� ��� ������ ������ ������
	D3D11_DEPTH_STENCIL_VIEW_DESC descDSV;	// ��������� � �����������
	ZeroMemory(&descDSV, sizeof(descDSV));
	descDSV.Format = descDepth.Format;		// ������ ��� � ��������
	descDSV.ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D;
	descDSV.Texture2D.MipSlice = 0;
	// ��� ������ ����������� ���������-�������� � �������� ������� ������ ������ ������
	hr = m_pd3dDevice->CreateDepthStencilView(m_pDepthStencil, &descDSV, &m_pDepthStencilView);
	if (FAILED(hr)) return hr;

	// ���������� ������ ������� ������ � ������ ������ ������ � ��������� ����������
	m_pImmediateContext->OMSetRenderTargets(1, &m_pRenderTargetView, m_pDepthStencilView);


	// our gui app
	GUI::GUI gui;
	gui.m_windowManager->addWindow(new GUI::GuiDemoWindow);
	gui.init(hWnd, m_pd3dDevice, m_pImmediateContext);


    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_GUI));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
		}

		static ULONGLONG prevTime;
		ULONGLONG curTime = GetTickCount64();
		if (curTime - prevTime > 1000 / 60) {
			float ClearColor[4] = { 0.0f, 0.0f, 1.0f, 1.0f };
			m_pImmediateContext->ClearRenderTargetView(m_pRenderTargetView, ClearColor);
			gui.render();
			m_pSwapChain->Present(0, 0);
		}
    }

    return (int) msg.wParam;
}


//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_GUI));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = NULL;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow, HWND& hWnd)
{
	int width = 1280;
	int height = 720;

   hInst = hInstance; // Store instance handle in our global variable

   RECT rc = { 0, 0, width, height };
   AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);
   hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, rc.right - rc.left, rc.bottom - rc.top, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
  // UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hWnd, message, wParam, lParam)) {
		return 0;
	}

    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
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
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
