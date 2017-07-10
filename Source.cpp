#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include <windows.h>

TCHAR szClassName[] = TEXT("Window");

BOOL GetPEHeader(HWND hEdit, LPTSTR lpszFilePath)
{
	SetWindowText(hEdit, 0);
	HANDLE hFile = CreateFile(lpszFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return FALSE;
	}
	BOOL bReturn = FALSE;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)dosHeader + (DWORD_PTR)dosHeader->e_lfanew);
		if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			TCHAR szText[1024];
			PIMAGE_FILE_HEADER pImageFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
			wsprintf(szText, TEXT("Machine : %d\r\n"), pImageFileHeader->Machine);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("NumberOfSections : %d\r\n"), pImageFileHeader->NumberOfSections);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("TimeDateStamp : %d\r\n"), pImageFileHeader->TimeDateStamp);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("PointerToSymbolTable : %d\r\n"), pImageFileHeader->PointerToSymbolTable);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("NumberOfSymbols : %d\r\n"), pImageFileHeader->NumberOfSymbols);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfOptionalHeader : %d\r\n"), pImageFileHeader->SizeOfOptionalHeader);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("Characteristics : %d\r\n"), pImageFileHeader->Characteristics);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			PIMAGE_OPTIONAL_HEADER pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;
			wsprintf(szText, TEXT("Magic : %d\r\n"), pImageOptionalHeader->Magic);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MajorLinkerVersion : %d\r\n"), pImageOptionalHeader->MajorLinkerVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MinorLinkerVersion : %d\r\n"), pImageOptionalHeader->MinorLinkerVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfCode : %d\r\n"), pImageOptionalHeader->SizeOfCode);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfInitializedData : %d\r\n"), pImageOptionalHeader->SizeOfInitializedData);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfUninitializedData : %d\r\n"), pImageOptionalHeader->SizeOfUninitializedData);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("AddressOfEntryPoint : %d\r\n"), pImageOptionalHeader->AddressOfEntryPoint);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("BaseOfCode : %d\r\n"), pImageOptionalHeader->BaseOfCode);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
#ifndef _WIN64
			wsprintf(szText, TEXT("BaseOfData : %d\r\n"), pImageOptionalHeader->BaseOfData);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
#endif
			wsprintf(szText, TEXT("ImageBase : %d\r\n"), pImageOptionalHeader->ImageBase);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SectionAlignment : %d\r\n"), pImageOptionalHeader->SectionAlignment);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("FileAlignment : %d\r\n"), pImageOptionalHeader->FileAlignment);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MajorOperatingSystemVersion : %d\r\n"), pImageOptionalHeader->MajorOperatingSystemVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MinorOperatingSystemVersion : %d\r\n"), pImageOptionalHeader->MinorOperatingSystemVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MajorImageVersion : %d\r\n"), pImageOptionalHeader->MajorImageVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MinorImageVersion : %d\r\n"), pImageOptionalHeader->MinorImageVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MajorSubsystemVersion : %d\r\n"), pImageOptionalHeader->MajorSubsystemVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("MinorSubsystemVersion : %d\r\n"), pImageOptionalHeader->MinorSubsystemVersion);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("Win32VersionValue : %d\r\n"), pImageOptionalHeader->Win32VersionValue);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfImage : %d\r\n"), pImageOptionalHeader->SizeOfImage);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfHeaders : %d\r\n"), pImageOptionalHeader->SizeOfHeaders);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("CheckSum : %d\r\n"), pImageOptionalHeader->CheckSum);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("Subsystem : %d\r\n"), pImageOptionalHeader->Subsystem);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("DllCharacteristics : %d\r\n"), pImageOptionalHeader->DllCharacteristics);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfStackReserve : %d\r\n"), pImageOptionalHeader->SizeOfStackReserve);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfStackCommit : %d\r\n"), pImageOptionalHeader->SizeOfStackCommit);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfHeapReserve : %d\r\n"), pImageOptionalHeader->SizeOfHeapReserve);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("SizeOfHeapCommit : %d\r\n"), pImageOptionalHeader->SizeOfHeapCommit);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("LoaderFlags : %d\r\n"), pImageOptionalHeader->LoaderFlags);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			wsprintf(szText, TEXT("NumberOfRvaAndSizes : %d\r\n"), pImageOptionalHeader->NumberOfRvaAndSizes);
			SendMessage(hEdit, EM_REPLACESEL, 0, (LPARAM)szText);
			bReturn = TRUE;
		}
	}
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return bReturn;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEdit;
	switch (msg)
	{
	case WM_CREATE:
		hEdit = CreateWindow(TEXT("EDIT"), TEXT("ここにモジュールをドラッグ＆ドロップ"), WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_READONLY, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		DragAcceptFiles(hWnd, TRUE);
		break;
	case WM_SIZE:
		MoveWindow(hEdit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
		break;
	case WM_DROPFILES:
		{
			const UINT iFileNum = DragQueryFile((HDROP)wParam, -1, NULL, 0);
			if (iFileNum == 1)
			{
				TCHAR szFilePath[MAX_PATH];
				DragQueryFile((HDROP)wParam, 0, szFilePath, MAX_PATH);
				GetPEHeader(hEdit, szFilePath);
			}
			DragFinish((HDROP)wParam);
		}
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		0,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		(HBRUSH)(COLOR_WINDOW + 1),
		0,
		szClassName
	};
	RegisterClass(&wndclass);
	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("PE ヘッダーの情報を取得"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		0,
		CW_USEDEFAULT,
		0,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return (int)msg.wParam;
}





























































