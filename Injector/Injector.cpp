// Injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <custom/codepage.hpp>
#include <iostream>
#include "Injector.hpp"
#include <vector>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
using namespace std;

void copy_folder(const path& source, const path& target)
{
	create_directories(target);
	for(recursive_directory_iterator itr(source); decltype(itr)() != itr; ++itr)
	{
		path p = target / path(itr->path().string().substr(source.string().length() + 1));
		if(false == is_directory(itr->path()))
			copy_file(itr->path(), p, copy_options::overwrite_existing);
		else
			create_directories(p);
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	wstring fileName;
	string sfileName;
	getline(cin, sfileName);
	fileName = codepage::acp_to_unicode(sfileName);
	boost::replace_all(fileName, L"\"", L"");
	Injector::inject(fileName, "monitor.dll");
	wchar_t monitorFolder[MAX_PATH];
	GetModuleFileNameW(nullptr, monitorFolder, _countof(monitorFolder));
	PathRemoveFileSpecW(monitorFolder);
	PathCombineW(monitorFolder, monitorFolder, L"monitor");
	copy_folder(monitorFolder, path(fileName).parent_path() / path(L"monitor"));
	return 0;
}

