
#include <iostream>
#include "main.h"


#include "Game/ScriptEngine/Natives/NativeGroup_PLAYER.h"
#include "Core/ScriptLang/ClassBuilder.h"

int main()
{
	auto native = SE::PLAYER::FORCE_CLEANUP_FOR_ALL_THREADS_WITH_THIS_NAME;
	auto name = native.getName();
	auto sig = native.getSignature();

	auto parts = Class::Member::parseSignature(sig);

	//system("pause");
	return 0;
}