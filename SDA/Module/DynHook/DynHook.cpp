#include "DynHook.h"

using namespace CE::Hook::Method;
using namespace CE::Assembly;


//template<typename UserType>
//void Method2<UserType>::generateDynFuncBody()
//{
//
//}








//TODO на сегодня
/*
	1) сделать функцию хука. Сохранить аргументы. Узнать про хранение float, double, 5-ого и тд аргумента
		1.1) добавить XMM0,... поддержку регистров
	2) сделать простой фильтр. Решить как передавать аргументы в фильтр.
	3) решить как сохранять аргументы функции(все) максимально быстро в потокобезопасную очередь
	4) 


	MOVSS XMM1, dword[rax+0x2]
	movss dword ptr [rax + 0x5], xmm0

	7ff71d6c3068
*/


int zydis_show(void* ptr, ZyanUSize length)
{
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	
    ZyanU64 runtime_address = (ZyanU64)ptr;
    ZyanUSize offset = 0;

    ZydisDecodedInstruction instruction;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)((ZyanU64)ptr + offset), length - offset,
        &instruction)))
    {
        printf("%016" PRIX64 "  ", runtime_address);
		
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
            runtime_address);
        puts(buffer);

        offset += instruction.length;
        runtime_address += instruction.length;
    }
	printf("\n\n");
	return 0;
}

void test()
{
	using namespace CE::Assembly;

	BYTE storage[200];

	ByteStream bs(storage);

	{
		Block code2;
		code2	
			.beginBlock()
				.push(Register::r10)
				.pop(Register::r10)
				.mov(Register::al, 1)
				.mov(Register::ax, 1)
				.mov(Register::eax, 1)
				.mov(Register::rax, 1)
				.mov(Register::r10, 1)
				.mov(Register::r10d, 1)
				.mov(Register::r10w, 1)
				.lea(Register::rcx, Register::r8, 2)
				.mov(Register::rcx, Register::rax, 2)
				.add(Register::al, Register::r12b)
				.mov(Register::r8, -0x50, Register::rcx)
				.cmp(Register::al, Register::bl)
			.endBlock()
			.ret();

		code2.compile(bs);
		bs.debugShow();
	}
}







void module_dynhook()
{
	//using namespace CE::Assembly;
	//using namespace CE::Hook;
	//CE::Disassembler::init();
	//
	//if (false)
	//{
	//	DynHook hook(&sum, &sum_before, &sum_after);
	//	hook.setUserPtr(&hook);
	//	hook.hook();
	//	//hook.unhook();

	//	{
	//		double param2 = 3.0;
	//		float result = sum(2.0, param2, true, false, 10.0);
	//		printf("result = %f", result);
	//	}
	//}

	//byte* addr = (byte*)&sum;
	//
	//ByteStream bs(addr);
	//Label l1;
	//Label l2;

	//Block code;
	//RawBlock* codeSaved;
	//code
	//	.call(getFalse)
	//	.test(Register::al, Register::al)
	//	//.rawBlock(&codeSaved)
	//	.jnz(&l1)
	//	.mov(Register::cl, 5)
	//	.mov(Register::dl, 5)
	//	.jmp(&l2)
	//	.mov(Register::r8, Register::rsp, 2)
	//	.movss(Register::rsp, -0x28, Register::xmm1)
	//	.label(l1)
	//	.mov(Register::cl, 3)
	//	.mov(Register::dl, 3)
	//	.sub(Register::rsp, 128)
	//	.mov_ptr(Register::al, 0x123456789ABCDEF)
	//	.mov_ptr(0x123456789ABCDEF, Register::ax)
	//	.label(l2)
	//	.jmp(&sum_hook);

	////codeSaved->setData(addr, 5);

	//bs.setWriteFlag(false);
	//code.compile(bs);

	//DWORD old;
	//VirtualProtect(addr, bs.getOffset(), PAGE_EXECUTE_READWRITE, &old);

	//bs.setWriteFlag(true);
	//code.compile(bs);
	//printf("offset = %i\n", bs.getOffset());

	//VirtualProtect(addr, 6, old, &old);
	//zydis_show(&sum, bs.getOffset());


	//{
	//	double param2 = 3.0;
	//	int result = sum(2.0, param2, true, false, 0.0);
	//	printf("result = %i", result);
	//}
}