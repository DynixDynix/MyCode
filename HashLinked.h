#pragma once/*保证头文件不被重复包含*/
#include "stdafx.h"
struct Struct_Chain_Hash
{
	char*Key;
	unsigned short Key_Size;
	struct Struct_Chain_Hash*Chain_Next;
	struct Struct_Chain_Hash*Before_Chain;
	size_t Hash_Index;
	char*Data;
	unsigned Data_Size;
};

struct Struct_HashLinked_0x4
{
	Struct_HashLinked_0x4()
	{
		Initialize(100, 100);
	}
	~Struct_HashLinked_0x4()
	{
		Delete();
	}
public:
#ifdef System_Linux
	pthread_Thead_Lock_t Thead_Lock;
#else
	RTL_CRITICAL_SECTION Thead_Lock;
#endif
	Struct_Chain_Hash*Chain_Main_Array; unsigned Chain_Main_Num;
	void Initialize(unsigned SetAddHashLength, unsigned short Surplus)
	{
		/*
		参数:开始链条数量和重哈希增加链条,必定要预留的链条数量
		*/
		Delete();
		Chain_Main_Num = 0;
		Chain_Main_Used_Num = 0;
		Chain_Used_Array = 0;
		Chain_Used_Num = 0;
		ADD_HASH_LENGTH = SetAddHashLength;
		Chain_Main_SurplusNum = Surplus;
		Chain_Main_Num = ADD_HASH_LENGTH + Chain_Main_SurplusNum;
		Chain_Main_Array = (Struct_Chain_Hash*)malloc(Chain_Main_Num * sizeof(Struct_Chain_Hash));
		memset(Chain_Main_Array, 0, Chain_Main_Num * sizeof(Struct_Chain_Hash));

#ifdef System_Linux
		pthread_Thead_Lock_init(&Thead_Lock, NULL);
#else
		InitializeCriticalSection(&Thead_Lock);
#endif
	}
	void Delete()
	{
		for (size_t i = 0; i < Chain_Main_Num; i++)
		{
			Struct_Chain_Hash*Chain_Buffer = Chain_Main_Array[i].Chain_Next;
			while (Chain_Buffer)
			{
				Struct_Chain_Hash*Chain_Next = Chain_Buffer->Chain_Next;
				free(Chain_Buffer->Key);
				free(Chain_Buffer->Data);
				free(Chain_Buffer);
				Chain_Buffer = Chain_Next;
			}
			free(Chain_Main_Array[i].Key);
			Chain_Main_Array[i].Key = 0;
			Chain_Main_Array[i].Chain_Next = 0;
		}
		free(Chain_Main_Array);
#ifdef System_Linux
		pthread_Thead_Lock_init(&Thead_Lock, NULL);
#else
		DeleteCriticalSection(&Thead_Lock);
#endif
		Chain_Used_Array = 0;
		Chain_Main_Num = 0;
		Chain_Used_Num = 0;
		ADD_HASH_LENGTH = 0;
		Chain_Main_Used_Num = 0;
		Chain_Main_SurplusNum = 0;
	}
	Struct_Chain_Hash*PushChain(char Key[], unsigned short Key_Size, unsigned Data_Size)/*多线程需要加锁*/
	{
#ifdef System_Linux
		if (pthread_Thead_Lock_lock(&Thead_Lock) != 0)fprintf(stdout, "lock error!\n");
#else
		EnterCriticalSection(&Thead_Lock);
#endif
		Struct_Chain_Hash*Chain_Buffer;
		if (Chain_Main_Used_Num == Chain_Main_Num - Chain_Main_SurplusNum)/*需要重哈希*/
		{
			Struct_Chain_Hash*Chain_Used_Array = (Struct_Chain_Hash*)malloc(Chain_Used_Num * sizeof(Struct_Chain_Hash));
			memset(Chain_Used_Array, 0, Chain_Used_Num * sizeof(Struct_Chain_Hash));
			unsigned ChainNum = 0;
			unsigned i;
			/*备份之前的表*/
			for (i = 0; i < Chain_Main_Num; i++)
			{
				for (Chain_Buffer = &Chain_Main_Array[i]; Chain_Buffer; Chain_Buffer = Chain_Buffer->Chain_Next)
				{
					if (Chain_Buffer->Key)
					{
						Chain_Used_Array[ChainNum].Key = (char*)malloc(Chain_Buffer->Key_Size);
						memset(Chain_Used_Array[ChainNum].Key, 0, Chain_Buffer->Key_Size);
						memcpy(Chain_Used_Array[ChainNum].Key, Chain_Buffer->Key, Chain_Buffer->Key_Size);
						Chain_Used_Array[ChainNum].Key_Size = Chain_Buffer->Key_Size;
						Chain_Used_Array[ChainNum].Data = Chain_Buffer->Data;
						ChainNum++;
					}
				}
			}
			FreeHashLinked();
			Chain_Main_Num += ADD_HASH_LENGTH;
			Chain_Used_Num = 0;
			Chain_Main_Used_Num = 0;
			free(Chain_Main_Array);
			Chain_Main_Array = (Struct_Chain_Hash*)malloc(Chain_Main_Num * sizeof(Struct_Chain_Hash));
			memset(Chain_Main_Array, 0, Chain_Main_Num * sizeof(Struct_Chain_Hash));
			for (i = 0; i < ChainNum; i++)
			{
				Chain_Buffer = AddChain(Chain_Used_Array[i].Key, Chain_Used_Array[i].Key_Size, Data_Size);
			}
			free(Chain_Used_Array); Chain_Used_Array = 0;
		}
		Chain_Buffer = AddChain(Key, Key_Size, Data_Size);

#ifdef System_Linux
		if (pthread_Thead_Lock_unlock(&Thead_Lock) != 0)fprintf(stdout, "unlock error!\n");
#else
		LeaveCriticalSection(&Thead_Lock);
#endif
		return Chain_Buffer;
	}
	Struct_Chain_Hash*GetChainKey(char Key[], unsigned short Key_Size)
	{
#ifdef Process_X64
		Struct_Chain_Hash*Chain_Buffer = &Chain_Main_Array[MurmurHash_X64(Key, Key_Size)];/*得到链头入口*/
#else
		Struct_Chain_Hash*Chain_Buffer = &Chain_Main_Array[ELFHash(Key, Key_Size)];/*得到链头入口*/
#endif
		while (Chain_Buffer)
		{
			if (Chain_Buffer->Key_Size == Key_Size)
			{
				/*解决哈希碰撞(Key不同,映射下标相同)*/
				if (ByteMatching(Chain_Buffer->Key, Chain_Buffer->Key_Size, (char*)Key, Key_Size))return Chain_Buffer;
			}
			Chain_Buffer = Chain_Buffer->Chain_Next;
		}
		return 0;
	}
	Struct_Chain_Hash*GetChainSonkey(char Key[], unsigned short Key_Size, bool 原Key为子)/*可以判断长短不一定相同的,只要是子串即可,查询速度较慢*/
	{
		for (unsigned i = 0; i < Chain_Main_Num; i++)
		{
			Struct_Chain_Hash*Chain_Buffer = &Chain_Main_Array[i];
			while (Chain_Buffer)
			{
				if (Chain_Buffer->Key)
				{
					if (原Key为子)
					{
						if (ByteMatching(Key, Key_Size, Chain_Buffer->Key, Chain_Buffer->Key_Size))return Chain_Buffer;
					}
					else
					{
						if (ByteMatching(Chain_Buffer->Key, Chain_Buffer->Key_Size, Key, Key_Size))return Chain_Buffer;
					}
				}
				Chain_Buffer = Chain_Buffer->Chain_Next;
			}
		}
		return 0;
	}
	struct Struct_Chain_Hash*ByteMatchingChain(char*Data, unsigned Data_Size, unsigned Src_Data_Offset)
	{

		for (unsigned i = 0; i < Chain_Main_Num; i++)
		{
			Struct_Chain_Hash*Chain_Buffer = &Chain_Main_Array[i];
			while (Chain_Buffer)
			{
				if (Chain_Buffer->Data)
				{
					size_t i = 0;
					for (; i < Data_Size; i++)
					{
						if (Chain_Buffer->Data[Src_Data_Offset + i] != Data[i])
						{
							break;
						}
					}
					if (i == Data_Size)
					{
						return Chain_Buffer;
					}
				}
			}
		}
		return 0;
	}
	bool DeleteChainKey(void*Key, unsigned short Key_Size)
	{
		if (Struct_Chain_Hash *Chain_Buffer = GetChainKey((char*)Key, Key_Size))
		{
			free(Chain_Buffer->Key);
			free(Chain_Buffer->Data);
			if (Chain_Buffer->Before_Chain)/*不是链头*/
			{
				if (Chain_Buffer->Chain_Next) {/*不是链尾*/
					Chain_Buffer->Chain_Next->Before_Chain = Chain_Buffer->Before_Chain;
					Chain_Buffer->Before_Chain->Chain_Next = Chain_Buffer->Chain_Next;
				}
				else Chain_Buffer->Before_Chain->Chain_Next = 0;
				free(Chain_Buffer);
			}
			else
			{
				/*不能释放Chain_Buffer因为链头入口必须存在空间*/
				Chain_Buffer->Data = 0;
				Chain_Buffer->Key = 0;
				Chain_Buffer->Key_Size = 0;
				Chain_Main_Used_Num--;
			}
			Chain_Used_Num--;
			return true;
		}
		return false;
	}
	bool DeleteChainAdress(Struct_Chain_Hash*Chain)
	{
		free(Chain->Data);
		free(Chain->Key);
		if (Chain->Before_Chain)/*不是链头*/
		{
			if (Chain->Chain_Next) {/*不是链尾*/
				Chain->Chain_Next->Before_Chain = Chain->Before_Chain;
				Chain->Before_Chain->Chain_Next = Chain->Chain_Next;
			}
			else Chain->Before_Chain->Chain_Next = 0;
			free(Chain);
		}
		else
		{
			/*不能释放Chain_Buffer因为链头入口必须存在空间*/
			Chain->Data = 0;
			Chain->Key = 0;
			Chain->Key_Size = 0;
			Chain_Main_Used_Num--;
		}
		Chain_Used_Num--;
		return true;
	}
	void FreeHashLinked()
	{
		for (size_t i = 0; i < Chain_Main_Num; i++)
		{
			Struct_Chain_Hash*Chain_Buffer = Chain_Main_Array[i].Chain_Next;
			while (Chain_Buffer)
			{
				Struct_Chain_Hash*Chain_Next = Chain_Buffer->Chain_Next;
				free(Chain_Buffer->Key);
				free(Chain_Buffer);
				Chain_Buffer = Chain_Next;
			}
			free(Chain_Main_Array[i].Key);
			Chain_Main_Array[i].Key = 0;
			Chain_Main_Array[i].Chain_Next = 0;
		}
	}
	void Print()
	{
		printf("链头个数:%d\n", Chain_Main_Num);
		printf("使用链条个数:%d\n", Chain_Used_Num);
		printf("被使用的链头个数:%d\n", Chain_Main_Used_Num);
		for (size_t i = 0; i < Chain_Main_Num; i++)
		{
			Struct_Chain_Hash*Chain_Buffer = &Chain_Main_Array[i];
			if (Chain_Buffer->Key)printf("■%08X(%d)-> ", Chain_Buffer, *(int*)Chain_Buffer->Key);
			else printf("□%08X-> ", Chain_Buffer);
			Chain_Buffer = Chain_Buffer->Chain_Next;
			while (Chain_Buffer)
			{
				if (Chain_Buffer->Key)printf("■%08X【b:%08X】(%d)-> ", Chain_Buffer, Chain_Buffer->Before_Chain, *(int*)Chain_Buffer->Key);
				else printf("%08X【b:%08X】-> ", Chain_Buffer, Chain_Buffer->Before_Chain);
				Chain_Buffer = Chain_Buffer->Chain_Next;
			}
			printf("\n");
		}
	}
private:
	Struct_Chain_Hash*AddChain(char Key[], unsigned short Key_Size, unsigned Data_Size)
	{
		Struct_Chain_Hash*Chain_Head = 0;
#ifdef Process_X64
		size_t Index = MurmurHash_X64(Key, Key_Size);
#else
		size_t Index = ELFHash(Key, Key_Size);
#endif
		Chain_Head = &Chain_Main_Array[Index];/*得到链头入口*/
		Chain_Head->Hash_Index = Index;
		/*如果链头已经存在Key则把链头数据移到后面*/
		if (Chain_Head->Key)/*链头必须存在所以只能判断Key*/
		{
			Struct_Chain_Hash*NewChain = (Struct_Chain_Hash*)malloc(sizeof(Struct_Chain_Hash));
			memset(NewChain, 0, sizeof(Struct_Chain_Hash));
			NewChain->Key = Chain_Head->Key;
			NewChain->Key_Size = Chain_Head->Key_Size;
			NewChain->Data = Chain_Head->Data;
			NewChain->Chain_Next = Chain_Head->Chain_Next;
			NewChain->Before_Chain = Chain_Head;
			if (Chain_Head->Chain_Next)Chain_Head->Chain_Next->Before_Chain = NewChain;
			Chain_Head->Chain_Next = NewChain;
		}
		else Chain_Main_Used_Num++;
		Chain_Head->Key = (char*)malloc(Key_Size);
		Chain_Head->Key_Size = Key_Size;
		memcpy(Chain_Head->Key, Key, Chain_Head->Key_Size);
		Chain_Used_Num++;
		if (Data_Size)
		{
			Chain_Head->Data = (char*)malloc(Data_Size);
			Chain_Head->Data_Size = Data_Size;
			memset(Chain_Head->Data, 0, Data_Size);
		}
		return Chain_Head;
	}
	unsigned ELFHash(char Key[], unsigned short Key_Size)/*映射MapIndex*/
	{
		/*ELFhash强调的是每个字符都要对最后的结构有影响，所以说我们左移到一定程度是会吞掉最高的四位的，所以说我们要将最高的四位先对串产生影响，再让他被吞掉，之后的所有的影响都是叠加的，这就是多次的杂糅保证散列均匀，防止出现冲突的大量出现*/
		unsigned Hash = 0, X = 0;
		for (unsigned short i = 0; i < Key_Size; i++)
		{
			Hash = (Hash << 4) + Key[i];//hash左移4位，把当前字符ASCII存入hash低四位。 
			if ((X = Hash & 0xF0000000L)) {
				/*如果最高的四位不为0，则说明字符多余7个，现在正在存第8个字符，如果不处理，再加下一个字符时，第一个字符会被移出，因此要有如下处理。
				该处理，如果对于字符串(a-z 或者A-Z)就会仅仅影响5-8位，否则会影响5-31位，因为C语言使用的算数移位,因为1-4位刚刚存储了新加入到字符，所以不能>>28*/
				Hash ^= (X >> 24);/*影响5-8位,杂糅一次*/
				/*上面这行代码并不会对X有影响，本身X和hash的高4位相同，下面这行代码&~即对28-31(高4位)位清零*/
				Hash &= ~X;/*清空高四位(28~31位),~取反运算符*/
			}
		}
		return (Hash & 0x7FFFFFFF) % Chain_Main_Num;/*返回一个符号位为0的数，即丢弃最高位，以免函数外产生影响。(我们可以考虑，如果只有字符，符号位不可能为负)*/
	}
	unsigned int BKDRHash(char Key[], int Key_Size)
	{
		unsigned int seed = 131;
		unsigned int hash = 0;
		for (int i = 0; i < Key_Size; i++)
		{
			hash = hash * seed + (Key[i]);
		}
		return(hash % Chain_Main_Num);
	}
	unsigned long long MurmurHash_X64(const char * key, int Key_Size)
	{
		const unsigned int m = 0x5BD1E995;
		const int r = 24;
		unsigned int h1 = 3999999979/*最好是一个质数*/ ^ Key_Size;
		unsigned int h2 = 0;

		const unsigned int * data = (const unsigned int *)key;

		while (Key_Size >= 8)
		{
			unsigned int k1 = *data++;
			k1 *= m; k1 ^= k1 >> r; k1 *= m;
			h1 *= m; h1 ^= k1;
			Key_Size -= 4;

			unsigned int k2 = *data++;
			k2 *= m; k2 ^= k2 >> r; k2 *= m;
			h2 *= m; h2 ^= k2;
			Key_Size -= 4;
		}

		if (Key_Size >= 4)
		{
			unsigned int k1 = *data++;
			k1 *= m; k1 ^= k1 >> r; k1 *= m;
			h1 *= m; h1 ^= k1;
			Key_Size -= 4;
		}

		switch (Key_Size)
		{
		case 3: h2 ^= ((unsigned char*)data)[2] << 16;
		case 2: h2 ^= ((unsigned char*)data)[1] << 8;
		case 1: h2 ^= ((unsigned char*)data)[0];
			h2 *= m;
		};
		h1 ^= h2 >> 18; h1 *= m;
		h2 ^= h1 >> 22; h2 *= m;
		h1 ^= h2 >> 17; h1 *= m;
		h2 ^= h1 >> 19; h2 *= m;

		unsigned long long h = h1;

		h = (h << 32) | h2;

		return h % Chain_Main_Num;
	}
	unsigned ByteMatching(const char* Memory_Const, unsigned Memory_Const_Size, const char*Memory_Into, unsigned Memory_Into_Size)
	{
		for (size_t i = 0; i < Memory_Const_Size; i++)
		{
			for (size_t j = 0; j < Memory_Into_Size; j++)
			{
				if (Memory_Const[i + j] != Memory_Into[j])break;
				if (j == Memory_Into_Size - 1)return i + Memory_Into_Size;
			}
		}
		return 0;
	}
	unsigned Chain_Main_Used_Num;
	Struct_Chain_Hash*Chain_Used_Array; unsigned Chain_Used_Num;
	unsigned ADD_HASH_LENGTH;
	unsigned Chain_Main_SurplusNum;
}HashLinked_0x4;
