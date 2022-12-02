/*
当前版本调用标准:
--------------------------------------------------------------------------------------------------------------------------------
|---| 完成后可读次数 | 完成后可写次数 | 写后立即ColoseSocket | ConnectEx后立即读写 | 服务端连接IO数量 | 多次投递IO参数互不影响 |
--------------------------------------------------------------------------------------------------------------------------------
|TCP|      无限      |      无限      |          √          |          ×         |       65535      |           √           |
--------------------------------------------------------------------------------------------------------------------------------
|UDP|      无限      |      无限      |          √          |          √         |         1        |           ×           |
--------------------------------------------------------------------------------------------------------------------------------
|SSL|      一次      |      无限      |          ×          |          ×         |       65535      |           √           |
--------------------------------------------------------------------------------------------------------------------------------
*/
#pragma once
#include "stdafx.h"
#include "HashLinked.h"
#include "Encode.h"
#pragma warning(disable: 4996)


#define IPPROTO_SSL 10

#define IO_State_Post 999
#define IO_State_ConnectEx 1
#define IO_State_DisconnectEx 2
#define IO_State_NewClient 3
#define IO_State_Read 4
#define IO_State_Write 5
#define IO_State_Error 6
#define IO_State_Read_Keep 7

#define IO_State_Handshaking_Write_SSL 8
#define IO_State_Handshaking_Read_SSL 9
#define IO_State_Handshaked_Read_SSL 10
#define IO_State_Handshaked_Write_SSL 11
#define IO_State_Handshaked_SSL 12
#define SLL_Handshaking_Read_Size 8192



#ifdef Use_OpenSSL 
struct Struct_BIO
{
	BIO*BIO_Write;
	BIO*BIO_Read;
};
BIO*ErrBio;
#endif

struct Struct_IOCP_IO
{
	OVERLAPPED OVER_LAPPED;
	SOCKET Socket;
	WSABUF WSABuffer;
	SOCKADDR_IN Sockaddr_in;
	Struct_IOCP_IO*IO_Server;
	void* Custom_P;
	void* Custom_P_2;
	void* Custom_P_3;
	char IO_State;
	char IO_State_Error_Before;
	char IO_Type;/*留给外部使用*/
	char IO_Type_Custom;/*留给外部使用*/
	char IO_State_Delivery;/*留给外部使用*/

	UINT8 Protocol;
	HANDLE HTimer;
	DWORD Read_Time;
#ifdef Use_OpenSSL 
	SSL*Socket_SSL;
	SSL_CTX*SSL_Ctx;
	Struct_BIO*BIO;
#endif
};
struct Struct_IOCP_Return
{
	OVERLAPPED*OVER_LAPPED_P;
	Struct_IOCP_IO*IOCP_IO;
	Struct_IOCP_IO*IO_Server;
	int Complete_Size;
	INT Error_Cede;
};

DWORD Complete_Index;
HANDLE IOCP_Handle;
WSADATA IOCP_WSAData;
hostent*主机信息结构;
GUID DisconnectEx_GUID;
GUID ConnectEx_GUID;
GUID AcceptEx_GUID;
GUID GetAcceptExSockAddrs_GUID;
LPFN_DISCONNECTEX DisconnectEx;
LPFN_CONNECTEX ConnectEx;
LPFN_ACCEPTEX IOCP_AcceptEx;
LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockAddrs;
int Lock_SSL_Number;
RTL_CRITICAL_SECTION*Lock_SSL;
struct CRYPTO_dynlock_value
{
	RTL_CRITICAL_SECTION lock;
};

Struct_HashLinked_0x4 Hash_UDP_Server;
Struct_HashLinked_0x4 Hash_UDP_IO;
int(*UDP_Close_CallBack)(Struct_IOCP_IO*IO) = 0;
volatile long 次数 = 0;
class Class_IOCP_0x12
{
	Class_IOCP_0x12()
	{
		Initialization();
	}
	~Class_IOCP_0x12()
	{
		Deconstruction();
	}
public:
	static void Set_UDP_Close_CallBack(VOID*Call)/*如果要使用WriteStr则必须返回真,否则可能写入不成功*/
	{
		UDP_Close_CallBack = (int(*)(Struct_IOCP_IO*IO))Call;
	}
	static void Initialization()
	{
		int Code = WSAStartup(MAKEWORD(2, 2), &IOCP_WSAData);/*启动网络*/
		if (Code != 0)
		{
			printf("启动网络错误%d\n", Code);
			/*MAKEWORD(2,2)表示使用WINSOCK2版本.IOCP_WSAData用来存储系统传回的关于WINSOCK的资料*/
		}
		IOCP_Handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (!IOCP_Handle)
		{
			printf("初始化完成端口失败,错误代码:%d\n", WSAGetLastError());
		}
		/*=========================================================================================*/
		SOCKET Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);/*单纯用于获取函数指针*/

		DisconnectEx_GUID = WSAID_DISCONNECTEX;
		ConnectEx_GUID = WSAID_CONNECTEX;
		AcceptEx_GUID = WSAID_ACCEPTEX;
		GetAcceptExSockAddrs_GUID = WSAID_GETACCEPTEXSOCKADDRS;

		DWORD dwBytes = NULL;
		if (SOCKET_ERROR == WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &ConnectEx_GUID, sizeof(ConnectEx_GUID),
			&ConnectEx, sizeof(ConnectEx), &dwBytes, 0, 0))
		{
			printf("未能获取ConnectEx函数指针,错误代码:%d\n", WSAGetLastError());
		}

		if (SOCKET_ERROR == WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&DisconnectEx_GUID, sizeof(DisconnectEx_GUID), &DisconnectEx, sizeof(DisconnectEx), &dwBytes, NULL, NULL))
		{
			printf("未能获取DisconnectEx函数指针,错误代码:%d\n", WSAGetLastError());
		}

		if (SOCKET_ERROR == WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &AcceptEx_GUID,/*需要查看*/
			sizeof(AcceptEx_GUID), &IOCP_AcceptEx, sizeof(IOCP_AcceptEx), &dwBytes, NULL, NULL))
		{
			printf("未能获取AcceptEx函数指针,错误代码:%d\n", WSAGetLastError());
		}
		/*=============================================================================================*/
		if (SOCKET_ERROR == WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &GetAcceptExSockAddrs_GUID,
			sizeof(GetAcceptExSockAddrs_GUID),
			&GetAcceptExSockAddrs,
			sizeof(GetAcceptExSockAddrs),
			&dwBytes,
			NULL,
			NULL))
		{
			printf("未能获取GuidGetAcceptExSockAddrs函数指针,错误代码:%d\n", WSAGetLastError());
		}
		closesocket(Socket);
		Socket = INVALID_SOCKET;
#ifdef Use_OpenSSL 
		SSL_Load();
#endif
	}
	static void Deconstruction()
	{
#ifdef Use_OpenSSL 
		Free_SSL();
#endif
		/*缺少data释放*/
		WSACleanup();/*关闭网络,终止soke2.DLL*/
		CloseHandle(IOCP_Handle);
		//PostQueuedCompletionStatus(IOCP_Handle, 0, 0, 0);

	}
	static Struct_IOCP_IO*Get_UDP_IO(WORD HtonsPort)
	{
		EnterCriticalSection(&Hash_UDP_IO.Thead_Lock);
		Struct_Chain_Hash*Chain_Hash = Hash_UDP_IO.GetChainKey((char*)&HtonsPort, 2);
		LeaveCriticalSection(&Hash_UDP_IO.Thead_Lock);
		if (!Chain_Hash)return 0;
		else return (Struct_IOCP_IO*)Chain_Hash->Data;
	}
	static string Get_Native_IP(char Pint)
	{

		PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
		//得到结构体大小,用于GetAdaptersInfo参数
		unsigned long stSize = sizeof(IP_ADAPTER_INFO);
		//调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
		int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		string RetIP = "";
		if (ERROR_BUFFER_OVERFLOW == nRel)
		{
			//如果函数返回的是ERROR_BUFFER_OVERFLOW
			//则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
			//这也是说明为什么stSize既是一个输入量也是一个输出量
			//释放原来的内存空间
			delete pIpAdapterInfo;
			//重新申请内存空间用来存储所有网卡信息
			pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
			//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
			nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		}
		PIP_ADAPTER_INFO pIpAdapterInfo_P = pIpAdapterInfo;
		if (ERROR_SUCCESS == nRel)
		{
			//输出网卡信息
			//可能有多网卡,因此通过循环去判断
			while (pIpAdapterInfo_P)
			{
				if (Pint)
				{
					printf("网卡名称:%s\n", pIpAdapterInfo_P->AdapterName);
					printf("网卡描述:%s\n", pIpAdapterInfo_P->Description);
					printf("网卡类型:");
					switch (pIpAdapterInfo_P->Type)
					{
					case MIB_IF_TYPE_OTHER:printf("OTHER\n"); break;
					case MIB_IF_TYPE_ETHERNET:printf("ETHERNET\n"); break;
					case MIB_IF_TYPE_TOKENRING:printf("TOKENRING\n"); break;
					case MIB_IF_TYPE_FDDI:printf("FDDI\n"); break;
					case MIB_IF_TYPE_PPP:printf("PPP\n"); break;
					case MIB_IF_TYPE_LOOPBACK:printf("LOOPBACK\n"); break;
					case MIB_IF_TYPE_SLIP:printf("SLIP\n"); break;
					default:printf("未知\n"); break;
					}
					printf("网卡MAC地址:");
					for (DWORD i = 0; i < pIpAdapterInfo_P->AddressLength; i++)
					{
						if (i < pIpAdapterInfo_P->AddressLength - 1)printf("%02X-", pIpAdapterInfo_P->Address[i]);
						else printf("%02X\n", pIpAdapterInfo_P->Address[i]);
					}
					printf("网关地址:%s\n", pIpAdapterInfo_P->GatewayList.IpAddress.String);
					IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo_P->IpAddressList);/*可能网卡有多IP,因此通过循环去判断*/
					do
					{
						if ((!strstr(pIpAddrString->IpAddress.String, "0.0.0.0")) && RetIP == "")
						{
							RetIP = pIpAddrString->IpAddress.String;
						}
						printf("IP:%s\n", pIpAddrString->IpAddress.String);
						printf("子网地址:%s\n", pIpAddrString->IpMask.String);
						pIpAddrString = pIpAddrString->Next;
					} while (pIpAddrString);
					printf("----------------------------------------\n");
				}
				else
				{

					IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo_P->IpAddressList);/*可能网卡有多IP,因此通过循环去判断*/
					do
					{
						if (!strstr(pIpAddrString->IpAddress.String, "0.0.0.0"))
						{
							RetIP = pIpAddrString->IpAddress.String;
							delete pIpAdapterInfo;
							return RetIP;
						}
						pIpAddrString = pIpAddrString->Next;
					} while (pIpAddrString);
				}
				pIpAdapterInfo_P = pIpAdapterInfo_P->Next;
			}
		}
		delete pIpAdapterInfo;
		return RetIP;
	};
	static string Get_MAC()
	{
		char MAC[128] = { 0 };
		PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
		unsigned long stSize = sizeof(IP_ADAPTER_INFO);
		int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		string RetIP = "";
		if (ERROR_BUFFER_OVERFLOW == nRel)
		{
			pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
			nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
		}
		PIP_ADAPTER_INFO pIpAdapterInfo_P = pIpAdapterInfo;
		if (ERROR_SUCCESS == nRel)
		{
			while (pIpAdapterInfo_P)
			{
				IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo_P->IpAddressList);/*可能网卡有多IP,因此通过循环去判断*/
				do
				{
					if (!strstr(pIpAddrString->IpAddress.String, "0.0.0.0"))
					{
						DWORD j = 0;
						for (DWORD i = 0; i < pIpAdapterInfo_P->AddressLength; i++, j += 3)
						{
							sprintf(MAC + j, "%02X-", pIpAdapterInfo_P->Address[i] );
						}
						MAC[j-1] = 0;
						delete pIpAdapterInfo;
						string Ret = MAC;
						return Ret;
					}
					pIpAddrString = pIpAddrString->Next;
				} while (pIpAddrString);

				pIpAdapterInfo_P = pIpAdapterInfo_P->Next;
			}
		}
		delete pIpAdapterInfo;
		return "";
	};
#ifdef Use_OpenSSL 
	static Struct_IOCP_IO*New_Server_SSL(const char*IP, unsigned Port, SSL_CTX*SSL_Ctx, DWORD Read_Time)
	{
		if (Struct_IOCP_IO*New_IO = New_Server_TCP(IP, Port, Read_Time))
		{
			New_IO->Protocol = IPPROTO_SSL;
			New_IO->SSL_Ctx = SSL_Ctx;
			return New_IO;
		}
		return 0;
	}
#endif
	static Struct_IOCP_IO*New_Server_TCP(const char*IP, unsigned Port, DWORD Read_Time)/*ServerSocket是没有OVER_LAPPED_P的*/
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		ZeroMemory(New_IO, sizeof(Struct_IOCP_IO));
		New_IO->Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, WSA_FLAG_OVERLAPPED);/*需要查看*/
		if (New_IO->Socket == INVALID_SOCKET)
		{
			printf("初始化Socket失败,错误代码:%d\n", WSAGetLastError());
			free(New_IO);
			return 0;
		}
		/*设置端口复用*/
		int one = 1;
		setsockopt(New_IO->Socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
		/*=============================================================================================*/
		if (NULL == CreateIoCompletionPort((HANDLE)New_IO->Socket, IOCP_Handle, (ULONG_PTR)New_IO, 0))
		{
			printf("完成端口绑定失败!错误代码:%d\n", WSAGetLastError());
			closesocket(New_IO->Socket);
			New_IO->Socket = INVALID_SOCKET;
			free(New_IO);
			return 0;
		}
		/*=============================================================================================*/
		New_IO->Sockaddr_in.sin_family = AF_INET;
		New_IO->Sockaddr_in.sin_port = htons(Port);
		New_IO->Sockaddr_in.sin_addr.s_addr = inet_addr(IP);
		if (bind(New_IO->Socket, (SOCKADDR*)&New_IO->Sockaddr_in, sizeof(SOCKADDR)) == SOCKET_ERROR)
		{
			printf("绑定socket失败: %d\n", WSAGetLastError());
			closesocket(New_IO->Socket);
			New_IO->Socket = INVALID_SOCKET;
			free(New_IO);
			return 0;
		}
		//cout << (int)((SOCKADDR*)&Sockaddr_in)->sa_data[2] << "." << (int)((SOCKADDR*)&Sockaddr_in)->sa_data[3] << "." << (int)((SOCKADDR*)&Sockaddr_in)->sa_data[4] << "." << (int)((SOCKADDR*)&Sockaddr_in)->sa_data[5] << endl;
		if (listen(New_IO->Socket, SOMAXCONN) == SOCKET_ERROR)/*开始监听*/
		{
			printf("listen failed with error: %d\n", WSAGetLastError());
			closesocket(New_IO->Socket);
			free(New_IO);
			return 0;
		}
		//#ifdef Process_X64
		//		printf("服务端创建成功Socket:%lld\n", New_IO->Socket);
		//#else 
		//		printf("服务端创建成功Socket:%d\n", New_IO->Socket);
		//#endif
		New_IO->Read_Time = Read_Time;
		New_IO->Protocol = IPPROTO_TCP;
		New_IO->IO_Server = New_IO;
		return New_IO;
	}
	static Struct_IOCP_IO*New_Server_UDP(const char*IP, unsigned Port, DWORD Read_Time)/*ServerSocket是没有OVER_LAPPED_P的*/
	{
		/*
		struct linger lng;
		lng.l_onoff = 0;

		nRet = setsockopt(g_hSocket,SOL_SOCKET,SO_LINGER, (char*)&lng, sizeof(lng));
		if (nRet == SOCKET_ERROR)
		{
			nRet = WSAGetLastError();
			printf ("setsockopt() SO_REUSEADDR failed, Err: %d\n",WSAGetLastError());
		}
		*/
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		ZeroMemory(New_IO, sizeof(Struct_IOCP_IO));
		//socket(AF_INET, SOCK_DGRAM, 0);
		New_IO->Socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, WSA_FLAG_OVERLAPPED);/*需要查看*/
		if (New_IO->Socket == INVALID_SOCKET)
		{
			printf("初始化Socket失败,错误代码:%d\n", WSAGetLastError());
			free(New_IO);
			return 0;
		}

		/*设置端口复用*/
		int one = 1;
		setsockopt(New_IO->Socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));

		New_IO->Sockaddr_in.sin_family = AF_INET;
		New_IO->Sockaddr_in.sin_port = htons(Port);
		New_IO->Sockaddr_in.sin_addr.s_addr = inet_addr(IP);
		if (bind(New_IO->Socket, (SOCKADDR*)&New_IO->Sockaddr_in, sizeof(SOCKADDR)) == SOCKET_ERROR)
		{
			printf("绑定socket失败: %d\n", WSAGetLastError());
			closesocket(New_IO->Socket);
			New_IO->Socket = INVALID_SOCKET;
			free(New_IO);
			return 0;
		}

		/*=============================================================================================*/
		if (NULL == CreateIoCompletionPort((HANDLE)New_IO->Socket, IOCP_Handle, (ULONG_PTR)New_IO, 0))
		{
			printf("完成端口绑定失败!错误代码:%d\n", WSAGetLastError());
			closesocket(New_IO->Socket);
			New_IO->Socket = INVALID_SOCKET;
			free(New_IO);
			return 0;
		}
		/*=============================================================================================*/
		Hash_UDP_Server.PushChain((char*)&New_IO->Socket, sizeof(SOCKET), 0);
		New_IO->Read_Time = Read_Time;
		New_IO->IO_Server = New_IO;
		New_IO->Protocol = IPPROTO_UDP;
		return New_IO;
	}
	static Struct_IOCP_IO*ConnectEx_TCP(CONST CHAR*请求域名, WORD Port, CONST CHAR*Data, DWORD Data_Size, DWORD Read_Time, Struct_IOCP_IO*IO_Mapping)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO_Mapping);
		New_IO->WSABuffer.len = Data_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		memcpy(New_IO->WSABuffer.buf, Data, New_IO->WSABuffer.len);
		New_IO->IO_State = IO_State_ConnectEx;
		主机信息结构 = gethostbyname(请求域名);/*获取域名主机信息，返回一个hostent指针*/
		if (!主机信息结构)
		{
			printf("网络错误\n");
			free(New_IO);
			return 0;
		}
		New_IO->Sockaddr_in.sin_family = AF_INET;/*sin_family表示协议簇，一般用AF_INET表示TCP/IP协议*/
		New_IO->Sockaddr_in.sin_port = htons(Port);//设置端口
		//IOCPHashList.NewestChain->Sockaddr_in.sin_addr.s_addr = inet_addr(请求域名);
		//客户端Sockaddr_in.sin_addr.S_un.S.addr = htonl("IP地址");//inet_addr()
		memcpy(&(New_IO->Sockaddr_in.sin_addr), 主机信息结构->h_addr, 4);
		/*参数2为协议的Socket类型，常用的有3种：SOCK_STREAM、SOCK_DGRAM和SOCK_RAW。SOCK_STREAM对应于TCP，SOCK_DGRAM对应于UDP。*/
		/*参数3为protocol指定所使用的协议。对于SOCK_STREAM、SOCK_DGRAM两种类型的Socket，该参数为0，对于原始Socket才需要指定具体的协议。*/
		New_IO->Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);/*每次重新send之前需要调用*/
		setsockopt(New_IO->Socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
		if (New_IO->Socket == INVALID_SOCKET)
		{
			printf("套接字不正常\n");
			free(New_IO);
			return 0;
		}
		if (!CreateIoCompletionPort((HANDLE)New_IO->Socket, IOCP_Handle, 0, 0))
		{
			printf("完成端口绑定失败!错误代码:%d\n", WSAGetLastError());
			free(New_IO);
			return 0;
		}
		/*=========================================================================================*/
		SOCKADDR_IN local;
		local.sin_family = AF_INET;
		local.sin_addr.S_un.S_addr = INADDR_ANY;
		local.sin_port = NULL;
		if (SOCKET_ERROR == bind(New_IO->Socket, (LPSOCKADDR)&local, sizeof(SOCKADDR)))
		{
			printf("绑定套接字失败,对方可能关闭了服务器!\r\n");
			getchar();
			free(New_IO);
			return 0;
		}
		/*=========================================================================================*/
		if (!ConnectEx(New_IO->Socket, (SOCKADDR*)&New_IO->Sockaddr_in,/*对方地址*/ sizeof(SOCKADDR), New_IO->WSABuffer.buf, New_IO->WSABuffer.len, 0, &New_IO->OVER_LAPPED))
		{
			if (WSAGetLastError() != ERROR_IO_PENDING)
			{
				printf("连接错误:%d\n", WSAGetLastError());
				free(New_IO);
				return 0;
			}
		}
		New_IO->Read_Time = Read_Time;
		New_IO->Protocol = IPPROTO_TCP;
		return New_IO;
	}
	static Struct_IOCP_IO*ConnectEx_UDP(CONST CHAR*请求域名, WORD Port, CONST CHAR*Data, DWORD Data_Size, DWORD Read_Time, Struct_IOCP_IO*IO_Mapping)
	{

		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO_Mapping);
		New_IO->WSABuffer.len = Data_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		memcpy(New_IO->WSABuffer.buf, Data, New_IO->WSABuffer.len);
		New_IO->IO_State = IO_State_ConnectEx;
		主机信息结构 = gethostbyname(请求域名);/*获取域名主机信息，返回一个hostent指针*/
		if (!主机信息结构)
		{
			printf("网络错误\n");
			free(New_IO);
			return 0;
		}
		New_IO->Sockaddr_in.sin_family = AF_INET;/*sin_family表示协议簇，一般用AF_INET表示TCP/IP协议*/
		New_IO->Sockaddr_in.sin_port = htons(Port);//设置端口
		//IOCPHashList.NewestChain->Sockaddr_in.sin_addr.s_addr = inet_addr(请求域名);
		//客户端Sockaddr_in.sin_addr.S_un.S.addr = htonl("IP地址");//inet_addr()
		memcpy(&(New_IO->Sockaddr_in.sin_addr), 主机信息结构->h_addr, 4);
		/*参数2为协议的Socket类型，常用的有3种：SOCK_STREAM、SOCK_DGRAM和SOCK_RAW。SOCK_STREAM对应于TCP，SOCK_DGRAM对应于UDP。*/
		/*参数3为protocol指定所使用的协议。对于SOCK_STREAM、SOCK_DGRAM两种类型的Socket，该参数为0，对于原始Socket才需要指定具体的协议。*/
		New_IO->Socket = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);/*每次重新send之前需要调用*/
		setsockopt(New_IO->Socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
		if (New_IO->Socket == INVALID_SOCKET)
		{
			printf("套接字不正常\n");
			free(New_IO);
			return 0;
		}
		if (!CreateIoCompletionPort((HANDLE)New_IO->Socket, IOCP_Handle, 0, 0))
		{
			printf("完成端口绑定失败!错误代码:%d\n", WSAGetLastError());
			free(New_IO);
			return 0;
		}
		/*=========================================================================================*/
		SOCKADDR_IN local;
		local.sin_family = AF_INET;
		local.sin_addr.S_un.S_addr = INADDR_ANY;
		local.sin_port = NULL;
		if (SOCKET_ERROR == bind(New_IO->Socket, (LPSOCKADDR)&local, sizeof(SOCKADDR)))
		{
			printf("绑定套接字失败,对方可能关闭了服务器!\r\n");
			getchar();
			free(New_IO);
			return 0;
		}
		New_IO->Read_Time = Read_Time;
		New_IO->Protocol = IPPROTO_UDP;
		Write(New_IO, Data, Data_Size);
		return New_IO;
	}
#ifdef Use_OpenSSL 
	static Struct_IOCP_IO*ConnectEx_SSL(CONST CHAR*请求域名, WORD Port, SSL_CTX*SSL_Ctx, DWORD Read_Time, Struct_IOCP_IO*IO_Mapping)
	{
		if (Struct_IOCP_IO*New_IO = ConnectEx_TCP(请求域名, Port, 0, 0, Read_Time, IO_Mapping))
		{
			New_IO->Protocol = IPPROTO_SSL;
			New_IO->SSL_Ctx = SSL_Ctx;
			return New_IO;
		}
		return 0;
	}
#endif
	static Struct_IOCP_IO*DisconnectEx_IOCP(Struct_IOCP_IO*IO)
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		ZeroMemory(&New_IO->OVER_LAPPED, sizeof(New_IO->OVER_LAPPED));
		New_IO->Socket = IO->Socket;
		New_IO->Protocol = IO->Protocol;
		New_IO->WSABuffer.buf = NULL;
		New_IO->WSABuffer.len = NULL;
		New_IO->IO_State = IO_State_DisconnectEx;
		if (!DisconnectEx)
		{
			DWORD dwBytes = NULL;
			if (SOCKET_ERROR == WSAIoctl(New_IO->Socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
				&DisconnectEx_GUID, sizeof(DisconnectEx_GUID), &DisconnectEx, sizeof(DisconnectEx), &dwBytes, NULL, NULL))
			{
				printf("未能获取DisconnectEx函数指针,错误代码:%d\n", WSAGetLastError());
				return 0;
			}
		}
		if (!DisconnectEx(New_IO->Socket, &New_IO->OVER_LAPPED, 0, 0))
		{
			DWORD dwError = WSAGetLastError();
			if (ERROR_IO_PENDING != dwError)
			{
				printf("投递DisconnectEx失败:错误代码:%d\r\n", WSAGetLastError());
				return 0;
			}
		}
		return New_IO;
	}
	static Struct_IOCP_IO*AcceptEx_TCP(Struct_IOCP_IO*IO_Server, DWORD Read_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO_Server);
		if (!New_IO)return 0;
		New_IO->IO_State = IO_State_NewClient;
		New_IO->WSABuffer.len = Read_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len + ((sizeof(SOCKADDR) + 16) * 2));
		ZeroMemory(New_IO->WSABuffer.buf, New_IO->WSABuffer.len + ((sizeof(SOCKADDR) + 16) * 2));
		New_IO->Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (!CreateIoCompletionPort((HANDLE)New_IO->Socket, IOCP_Handle, 0, 0))printf("完成端口绑定失败!错误代码:%d\n", WSAGetLastError());
		if (FALSE == IOCP_AcceptEx(IO_Server->Socket, New_IO->Socket, New_IO->WSABuffer.buf, New_IO->WSABuffer.len, sizeof(SOCKADDR) + 16, sizeof(SOCKADDR) + 16, 0, &New_IO->OVER_LAPPED))
		{
			if (WSA_IO_PENDING != WSAGetLastError())
			{
				printf("投递IOAcceptEx失败,错误代码:%d\n", WSAGetLastError());
				free(New_IO->WSABuffer.buf);
				free(New_IO);
				return 0;
			}
		}
		return New_IO;
	}
	static Struct_IOCP_IO*AcceptEx_UDP(Struct_IOCP_IO*IO_Server, DWORD Read_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO_Server);
		if (!New_IO)return 0;
		New_IO->IO_State = IO_State_NewClient;
		New_IO->WSABuffer.len = Read_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		INT Error;
		DWORD Flags = NULL;
		DWORD RecvBytes;
		int Len = sizeof(sockaddr);
		if ((WSARecvFrom(New_IO->Socket, &New_IO->WSABuffer, 1, &RecvBytes, &Flags, (sockaddr*)&New_IO->Sockaddr_in, &Len, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR) && (WSA_IO_PENDING != (Error = WSAGetLastError())))
		{
			printf("投递WSARecvFrom失败,错误代码:%d\n", WSAGetLastError());
			free(New_IO->WSABuffer.buf);
			free(New_IO);
			return 0;
		}
		return New_IO;
	}
	static Struct_IOCP_IO*Read(Struct_IOCP_IO*IO, DWORD Read_Size)
	{
		if (IO->IO_State == IO_State_Error)	return 0;
		switch (IO->Protocol)
		{
		case IPPROTO_TCP:return Read_TCP(IO, Read_Size);
		case IPPROTO_UDP:
		{
			if (Hash_UDP_Server.GetChainKey((char*)&IO->Socket, sizeof(SOCKET)))
			{
				Struct_IOCP_IO*IOCP_IO_Copy = Get_UDP_IO(IO->Sockaddr_in.sin_port);
				if (IOCP_IO_Copy)
				{
					memcpy(IOCP_IO_Copy, IO, sizeof(IO));
					if (IOCP_IO_Copy->HTimer == 0)
					{
						if (!CreateTimerQueueTimer(&IOCP_IO_Copy->HTimer, 0, (WAITORTIMERCALLBACK)TimerRoutine_UDP_Server, (void*)IO->Sockaddr_in.sin_port, IO->Read_Time, 0, 0))
						{
							printf("CreateTimerQueueTimer Error:%d\n", GetLastError());
						}
						IO->HTimer = IOCP_IO_Copy->HTimer;/*解决Write覆盖*/
					}
					return IO;
				}
			}
			return Read_UDP(IO, Read_Size);
		}
#ifdef Use_OpenSSL 
		case IPPROTO_SSL:return Read_SSL(IO);
#endif
		}
	}
	static Struct_IOCP_IO*Write(Struct_IOCP_IO*IO, CONST CHAR*Data, DWORD Data_Size)
	{
		if (IO->IO_State == IO_State_Error)	return 0;
		switch (IO->Protocol)
		{
		case IPPROTO_TCP:return Write_TCP(IO, Data, Data_Size);
		case IPPROTO_UDP:
		{
			if (Hash_UDP_Server.GetChainKey((char*)&IO->Socket, sizeof(SOCKET)))
			{
				Struct_IOCP_IO*IOCP_IO_Copy = Get_UDP_IO(IO->Sockaddr_in.sin_port);
				if (IOCP_IO_Copy)memcpy(IOCP_IO_Copy, IO, sizeof(IO));
			}
			return Write_UDP(IO, Data, Data_Size);
		}
#ifdef Use_OpenSSL 
		case IPPROTO_SSL:return Write_SSL(IO, Data, Data_Size);
#endif
		}

	}
	static Struct_IOCP_IO*Post()/*用于清理线程*/
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		ZeroMemory(&New_IO->OVER_LAPPED, sizeof(New_IO->OVER_LAPPED));
		New_IO->IO_State = IO_State_Post;
		New_IO->Socket = NULL;
		New_IO->WSABuffer.len = NULL;
		New_IO->WSABuffer.buf = NULL;
		if (!PostQueuedCompletionStatus(IOCP_Handle, 0xFFFFFFFF, 0, &New_IO->OVER_LAPPED))
		{
			printf("投递IOPost失败!错误代码:%d\n", WSAGetLastError());
			return 0;
		}
		return New_IO;
	}
	static Struct_IOCP_Return*IOCP_Solve(Struct_IOCP_Return*IOCP_Return)
	{
		//OVERLAPPED_ENTRY OVER_LAPPED数组[50];
		//DWORD 预置接收数量 = 50;
		//DWORD 实际接收数量=NULL;
		/*最后参数:FALSE表示函数会一直等待一个已完成I/O请求被添加到完成队列直到超时,
		TRUE表示当队列中没有已完成的I/O项时,线程将进入可警告状态*/
		//BOOL Bool =GetQueuedCompletionStatusEx(IOCP_Handle, OVER_LAPPED数组, 预置接收数量, &实际接收数量, -1, TRUE);
		//IOCP_Return->OVER_LAPPED_P = OVER_LAPPED数组->lpOverlapped;
		//IOCP_Return->Complete_Size = OVER_LAPPED数组->Complete_Size;
		//IOCP_Return->IOCP_IO = CONTAINING_RECORD(IOCP_Return->OVER_LAPPED_P, Struct_IOCP_IO, OVER_LAPPED);/*读取投递函数的IO*/	
		BOOL Bool = GetQueuedCompletionStatus(IOCP_Handle, (DWORD*)&IOCP_Return->Complete_Size, (PULONG_PTR)&IOCP_Return->IO_Server, &IOCP_Return->OVER_LAPPED_P, INFINITE);
#ifdef IOCP_Print_Index
		printf("【完成次数】%d\n", ++Complete_Index);
#endif
		IOCP_Return->IOCP_IO = (Struct_IOCP_IO*)IOCP_Return->OVER_LAPPED_P;/*读取投递函数的IO*/
		if (IOCP_Return->IOCP_IO->IO_State == IO_State_Read_Keep)
		{
#ifdef Use_OpenSSL
			if (IOCP_Return->IOCP_IO->BIO)IOCP_Return->IOCP_IO->IO_State = IO_State_Handshaked_Read_SSL;
			else IOCP_Return->IOCP_IO->IO_State = IO_State_Read;
#else
			IOCP_Return->IOCP_IO->IO_State = IO_State_Read;
#endif
		}
		if (IOCP_Return->IO_Server)
		{
			if (IOCP_Return->IO_Server->Protocol != IPPROTO_UDP)
			{
				if (AcceptEx_TCP(IOCP_Return->IO_Server, IOCP_Return->IOCP_IO->WSABuffer.len) == 0)
				{

				}
			}
			else
			{
				Struct_Chain_Hash*Chain_Hash = 0;
				EnterCriticalSection(&Hash_UDP_IO.Thead_Lock);
				Chain_Hash = Hash_UDP_IO.GetChainKey((char*)&IOCP_Return->IOCP_IO->Sockaddr_in.sin_port, 2);
				LeaveCriticalSection(&Hash_UDP_IO.Thead_Lock);
				if (!Chain_Hash)/*新客户端*/
				{
					Chain_Hash = Hash_UDP_IO.PushChain((char*)&IOCP_Return->IOCP_IO->Sockaddr_in.sin_port, 2, sizeof(Struct_IOCP_IO));
					memcpy(Chain_Hash->Data, IOCP_Return->IOCP_IO, sizeof(Struct_IOCP_IO));
				}
				else
				{
					Struct_IOCP_IO*IO_Before = (Struct_IOCP_IO*)Chain_Hash->Data;
					Struct_IOCP_IO*IO_Buffer = IOCP_Return->IOCP_IO;
					IOCP_Return->IOCP_IO->IO_Type = IO_Before->IO_Type;
					IOCP_Return->IOCP_IO->Custom_P = IO_Before->Custom_P;
					IOCP_Return->IOCP_IO->Custom_P_2 = IO_Before->Custom_P_2;
					IOCP_Return->IOCP_IO->Custom_P_3 = IO_Before->Custom_P_3;
					IOCP_Return->IOCP_IO->IO_Type_Custom = IO_Before->IO_Type_Custom;
				}
				if (AcceptEx_UDP(IOCP_Return->IO_Server, IOCP_Return->IOCP_IO->WSABuffer.len))
				{
					//CloseHandle((HANDLE)_beginthreadex(NULL, 0, ExitDetectionThread, GetConsoleWindow(), 0, 0));
					//服务器压力过大,网络失效的情况
				}
			}
		}
		if (IOCP_Return->IOCP_IO->HTimer && (IOCP_Return->IOCP_IO->IO_State == IO_State_Read || IOCP_Return->IOCP_IO->IO_State == IO_State_Handshaked_Read_SSL))
		{
			if (!DeleteTimerQueueTimer(0, IOCP_Return->IOCP_IO->HTimer, INVALID_HANDLE_VALUE))printf("DeleteTimerQueueTimer1 Error:%d\n", GetLastError());
			IOCP_Return->IOCP_IO->HTimer = 0;
		}
		if (!Bool)
		{
			IOCP_Return->Error_Cede = GetLastError();
			if (IOCP_Return->Error_Cede == ERROR_IO_PENDING)
			{
				/*可以释放IO但是不能关闭socket，ERROR_IO_PENDING后当前socket并不在当前IO*/
#ifdef IOCP_Print_Debug
				printf("稍后完成IO,Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
				IOCP_Return->IOCP_IO->IO_State = IO_State_Read_Keep;
				return IOCP_Return;
			}
			if (IOCP_Return->Error_Cede == ERROR_MORE_DATA)
			{
				printf("Socket:%d,UDP接收数据空间不够,只接收到部分数据\n", IOCP_Return->IOCP_IO->Socket);
			}
			else
			{
				IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
				IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
#ifdef IOCP_Print_Close
				switch (IOCP_Return->Error_Cede)
				{
				case WAIT_TIMEOUT:
					if (!判断Socket状态(IOCP_Return->IOCP_IO->Socket))printf("发送心跳确认对端关闭Socket:%d当前IO:%08X\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->IOCP_IO);
					else printf("连接超时Socket:%d当前IO:%08X\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->IOCP_IO);
					break;
				case ERROR_NETNAME_DELETED:
					printf("对端关闭Socket:%d当前IO:%08X\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->IOCP_IO);
					break;
				default:
					printf("完成端口出错,对方可能强制关闭,Socket:%d,错误代码:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Error_Cede);
					break;
				}
#endif
			}
			return IOCP_Return;
		}
		if (!IOCP_Return->IOCP_IO)/*一般不会出现*/
		{
			IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
			IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
			printf("IOCP_IO未获取到\n");
			return IOCP_Return;
		}
		if ((IOCP_Return->Complete_Size <= 0) && (IO_State_Read == IOCP_Return->IOCP_IO->IO_State || IO_State_Write == IOCP_Return->IOCP_IO->IO_State))/*判断是否有客户端断开了*/
		{
			IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
			IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
#ifdef IOCP_Print_Close
			printf("对端关闭,也有可能传输过程中出现了问题,Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
			return IOCP_Return;
		}
		if ((IOCP_Return->Complete_Size == 0) && (IO_State_Handshaked_Read_SSL == IOCP_Return->IOCP_IO->IO_State || IO_State_Handshaked_Write_SSL == IOCP_Return->IOCP_IO->IO_State))/*判断是否有客户端断开了*/
		{
			IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
			IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
#ifdef IOCP_Print_Close
			printf("对端关闭2,也有可能传输过程中出现了问题,Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
			return IOCP_Return;
		}
#ifdef Use_OpenSSL 
		if (IOCP_Return->IOCP_IO->BIO)
		{
			DWORD dwOverlappedFlags = 0;
			WSAGetOverlappedResult(IOCP_Return->IOCP_IO->Socket, IOCP_Return->OVER_LAPPED_P, (DWORD*)&IOCP_Return->Complete_Size, TRUE, &dwOverlappedFlags);
			if (WSAGetLastError())
			{
				printf("WSAGetLastError异常,Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
				IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
				IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
				return IOCP_Return;
			}
		}
#endif
		/*=====================================================================================================================================以上是错误判断*/

		switch (IOCP_Return->IOCP_IO->IO_State)
		{
		case IO_State_ConnectEx:
#ifdef IOCP_Print_Debug
			printf("【IO_State_ConnectEx】目标Socket:%d消息发送成功\n", IOCP_Return->IOCP_IO->Socket);
#endif
#ifdef Use_OpenSSL 
			if (IOCP_Return->IOCP_IO->Protocol == IPPROTO_SSL)
			{
				TCP_IO_Handshake_SSL(IOCP_Return->IOCP_IO, 0);
				IO_Delete(IOCP_Return->IOCP_IO);
				return IOCP_Solve(IOCP_Return);
			}
#endif
			break;
		case IO_State_DisconnectEx:
#ifdef IOCP_Print_Debug
			printf("【IO_State_DisconnectEx】与对方断开Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
			break;
		case IO_State_NewClient:/*ReturnIOCPChain是客户端,ServerChain服务端*/
		{
			/*如果接收了第一次客户端的数据,将会影响第一次的WSABUF重叠接收。如果对方是没有延迟的重复发送,将会全部受影响,这时候应该不接收第一次,全部转交给WSARecv处理*/
			/*如果没有接收第一次数据,那么,这里应该WSARecv预投递好客户端最大一次发送的数据次数*/
			/*取得连入客户端的地址信息取得客户端和本地端的地址信息*/
			if (IOCP_Return->IO_Server->Protocol != IPPROTO_UDP)
			{
				void*ClientAddr = NULL;
				void*LocalAddr = NULL;
				INT Socket_Size = 0;
				GetAcceptExSockAddrs(IOCP_Return->IOCP_IO->WSABuffer.buf, IOCP_Return->IOCP_IO->WSABuffer.len, sizeof(SOCKADDR) + 16/*为本地地址预留的空间大小*/, sizeof(SOCKADDR) + 16/*为远程地址预留的空间大小*/, (LPSOCKADDR*)&LocalAddr, &Socket_Size, (LPSOCKADDR*)&ClientAddr, &Socket_Size);
				memcpy(&IOCP_Return->IOCP_IO->Sockaddr_in, ClientAddr, sizeof(SOCKADDR));
			}
#ifdef IOCP_Print_Debug
			printf("【IO_State_NewClient】新客户端连入Socket:%d 客户端IP:%s 端口:%d Complete_Size:%d\n",
				IOCP_Return->IOCP_IO->Socket,
				inet_ntoa(IOCP_Return->IOCP_IO->Sockaddr_in.sin_addr),
				ntohs(IOCP_Return->IOCP_IO->Sockaddr_in.sin_port),
				IOCP_Return->Complete_Size);
			/*for (size_t i = NULL; i < IOCP_Return->Complete_Size; i++)
			{
				printf("%c", IOCP_Return->IOCP_IO->WSABuffer.buf[i]);
			}
			printf("\n");*/
#endif

#ifdef Use_OpenSSL 
			if (IOCP_Return->IOCP_IO->Protocol == IPPROTO_SSL)
			{
				TCP_IO_Handshake_SSL(IOCP_Return->IOCP_IO, IOCP_Return->IO_Server);
				IO_Delete(IOCP_Return->IOCP_IO);

				return IOCP_Solve(IOCP_Return);
			}
#endif
			break;
		}
#ifdef IOCP_Print_Debug
		case IO_State_Read:
			printf("【IO_State_Read】接管IO%08X,对方Socket:%d发来消息 Complete_Size:%d\n", IOCP_Return->IOCP_IO, IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
			//for (size_t i = NULL; i < IOCP_Return->Complete_Size; i++)
			//{
			//	printf("%c", IOCP_Return->IOCP_IO->WSABuffer.buf[i]);
			//}
			//printf("\n");
			break;
		case IO_State_Write:
			printf("【IOCP_Write】\n发送到Socket:%d成功 Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
			break;
		case IO_State_Post:
			printf("【IO_State_Post】\n完成,是否需要关闭线程\n");
			break;
#endif	

#ifdef Use_OpenSSL 

		case IO_State_Handshaking_Read_SSL:
#ifdef IOCP_Print_Debug
			printf("【IO_State_Handshaking_Read_SSL】对方Socket:%d Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
#endif
			/*将对端数据写入到本地*/
			if (int Error_Code = SSL_get_error(IOCP_Return->IOCP_IO->Socket_SSL, BIO_write(IOCP_Return->IOCP_IO->BIO->BIO_Read, IOCP_Return->IOCP_IO->WSABuffer.buf, IOCP_Return->Complete_Size)))
			{
				if (ssl_is_fatal_error(Error_Code))
				{
					//Print_Error_Log(Error_Code);
#ifdef IOCP_Print_Close
					printf("握手失败1:Socket:%d,对方可能已经断开SSL连接\n", IOCP_Return->IOCP_IO->Socket);
#endif
					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
					break;
				}
			}
			if (int Error_Code = SSL_get_error(IOCP_Return->IOCP_IO->Socket_SSL, SSL_read(IOCP_Return->IOCP_IO->Socket_SSL, IOCP_Return->IOCP_IO->WSABuffer.buf, SLL_Handshaking_Read_Size)))
			{
				if (ssl_is_fatal_error(Error_Code))
				{
					//Print_Error_Log(Error_Code);
#ifdef IOCP_Print_Close
					printf("握手失败2:Socket:%d,对方可能已经断开SSL连接\n", IOCP_Return->IOCP_IO->Socket);
#endif
					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
					break;
				}
			}
			if (BIO_pending(IOCP_Return->IOCP_IO->BIO->BIO_Write))/*判断对端数据是否已经全部写入到本地,是则写入到客户端,否则继续投递读取后写入*/
			{
				IOCP_Return->IOCP_IO->WSABuffer.len = BIO_read(IOCP_Return->IOCP_IO->BIO->BIO_Write, IOCP_Return->IOCP_IO->WSABuffer.buf, SLL_Handshaking_Read_Size);
				if (int Error_Code = SSL_get_error(IOCP_Return->IOCP_IO->Socket_SSL, (int)IOCP_Return->IOCP_IO->WSABuffer.len))
				{
					if (ssl_is_fatal_error(Error_Code))
					{
						//Print_Error_Log(Error_Code);
#ifdef IOCP_Print_Close
						printf("握手失败3:Socket:%d,对方可能已经断开SSL连接\n", IOCP_Return->IOCP_IO->Socket);
#endif
						IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
						IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
						break;
					}
				}
				IOCP_Return->IOCP_IO->IO_State = IO_State_Handshaking_Write_SSL;

				WSASend(IOCP_Return->IOCP_IO->Socket, &IOCP_Return->IOCP_IO->WSABuffer, 1, 0, 0, &IOCP_Return->IOCP_IO->OVER_LAPPED, 0);
				int code = WSAGetLastError();
				if (0 != code && WSA_IO_PENDING != code) {

					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
				}

			}
			else if (SSL_is_init_finished(IOCP_Return->IOCP_IO->Socket_SSL))/*客户端一般会执行到这里*/
			{

#ifdef IOCP_Print_Debug
				printf("与服务端SSL握手成功Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
				Show_Target_Certificates_SSL(IOCP_Return->IOCP_IO->Socket_SSL);
				IOCP_Return->IOCP_IO->IO_State = IO_State_Handshaked_SSL;
				break;
			}
			else/*原版在这里每次都要投递一次WSARecv,如果是服务端这样无法判断什么时候握手成功*/
			{
				//IOCP_Return->IOCP_IO->WSABuffer.len = SLL_Handshaking_Read_Size;
				//DWORD Flags = NULL;
				//WSARecv(IOCP_Return->IOCP_IO->Socket, &IOCP_Return->IOCP_IO->WSABuffer, 1, 0, &Flags, &IOCP_Return->IOCP_IO->OVER_LAPPED, 0);
				//int code = WSAGetLastError();
				//if (0 != code && WSA_IO_PENDING != code) {
				//	IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
				//	IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
				//	break;
				//}

				IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
				IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
				break;
			}

			/*这里应该再次调用等待，如果直接返回可能会出现多线程冲突，可能投递WSASend/WSARecv完成后当前线程还在使用或删除IO*/
			return IOCP_Solve(IOCP_Return);
		case IO_State_Handshaking_Write_SSL:
		{
#ifdef IOCP_Print_Debug
			printf("【IO_State_Handshaking_Write_SSL】对方Socket:%d Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
#endif
			if (SSL_is_init_finished(IOCP_Return->IOCP_IO->Socket_SSL))
			{
#ifdef IOCP_Print_Debug
				printf("服务端与对端SSL握手成功Socket:%d\n", IOCP_Return->IOCP_IO->Socket);
				Show_Target_Certificates_SSL(IOCP_Return->IOCP_IO->Socket_SSL);
#endif
				IOCP_Return->IOCP_IO->IO_State = IO_State_Handshaked_SSL;
				break;
			}
			else
			{
				IOCP_Return->IOCP_IO->IO_State = IO_State_Handshaking_Read_SSL;
				IOCP_Return->IOCP_IO->WSABuffer.len = SLL_Handshaking_Read_Size;
				DWORD Flags = NULL;
				WSARecv(IOCP_Return->IOCP_IO->Socket, &IOCP_Return->IOCP_IO->WSABuffer, 1, 0, &Flags, &IOCP_Return->IOCP_IO->OVER_LAPPED, 0);
				int code = WSAGetLastError();
				if (0 != code && WSA_IO_PENDING != code)
				{
					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
					break;
				}
			}
		}
		/*这里应该再次调用等待，如果直接返回可能会出现多线程冲突，可能投递WSASend/WSARecv完成后当前线程还在使用或删除IO*/
		return IOCP_Solve(IOCP_Return);
		case IO_State_Handshaked_Read_SSL:

#ifdef IOCP_Print_Debug
			printf("【IO_State_Handshaked_Read_SSL】对方Socket:%d Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
#endif

			if (int Error_Code = SSL_get_error(IOCP_Return->IOCP_IO->Socket_SSL, BIO_write(IOCP_Return->IOCP_IO->BIO->BIO_Read, IOCP_Return->IOCP_IO->WSABuffer.buf, IOCP_Return->Complete_Size)))
			{
				if (ssl_is_fatal_error(Error_Code))
				{
					//Print_Error_Log(Error_Code);
					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
#ifdef IOCP_Print_Close
					printf("IO_State_Handshaked_Read_SSL失败:Socket:%d,对方可能已经断开SSL连接1\n", IOCP_Return->IOCP_IO->Socket);
#endif
					break;
				}
			}
			IOCP_Return->Complete_Size = 0;
			while (true)
			{

				int Len = SSL_read(IOCP_Return->IOCP_IO->Socket_SSL, IOCP_Return->IOCP_IO->WSABuffer.buf + IOCP_Return->Complete_Size, SLL_Handshaking_Read_Size);
				if (Len <= 0)break;
				IOCP_Return->Complete_Size += Len;
				if (IOCP_Return->Complete_Size + SLL_Handshaking_Read_Size > IOCP_Return->IOCP_IO->WSABuffer.len)/*预留下一次空间*/
				{
					IOCP_Return->IOCP_IO->WSABuffer.len += SLL_Handshaking_Read_Size;
					IOCP_Return->IOCP_IO->WSABuffer.buf = (char*)realloc(IOCP_Return->IOCP_IO->WSABuffer.buf, IOCP_Return->IOCP_IO->WSABuffer.len);

				}
			}
			if (IOCP_Return->Complete_Size <= 0)
			{
#ifdef IOCP_Print_Debug
				printf("SLL未传输完成 对方Socket:%d Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
#endif
				IOCP_Return->IOCP_IO->IO_State = IO_State_Read_Keep;
				Read_SSL(IOCP_Return->IOCP_IO);
				return IOCP_Return;
			}

			if (!IOCP_Return->IOCP_IO->Socket_SSL)printf("!BIO_Write_SSL()对方可能异常断开SSL连接,可能非正常操作,已经自动释放IO\n");
			else if (int Error_Code = SSL_get_error(IOCP_Return->IOCP_IO->Socket_SSL, (int)IOCP_Return->Complete_Size))
			{
				if (ssl_is_fatal_error(Error_Code))
				{
					//Print_Error_Log(Error_Code);
					IOCP_Return->IOCP_IO->IO_State_Error_Before = IOCP_Return->IOCP_IO->IO_State;
					IOCP_Return->IOCP_IO->IO_State = IO_State_Error;
					printf("IO_State_Handshaked_Read_SSL失败:Socket:%d,对方可能已经断开SSL连接2\n", IOCP_Return->IOCP_IO->Socket);
					break;
				}
			}
#ifdef IOCP_Print_Debug
			printf("读取SSL数据完成Socket:%d,Complete_Size:%d\n%s\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size, IOCP_Return->IOCP_IO->WSABuffer.buf);
#endif

			break;
		case IO_State_Handshaked_Write_SSL:
#ifdef IOCP_Print_Debug
			printf("【IO_State_Handshaked_Write_SSL】写入完成,Socket:%d,Complete_Size:%d\n", IOCP_Return->IOCP_IO->Socket, IOCP_Return->Complete_Size);
#endif
			break;
#endif
		default:
#ifdef IOCP_Print_Debug
			printf("IO_State参数异常Socket%d\n", IOCP_Return->IOCP_IO->Socket);
#endif
			break;
		}
		return IOCP_Return;
	}
	static void CloseSocket(Struct_IOCP_IO*IO)
	{
		if (!IO)return;
		if (Hash_UDP_Server.GetChainKey((char*)&IO->Socket, sizeof(SOCKET)))
		{
			EnterCriticalSection(&Hash_UDP_IO.Thead_Lock);
			Struct_Chain_Hash*Chain_Hash = Hash_UDP_IO.GetChainKey((char*)&IO->Sockaddr_in.sin_port, 2);
			if (Chain_Hash)
			{
				Struct_IOCP_IO*UDP_IO = (Struct_IOCP_IO*)Chain_Hash->Data;
				UDP_Close_CallBack(UDP_IO);
				/*因为UDP服务端没有关闭消息,如果不调用可能导致TimerRoutine还在运行中,之后删除的是其他相同端口的Socket*/
				if (UDP_IO->HTimer)if (!DeleteTimerQueueTimer(0, UDP_IO->HTimer, INVALID_HANDLE_VALUE))printf("DeleteTimerQueueTimer3 Error:%d\n", GetLastError());
				Hash_UDP_IO.DeleteChainAdress(Chain_Hash);
			}
			LeaveCriticalSection(&Hash_UDP_IO.Thead_Lock);
			return;
		}
		/*Now close the socket handle. This will do an abortive or graceful close, as requested.*/
		/*
		LINGER lingerStruct;
		lingerStruct.l_onoff = 1;
		lingerStruct.l_linger = 0;
		setsockopt(IO->Socket, SOL_SOCKET, SO_LINGER,(char *)&lingerStruct, sizeof(lingerStruct));
		CancelIo((HANDLE)IO->Socket);
		closesocket(IO->Socket);
		*/
		//shutdown(IO->Socket, 2);
		closesocket(IO->Socket);
	}
	static void IO_Delete(Struct_IOCP_IO*IO)
	{
		if (IO)
		{
			if (IO->IO_State == IO_State_Error)
			{
				CloseSocket(IO);
#ifdef Use_OpenSSL 
				if (IO->BIO != 0 && IO->IO_State != IO_State_Handshaked_Write_SSL && IO->IO_State_Error_Before != IO_State_Handshaked_Write_SSL)
				{
					if (BIO_pending(IO->BIO->BIO_Write) <= 0 || BIO_pending(IO->BIO->BIO_Read) <= 0)
					{
						if (IO->Socket_SSL)/*TCP_IO_Handshake_SSL可能会没有成功申请Socket_SSL*/
						{
							if (!SSL_shutdown(IO->Socket_SSL)) {
								/* If we called SSL_shutdown() first then
								we always get return value of ’0’. In
								this case, try again, but first send a
								TCP FIN to trigger the other side’s
								close_notify*/
								SSL_shutdown(IO->Socket_SSL);
							}
						}
#ifdef	IOCP_Print_Index
						InterlockedDecrement(&次数);
						printf("【SLL数量】%d\n", 次数);
#endif
						/*SSL_free和BIO_fre不能同时调用并且BIO释放不干净*/
						/*
						BIO_free_all(IO->BIO->BIO_Read);
						BIO_free_all(IO->BIO->BIO_Write);
						*/
						SSL_free(IO->Socket_SSL);
						free(IO->BIO);
						IO->BIO = 0;
					}
				}
#endif
			}
			memset(IO->WSABuffer.buf, 0, IO->WSABuffer.len);/*消除脏内存问题*/
			free(IO->WSABuffer.buf);
			free(IO);
		}
	}
#ifdef Use_OpenSSL 
	static char Show_Target_Certificates_SSL(SSL*Socket_SSL)/*需要完全握手后二次IO等待后才能调用*/
	{
		X509*Client_cert = SSL_get_peer_certificate(Socket_SSL);/*获取对方证书信息*/
		if (Client_cert != NULL)
		{
			printf("数字证书信息:\n");
			char*Information = X509_NAME_oneline(X509_get_subject_name(Client_cert), 0, 0);//得到对方所有者名字
			if (NULL == Information)
			{
				printf("auth error!\n");
				return 0;
			}
			printf("subject: %s\n", Information);
			Information = X509_NAME_oneline(X509_get_issuer_name(Client_cert), 0, 0);
			if (NULL == Information)
			{
				printf("certificate name is null\n");
				return 0;
			}
			printf("issuer: %s\n", Information);
			printf("connect successfully\n");
			X509_free(Client_cert);
			OPENSSL_free(Information);/*通过指针清理数字证书信息*/
		}
		else
		{
			printf("未获取到对方数字证书\n");
			return 0;
		}
		return 1;
	}
	static char Free_SSL()
	{
		CRYPTO_set_locking_callback(NULL);
		CRYPTO_set_dynlock_create_callback(NULL);
		CRYPTO_set_dynlock_lock_callback(NULL);
		CRYPTO_set_dynlock_destroy_callback(NULL);

		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();

		if (nullptr != Lock_SSL)
		{
			for (int n = 0; n < Lock_SSL_Number; ++n)DeleteCriticalSection(&Lock_SSL[n]);
			free(Lock_SSL);
			Lock_SSL = nullptr;
			Lock_SSL_Number = 0;
		}
		return 0;
	}
	static SSL_CTX*Load_CRT(const char*Visa_Certificates_Path, const char*Visa_Key_Path, const char*Verification_Certificates_Path)
	{
		/*
		SSLv23_client_method()
		SSLv23_server_method()
		SSLv23_method()
		TLSv1_server_method()
		SSLv2_server_method()//单独表示V2或V3标准
		SSLv3_server_method()
		*/
		SSL_CTX*SSL_Ctx = SSL_CTX_new(SSLv23_method());
		if (!SSL_Ctx)
		{
			ERR_print_errors_fp(stderr);
			return 0;
		}
		if (Verification_Certificates_Path)/*验证对方是否有这个ca机构颁发证书,默认模式是不验证客户端证书的,如果验证失败SSL_accept处会返回-1,一直报错*/
		{
			/*SSL_VERIFY_NONE表示不验证
			SSL_VERIFY_PEER用于客户端时要求服务器必须提供证书,用于服务器时服务器会发出证书请求消息要求客户端提供证书,但是客户端也可以不提供
			SSL_VERIFY_FAIL_IF_NO_PEER_CERT只适用于服务器且必须提供证书,他必须与SSL_VERIFY_PEER一起使用*/
			SSL_CTX_set_verify(SSL_Ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);/*设置验证方式,启用双向验证*/
			if (SSL_CTX_load_verify_locations(SSL_Ctx, Verification_Certificates_Path, NULL) == 0)/*加载本应用所信任的CA根证书,对方必须是使用这个根证书颁发的证书才能通过*/
			{
				ERR_print_errors_fp(stderr);
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
			SSL_CTX_set_verify_depth(SSL_Ctx, 1);
			/*设置加密算法*/
			/*SSL_CTX_set_client_CA_list这个API目前不知道用法*/
			//SSL_CTX_set_cipher_list(SSL_Ctx, "RC4-MD5");/*Windows系统加载这一行无法验证对方证书原因不明*/
			SSL_CTX_set_mode(SSL_Ctx, SSL_MODE_AUTO_RETRY);
		}

		/*■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■*/
		if (Visa_Certificates_Path&&Visa_Key_Path)/*客户端不用载入一般服务器不会验证*/
		{
			if (SSL_CTX_use_certificate_file(SSL_Ctx, Visa_Certificates_Path, SSL_FILETYPE_PEM) == 0)/*载入数字证书,此证书用来发送给对端,证书里包含有公钥*/
			{
				//ERR_print_errors_fp(stderr);
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
			if (SSL_CTX_use_PrivateKey_file(SSL_Ctx, Visa_Key_Path, SSL_FILETYPE_PEM) == 0)/*设置私钥*/
			{
				ERR_print_errors_fp(stderr);
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
			if (!SSL_CTX_check_private_key(SSL_Ctx))/* 检查私钥和证书是否匹配*/
			{
				printf("Private key does not match the certificate public key\n");
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
		}
		return SSL_Ctx;
	}
	static SSL_CTX*Load_CRT_Memory(const char*Visa_Certificates, const char*Visa_Key, const char*Verification_Certificates)
	{
		/*
		如果服务端加载Verification_Certificates客户端必须提供Visa_Certificates,Visa_Key
		如果客户端加载Verification_Certificates服务端必须提供Visa_Certificates,Visa_Key

		客户端加载Visa_Certificates,Visa_Key服务端也不一定会验证
		服务端加载Visa_Certificates,Visa_Key才能通过浏览器的验证

		此函需要在握手成功前调用
		*/
		/*
		SSLv23_client_method()
		SSLv23_server_method()
		SSLv23_method()
		TLSv1_server_method()
		SSLv2_server_method()//单独表示V2或V3标准
		SSLv3_server_method()
		*/
		SSL_CTX*SSL_Ctx = SSL_CTX_new(SSLv23_method());
		if (!SSL_Ctx)
		{
			ERR_print_errors_fp(stderr);
			return 0;
		}
		if (Verification_Certificates)/*验证对方是否有这个ca机构颁发证书,默认模式是不验证客户端证书的,如果验证失败SSL_accept处会返回-1,一直报错*/
		{
			/*SSL_VERIFY_NONE表示不验证
			SSL_VERIFY_PEER用于客户端时要求服务器必须提供证书,用于服务器时服务器会发出证书请求消息要求客户端提供证书,但是客户端也可以不提供
			SSL_VERIFY_FAIL_IF_NO_PEER_CERT只适用于服务器且必须提供证书,他必须与SSL_VERIFY_PEER一起使用*/
			SSL_CTX_set_verify(SSL_Ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);/*设置验证方式*/
			if (SSL_CTX_load_verify_locations(SSL_Ctx, 0, Verification_Certificates) == 0)/*加载本应用所信任的CA根证书,对方必须是使用这个根证书颁发的证书才能通过*/
			{
				ERR_print_errors_fp(stderr);
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
			SSL_CTX_set_verify_depth(SSL_Ctx, 1);
			/*设置加密算法*/
			/*SSL_CTX_set_client_CA_list这个API目前不知道用法*/
			//SSL_CTX_set_cipher_list(SSL_Ctx, "RC4-MD5");/*Windows系统加载这一行无法验证对方证书原因不明*/
			SSL_CTX_set_mode(SSL_Ctx, SSL_MODE_AUTO_RETRY);
		}
		/*■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■*/
		if (Visa_Key&&Visa_Certificates)/*客户端不用载入一般服务器不会验证*/
		{

			BIO *Bio = BIO_new_mem_buf(Visa_Key, strlen(Visa_Key));
			if (!Bio) printf("读取密钥失败\n");


			EVP_PKEY *pkey = PEM_read_bio_PrivateKey(Bio, 0, 0, 0);
			SSL_CTX_use_PrivateKey(SSL_Ctx, pkey);
			EVP_PKEY_free(pkey);
			BIO_free(Bio); Bio = 0;



			Bio = BIO_new_mem_buf(Visa_Certificates, strlen(Visa_Certificates));
			if (!Bio) printf("读取证书失败\n");
			X509 *cert = PEM_read_bio_X509(Bio, NULL, NULL, NULL);
			if (!cert) printf("读取证书失败2\n");
			ssl_print_cert_info(cert);/*显示证书*/
			SSL_CTX_use_certificate(SSL_Ctx, cert);
			X509_free(cert);
			BIO_free(Bio);

			//DER格式
			/*
			 SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
			 BIO *root = BIO_new_mem_buf(Visa_Certificates, strlen(Visa_Certificates));
			 X509 *certX = d2i_X509_bio(root, NULL);
			 X509_STORE *certS = SSL_CTX_get_cert_store(ctx);
			 X509_STORE_add_cert(certS, certX);
			 SSL_CTX_use_certificate(SSL_Ctx, certX);
			 X509_free(certX);
			 BIO_free(root);
			 */

			if (!SSL_CTX_check_private_key(SSL_Ctx))/* 检查私钥和证书是否匹配*/
			{
				printf("Private key does not match the certificate public key\n");
				SSL_CTX_free(SSL_Ctx);
				return 0;
			}
		}
		return SSL_Ctx;
	}
	static void Free_CRT(SSL_CTX*SSL_Ctx)
	{
		SSL_CTX_free(SSL_Ctx);
	}
	static void ssl_lock_callback(int mode, int n, const char *file, int line)
	{
		if (mode & CRYPTO_LOCK)
			EnterCriticalSection(&Lock_SSL[n]);
		else
			LeaveCriticalSection(&Lock_SSL[n]);
	}
	static CRYPTO_dynlock_value*ssl_lock_dyn_create_callback(const char *file, int line)
	{
		CRYPTO_dynlock_value *l = (CRYPTO_dynlock_value*)malloc(sizeof(CRYPTO_dynlock_value));
		InitializeCriticalSection(&l->lock);
		return l;
	}
	static void ssl_lock_dyn_callback(int mode, CRYPTO_dynlock_value* l, const char *file, int line)
	{
		if (mode & CRYPTO_LOCK)
			EnterCriticalSection(&l->lock);
		else
			LeaveCriticalSection(&l->lock);
	}
	static void ssl_lock_dyn_destroy_callback(CRYPTO_dynlock_value* l, const char *file, int line)
	{
		DeleteCriticalSection(&l->lock);
		free(l);
	}
	static unsigned long thread_id_callback(void)
	{
		//return (unsigned long)pthread_self();/*LINUX*/
		return GetCurrentThreadId();
	}
	static bool ssl_is_fatal_error(int ssl_error)
	{
		switch (ssl_error)/*不是这些消息就是错误的*/
		{
		case SSL_ERROR_NONE:
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_CONNECT:
		case SSL_ERROR_WANT_ACCEPT:
			return false;
		}
		return true;
	}
	static void Print_Error_Log(int Error_Code)
	{
		char message[512] = { 0 };
		while (SSL_ERROR_NONE != Error_Code)
		{
			ERR_error_string_n(Error_Code, message, 512);
			switch (Error_Code)
			{
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_WANT_READ:
				break;
			case SSL_ERROR_WANT_WRITE:
				break;
			case SSL_ERROR_WANT_CONNECT:
				break;
			case SSL_ERROR_WANT_ACCEPT:
				break;
			default:
				printf("%s\n", message);
				break;
			}
			Error_Code = ERR_get_error();
		}
	}
	/*暂时保留,可能以后需要*/
	static string ssl_get_cert_issuer_info_by_id(X509_NAME *issuer, int id)
	{
		std::string issuer_info;
		int index = X509_NAME_get_index_by_NID(issuer, id, -1);
		X509_NAME_ENTRY *entry = X509_NAME_get_entry(issuer, index);
		if (entry > 0)
		{
			ASN1_STRING *asn1_data = X509_NAME_ENTRY_get_data(entry);
			if (asn1_data > 0)
			{
				unsigned char *info = ASN1_STRING_data(asn1_data);
				if (info > 0)
					issuer_info = (char*)info;
			}
		}
		return issuer_info;
	}
	static void ssl_print_cert_info(X509 *cert)
	{
		printf("=======================\n");
		X509_NAME *name_subject = X509_get_subject_name(cert);
		if (name_subject > 0)
		{
			BIO *bio = BIO_new(BIO_s_mem());
			X509_NAME_print_ex(bio, name_subject, 0, XN_FLAG_RFC2253);
			char *subject = nullptr;
			long length = BIO_get_mem_data(bio, &subject);
			if (nullptr != subject && length > 0)
			{
				std::string str;
				str.resize(length);
				std::copy(subject, subject + length, str.begin());
				printf("CERT subject: %s\n", str.c_str());
			}
			BIO_free(bio);
		}

		X509_NAME *name_issuer = X509_get_issuer_name(cert);
		if (name_issuer > 0)
		{
			printf("CERT cn: %s\n", ssl_get_cert_issuer_info_by_id(name_issuer, NID_commonName).c_str());
			printf("CERT c: %s\n", ssl_get_cert_issuer_info_by_id(name_issuer, NID_countryName).c_str());
			printf("CERT o: %s\n", ssl_get_cert_issuer_info_by_id(name_issuer, NID_organizationName).c_str());
		}

		int criticality = -1, ext_index = -1;
		ASN1_BIT_STRING *key_usage = (ASN1_BIT_STRING *)X509_get_ext_d2i(cert, NID_key_usage, &criticality, &ext_index);
		if (key_usage > 0)
		{
			const char *usages[] = { "digitalSignature",
				"nonRepudiation",
				"keyEncipherment",
				"dataEncipherment",
				"keyAgreement",
				"keyCertSign",
				"cRLSign",
				"encipherOnly",
				"decipherOnly" };

			printf("CERT key_usage:");
			for (int index = 0; index < 8; index++)
			{
				if (ASN1_BIT_STRING_get_bit(key_usage, index))
					printf(" %s;", usages[index]);
			}
			printf("\n");
		}

		const char *kuValue = NULL;
		STACK_OF(ASN1_OBJECT) *ext_key_usage = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
		if (ext_key_usage > 0)
		{
			printf("CERT ext_key_usage:");
			while (sk_ASN1_OBJECT_num(ext_key_usage) > 0)
			{
				int usage_id = OBJ_obj2nid(sk_ASN1_OBJECT_pop(ext_key_usage));
				const char *usage_value = OBJ_nid2sn(usage_id);
				printf(" %d:%s;", usage_id, usage_value);
			}
			printf("\n");
		}

		STACK_OF(GENERAL_NAME) *alt_name = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
		while (sk_GENERAL_NAME_num(alt_name) > 0)
		{
			GENERAL_NAME *name = sk_GENERAL_NAME_pop(alt_name);
			switch (name->type)
			{
			case GEN_DNS:
				printf("CERT GEN_DNS: %s\n", ASN1_STRING_data(name->d.dNSName));
				break;
			case GEN_URI:
				printf("CERT GEN_URI: %s\n", ASN1_STRING_data(name->d.uniformResourceIdentifier));
				break;
			case GEN_EMAIL:
				printf("CERT GEN_EMAIL: %s\n", (char*)ASN1_STRING_data(name->d.rfc822Name));
				break;
			}
		}
		printf("=======================\n");
	}
	static bool TCP_IO_Handshake_SSL(Struct_IOCP_IO*IOCP_IO, Struct_IOCP_IO*IOCP_IO_Sever)
	{
#ifdef	IOCP_Print_Index
		InterlockedIncrement(&次数);
		printf("【SLL数量】%d\n", 次数);
#endif
		/*如果不New一个IO会出现多线程冲突问题或访问冲突问题比如外部释放IOCP_IO*/
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		ZeroMemory(New_IO, sizeof(Struct_IOCP_IO));
		New_IO->Socket = IOCP_IO->Socket;
		New_IO->Protocol = IPPROTO_SSL;
		New_IO->IO_Type = IOCP_IO->IO_Type;
		New_IO->Custom_P = IOCP_IO->Custom_P;
		New_IO->WSABuffer.buf = (char*)malloc(SLL_Handshaking_Read_Size);
		ZeroMemory(New_IO->WSABuffer.buf, SLL_Handshaking_Read_Size);
		New_IO->WSABuffer.len = SLL_Handshaking_Read_Size;
		New_IO->BIO = (Struct_BIO*)malloc(sizeof(Struct_BIO));
		memset(New_IO->BIO, 0, sizeof(Struct_BIO));
		New_IO->BIO->BIO_Write = BIO_new(BIO_s_mem());
		New_IO->BIO->BIO_Read = BIO_new(BIO_s_mem());
		if (IOCP_IO_Sever)New_IO->Socket_SSL = SSL_new(IOCP_IO_Sever->SSL_Ctx);
		else New_IO->Socket_SSL = SSL_new(New_IO->SSL_Ctx);
		if (!New_IO->Socket_SSL)
		{
			printf("TCP_IO_Handshake_SSL SSL_new() Error\n");
			//ERR_print_errors_fp(stderr);要出错，原因不明，可能只有LINUX可以使用
			New_IO->IO_State_Error_Before = IO_State_NewClient;
			New_IO->IO_State = IO_State_Error;
			return false;
		}
		SSL_set_bio(New_IO->Socket_SSL, New_IO->BIO->BIO_Read, New_IO->BIO->BIO_Write);
		DWORD dwOverlappeddNumberOfBytesTransferred = 0, dwOverlappedFlags = 0;
		WSAGetOverlappedResult(New_IO->Socket, &New_IO->OVER_LAPPED, &dwOverlappeddNumberOfBytesTransferred, TRUE, &dwOverlappedFlags);
		if (WSAGetLastError()) {
			New_IO->IO_State_Error_Before = IO_State_NewClient;
			New_IO->IO_State = IO_State_Error;
			return false;
		}
		//setsockopt(IOCP_Return->New_IO->Socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char*)&IOCP_Return->Hash_UDP_Server_P, sizeof(SOCKET));
		if (IOCP_IO_Sever)
		{
			SSL_set_accept_state(New_IO->Socket_SSL);
			DWORD Flags = NULL;
			New_IO->IO_State = IO_State_Handshaking_Read_SSL;
			WSARecv(New_IO->Socket, &New_IO->WSABuffer, 1, 0, &Flags, &New_IO->OVER_LAPPED, 0);
			int code = WSAGetLastError();
			if (0 != code && WSA_IO_PENDING != code)
			{
				New_IO->IO_State_Error_Before = IO_State_NewClient;
				New_IO->IO_State = IO_State_Error;
				printf("建立握手失败:Socket:%d,对方可能已经断开连接\n", New_IO->Socket);
				return false;
			}
		}
		else
		{
			SSL_set_connect_state(New_IO->Socket_SSL);
			bool fatal_error_occurred = false;
			if (nullptr != New_IO->Socket_SSL)
			{
				int bytes = SSL_read(New_IO->Socket_SSL, New_IO->WSABuffer.buf, SLL_Handshaking_Read_Size);
				if (BIO_pending(New_IO->BIO->BIO_Write))
				{
					ZeroMemory(New_IO->WSABuffer.buf, SLL_Handshaking_Read_Size);
					/*读取本地数据*/
					New_IO->WSABuffer.len = BIO_read(IOCP_IO->BIO->BIO_Write, IOCP_IO->WSABuffer.buf, SLL_Handshaking_Read_Size);
					//int ssl_error = ssl_get_error(IOCP_Return->IOCP_IO->Socket_SSL, bytes);
				}
				//	if (fatal_error_occurred)Struct_IOCP_IO_close(IOCP_Return->IOCP_IO);
			}
			/*发送给对端*/
			New_IO->IO_State = IO_State_Handshaking_Write_SSL;
			WSASend(New_IO->Socket, &New_IO->WSABuffer, 1, 0, 0, &New_IO->OVER_LAPPED, 0);
		}
		return true;
	}
#endif
	/*===========================================================================*/
	static CHAR IOCP_Bind_Callback(SOCKET Socket)/*用回调替换等待完成端口*/
	{
		if (!BindIoCompletionCallback((HANDLE)Socket, IOCPCallbackThread, 0))
		{
			printf("IOCP_Bind_Callback失败!错误代码:%d\n", WSAGetLastError());
			return -1;
		}
		return 0;
	}
	static VOID CALLBACK IOCPCallbackThread(DWORD dwErrorCode, DWORD dwBytesTrans, LPOVERLAPPED lpOverlapped)
	{
		return;
	}
	static CHAR 验证socket()
	{
		/*
		LOBYTE取得16进制数最低（最右边）字节的内容
		HIBYTE取得16进制数最高（最左边）字节的内容
		效果与MAKEWORD(2,2)相同
		*/
		if (LOBYTE(IOCP_WSAData.wVersion) != 2 || HIBYTE(IOCP_WSAData.wVersion) != 2)/*wVersion高位字节存储副版本号,低位字节存储主版本号*/
		{
			/*
			2.1, 1.2, 1.3, 1.4
			1.5, 1.6, 1.7, 1.8
			1.9, 2.0, 2.1，2.2
			返回值不等于514则版本错误
			*/
			cout << "SOCKET版本号不符或者版本号为1:" << IOCP_WSAData.wVersion << endl;
			return -1;/*版本号不符或者版本号为1*/
		}
		else/*514转换为16进制为202*/
		{
			printf("验证成功,SOCKET版本号为:%x\n", IOCP_WSAData.wVersion);
			printf("SOCKET能够支持的最高版本:%x\n", IOCP_WSAData.wVersion);
			cout << "SOCKET制造商标识和描述:" << IOCP_WSAData.szDescription << endl;
			cout << "SOCKET状态:" << IOCP_WSAData.szSystemStatus << endl;
			cout << "单个进程能够打开的SOCKET的最大数目:" << IOCP_WSAData.iMaxSockets << endl;
			cout << "能够发送或接收的最大的UDP的数据包大小:" << IOCP_WSAData.iMaxUdpDg << endl;
			return 0;
		}
	}
	static VOID 设置忽略完成端口(SOCKET Socket)
	{
		/*一般UDP用*/
		SetFileCompletionNotificationModes((HANDLE)Socket, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS);
	}
	static VOID 设置异步Socket(SOCKET Socket)/*已经废弃*/
	{
		u_long ulRet = TRUE;
		ioctlsocket(Socket, FIONBIO, &ulRet);
	}
	static Struct_IOCP_IO*IO_Copy_Shallow(Struct_IOCP_IO*IO)
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		memcpy(New_IO, IO, sizeof(Struct_IOCP_IO));
		return New_IO;
	}
	static Struct_IOCP_IO*IO_Copy_Deep(Struct_IOCP_IO*IO)
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		memcpy(New_IO, IO, sizeof(Struct_IOCP_IO));
		New_IO->WSABuffer.buf = (char*)malloc(IO->WSABuffer.len);
		memcpy(New_IO->WSABuffer.buf, IO->WSABuffer.buf, IO->WSABuffer.len);
		return New_IO;
	}
private:
	static VOID CALLBACK TimerRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		/*TimerOrWaitFired计时到了则为true,主动关闭则为false*/
		closesocket((SOCKET)lpParam);
	}
	static VOID CALLBACK TimerRoutine_UDP_Server(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
		EnterCriticalSection(&Hash_UDP_IO.Thead_Lock);
		Struct_Chain_Hash*Chain_Hash = Hash_UDP_IO.GetChainKey((char*)&lpParam, 2);
		if (Chain_Hash)
		{
			Struct_IOCP_IO*IOCP_IO_Copy = (Struct_IOCP_IO*)Chain_Hash->Data;
			HANDLE HTimer = IOCP_IO_Copy->HTimer;
			Hash_UDP_IO.DeleteChainAdress(Chain_Hash);
			LeaveCriticalSection(&Hash_UDP_IO.Thead_Lock);
			if (HTimer)if (!DeleteTimerQueueTimer(0, HTimer, INVALID_HANDLE_VALUE))printf("DeleteTimerQueueTimer2 Error:%d\n", GetLastError());/*这个会直接返回，这里不是停止时钟，而是做释放使用*/
		}
		LeaveCriticalSection(&Hash_UDP_IO.Thead_Lock);
	}
	static Struct_IOCP_IO*IO_Copy_Delivery(Struct_IOCP_IO*IO)
	{
		Struct_IOCP_IO*New_IO = (Struct_IOCP_IO*)malloc(sizeof(Struct_IOCP_IO));
		if (IO)memcpy(New_IO, IO, sizeof(Struct_IOCP_IO));
		/*
		ZeroMemory(New_IO, sizeof(Struct_IOCP_IO));
		New_IO->Socket = IO->Socket;
		New_IO->Protocol = IO->Protocol;
		New_IO->IO_Type = IO->IO_Type;
		New_IO->Custom_P = Custom_P;
		New_IO->IO_Server = IO->IO_Server;
#ifdef Use_OpenSSL
		if (IO->Protocol == IPPROTO_SSL)
		{
			New_IO->BIO = IO->BIO;
			New_IO->Socket_SSL = IO->Socket_SSL;
		}
#endif
		*/
		return New_IO;
	}
	static Struct_IOCP_IO*Read_TCP(Struct_IOCP_IO*IO, DWORD Read_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		New_IO->IO_State = IO_State_Read;
		New_IO->WSABuffer.len = Read_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		INT Error;
		DWORD Flags = NULL;
		/*如果返回值错误,并且错误的代码并非是Pending的话，那就说明这个重叠请求失败了*/
		if ((WSARecv(New_IO->Socket, &New_IO->WSABuffer, 1, 0, &Flags, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR) && (WSA_IO_PENDING != (Error = WSAGetLastError())))
		{
#ifdef Process_X64
			printf("投递IOWSARecv失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
			printf("投递IOWSARecv失败%d Socket%d\n", Error, New_IO->Socket);
#endif
			IO->IO_State_Error_Before = IO->IO_State;
			IO->IO_State = IO_State_Error;
			free(New_IO->WSABuffer.buf);
			free(New_IO);
			return 0;
		}
		IO->IO_State_Delivery = IO_State_Read;
		if (New_IO->HTimer == 0)
		{
			if (!CreateTimerQueueTimer(&New_IO->HTimer, 0, (WAITORTIMERCALLBACK)TimerRoutine, (void*)New_IO->Socket, New_IO->Read_Time, 0, 0))
			{
				printf("CreateTimerQueueTimer Error:%d\n", GetLastError());
			}
		}
		return New_IO;
	}
	static Struct_IOCP_IO*Write_TCP(Struct_IOCP_IO*IO, CONST CHAR*Data, DWORD Data_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		New_IO->IO_State = IO_State_Write;
		New_IO->WSABuffer.len = Data_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		memcpy(New_IO->WSABuffer.buf, Data, New_IO->WSABuffer.len);
		INT Error;
		if ((WSASend(New_IO->Socket, &New_IO->WSABuffer, 1, 0, 0, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR) && (WSA_IO_PENDING != (Error = WSAGetLastError())))
		{
#ifdef Process_X64
			printf("投递IOWSASend失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
			printf("投递IOWSASend失败%d Socket%d\n", Error, New_IO->Socket);
#endif
			IO->IO_State_Error_Before = IO->IO_State;
			IO->IO_State = IO_State_Error;
			free(New_IO->WSABuffer.buf);
			free(New_IO);
			return 0;
		}
		IO->IO_State_Delivery = IO_State_Write;
		return New_IO;
	}
	static Struct_IOCP_IO*Read_UDP(Struct_IOCP_IO*IO, DWORD Read_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		New_IO->IO_State = IO_State_Read;
		New_IO->WSABuffer.len = Read_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		New_IO->IO_Server = IO->IO_Server;
		INT Error;
		DWORD Flags = NULL;
		DWORD RecvBytes;
		int Len = sizeof(sockaddr);
		if ((WSARecvFrom(New_IO->Socket, &New_IO->WSABuffer, 1, &RecvBytes, &Flags, (sockaddr*)&New_IO->Sockaddr_in, &Len, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR) && (WSA_IO_PENDING != (Error = WSAGetLastError())))
		{
#ifdef Process_X64
			printf("投递IOWSARecv失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
			printf("投递IOWSARecv失败%d Socket%d\n", Error, New_IO->Socket);
#endif
			IO->IO_State_Error_Before = IO->IO_State;
			IO->IO_State = IO_State_Error;
			free(New_IO->WSABuffer.buf);
			free(New_IO);
			return 0;
		}
		if (New_IO->HTimer == 0)
		{
			if (!CreateTimerQueueTimer(&New_IO->HTimer, 0, (WAITORTIMERCALLBACK)TimerRoutine, (void*)New_IO->Socket, IO->Read_Time, 0, 0))
			{
				printf("CreateTimerQueueTimer Error:%d\n", GetLastError());
			}
		}
		return New_IO;
	}
	static Struct_IOCP_IO*Write_UDP(Struct_IOCP_IO*IO, CONST CHAR*Data, DWORD Data_Size)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		//sendto(IO->Socket, Data, Data_Size, 0, (sockaddr*)&IO->Sockaddr_in, sizeof(sockaddr));
		//return New_IO;
		New_IO->IO_State = IO_State_Write;
		New_IO->WSABuffer.len = Data_Size;
		New_IO->WSABuffer.buf = (CHAR*)malloc(New_IO->WSABuffer.len);
		memcpy(New_IO->WSABuffer.buf, Data, New_IO->WSABuffer.len);
		INT Error = 0;
		DWORD RecvBytes = 0;
		if ((WSASendTo(New_IO->Socket, &New_IO->WSABuffer, 1, &RecvBytes, 0, (sockaddr*)&New_IO->Sockaddr_in, sizeof(sockaddr), &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR) && (WSA_IO_PENDING != (Error = WSAGetLastError())))
		{
#ifdef Process_X64
			printf("投递IOWSASendTo失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
			printf("投递IOWSASendTo失败%d Socket%d\n", Error, New_IO->Socket);
#endif
			IO->IO_State_Error_Before = IO->IO_State;
			IO->IO_State = IO_State_Error;
			free(New_IO->WSABuffer.buf);
			free(New_IO);
			return 0;
		}
		IO->IO_State_Delivery = IO_State_Write;
		return New_IO;
	}
#ifdef Use_OpenSSL 
	static Struct_IOCP_IO*Read_SSL(Struct_IOCP_IO*IO)
	{
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		New_IO->WSABuffer.buf = (char*)malloc(SLL_Handshaking_Read_Size);/*BIO_read使用*/
		New_IO->WSABuffer.len = SLL_Handshaking_Read_Size;

		DWORD Flags = NULL;
		New_IO->IO_State = IO_State_Handshaked_Read_SSL;
		if (WSARecv(New_IO->Socket, &New_IO->WSABuffer, 1, 0, &Flags, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR)
			//if (WSARecv(New_IO->Socket, &IO->WSABuffer, 1, 0, &Flags, &New_IO->OVER_LAPPED, NULL) == SOCKET_ERROR)
		{
			INT Error;
			if (WSA_IO_PENDING != (Error = WSAGetLastError()))
			{
#ifdef Process_X64
				printf("投递IOWSARecv失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
				printf("投递IOWSARecv失败%d Socket%d\n", Error, New_IO->Socket);
#endif
				IO->IO_State_Error_Before = IO->IO_State;
				IO->IO_State = IO_State_Error;
				free(New_IO->WSABuffer.buf);
				free(New_IO);
				return 0;
			}
		}
		IO->IO_State_Delivery = IO_State_Handshaked_Read_SSL;
		if (New_IO->HTimer == 0)
		{
			if (!CreateTimerQueueTimer(&New_IO->HTimer, 0, (WAITORTIMERCALLBACK)TimerRoutine, (void*)New_IO->Socket, IO->Read_Time, 0, 0))
			{
				printf("CreateTimerQueueTimer Error:%d\n", GetLastError());
			}
		}
		return New_IO;
	}
	static Struct_IOCP_IO*Write_SSL(Struct_IOCP_IO*IO, const char*Data, int Data_Length)
	{
		if (!Data)return 0;
		Struct_IOCP_IO*New_IO = IO_Copy_Delivery(IO);
		if (int Error_Code = SSL_get_error(New_IO->Socket_SSL, SSL_write(New_IO->Socket_SSL, Data, Data_Length)))
		{
#ifdef Process_X64
			printf("SSL_write失败%d Socket%lld\n", Error_Code, New_IO->Socket);
#else 
			printf("SSL_write失败%d Socket%d\n", Error_Code, New_IO->Socket);
#endif
			if (ssl_is_fatal_error(Error_Code))Print_Error_Log(Error_Code);
			IO->IO_State_Error_Before = IO->IO_State;
			IO->IO_State = IO_State_Error;
			free(New_IO);
			return 0;
		}
		if (BIO_pending(New_IO->BIO->BIO_Write))/*SSL_write后可以调用*/
		{
			New_IO->WSABuffer.len = BIO_read(New_IO->BIO->BIO_Write, 0, Data_Length * 5/*加密后预留的长度*/);
			New_IO->WSABuffer.buf = (char*)malloc(New_IO->WSABuffer.len);/*BIO_read使用*/
			BIO_read(New_IO->BIO->BIO_Write, New_IO->WSABuffer.buf, New_IO->WSABuffer.len);
			if (int Error_Code = SSL_get_error(New_IO->Socket_SSL, New_IO->WSABuffer.len))
			{
#ifdef Process_X64
				printf("BIO_read失败%d Socket%lld\n", Error_Code, New_IO->Socket);
#else 
				printf("BIO_read失败%d Socket%d\n", Error_Code, New_IO->Socket);
#endif
				if (ssl_is_fatal_error(Error_Code))Print_Error_Log(Error_Code);
				IO->IO_State_Error_Before = IO->IO_State;
				IO->IO_State = IO_State_Error;
				free(New_IO->WSABuffer.buf);
				free(New_IO);
				return 0;
			}
		}
		New_IO->IO_State = IO_State_Handshaked_Write_SSL;/*必须在WSASend前,否则多线程可能会判断错误*/
		if (WSASend(New_IO->Socket, &New_IO->WSABuffer, 1, 0, 0, &New_IO->OVER_LAPPED, 0) == SOCKET_ERROR)
		{
			INT Error;
			if (WSA_IO_PENDING != (Error = WSAGetLastError()))
			{
#ifdef Process_X64
				printf("投递WSASend失败%d Socket%lld\n", Error, New_IO->Socket);
#else 
				printf("投递WSASend失败%d Socket%d\n", Error, New_IO->Socket);
#endif
				IO->IO_State_Error_Before = IO->IO_State;
				IO->IO_State = IO_State_Error;
				free(New_IO->WSABuffer.buf);
				free(New_IO);
				return 0;
			}
		}
		IO->IO_State_Delivery = IO_State_Handshaked_Write_SSL;
		return New_IO;
	}
	static char SSL_Load()
	{
		//SYSTEM_INFO info = { 0 };
		//GetNativeSystemInfo(&info);
		//info.dwNumberOfProcessors;
		Lock_SSL_Number = CRYPTO_num_locks();/*获取OpenSSL需要的锁数量*/
		if (Lock_SSL_Number > 0)
		{
			Lock_SSL = (RTL_CRITICAL_SECTION*)malloc(Lock_SSL_Number * sizeof(RTL_CRITICAL_SECTION));
			for (int i = 0; i < Lock_SSL_Number; ++i)InitializeCriticalSection(&Lock_SSL[i]);
		}
#ifdef _DEBUG
		//CRYPTO_malloc_debug_init();
		//CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
		CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
		CRYPTO_set_id_callback(&thread_id_callback);
		CRYPTO_set_locking_callback(&ssl_lock_callback);
		CRYPTO_set_dynlock_create_callback(&ssl_lock_dyn_create_callback);
		CRYPTO_set_dynlock_lock_callback(&ssl_lock_dyn_callback);
		CRYPTO_set_dynlock_destroy_callback(&ssl_lock_dyn_destroy_callback);
		SSL_load_error_strings();

		if (!SSL_library_init())/*初始化SSL库*/
		{
			ERR_print_errors_fp(stderr);
			return 0;
		}

		if (!SSL_library_init())/*初始化SSL库*/
		{
			ERR_print_errors_fp(stderr);
			return 0;
		}
		OpenSSL_add_ssl_algorithms();/*载入所有SSL算法*/
		OpenSSL_add_all_algorithms();/*加载算法库*/
		SSL_load_error_strings();

		//ErrBio = BIO_new_fd(2, BIO_NOCLOSE);

	}
#endif
	static bool 判断Socket状态(SOCKET Socket)
	{
		/*
		判断客户端Socket是否已经断开,否则在一个无效的Socket上投递WSARecv操作会出现异常
		使用的方法是尝试向这个socket发送数据,判断这个socket调用的返回值
		因为如果客户端网络异常断开(例如客户端崩溃或者拔掉网线等)的时候,服务器端是无法收到客户端断开的通知的
		*/
		if (-1 == send(Socket, "", 0, 0))return false;
		return true;
	}
};

