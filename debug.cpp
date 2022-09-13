// Copyright (C) 2014 oct0xor
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License 2.0 for more details.
// 
// A copy of the GPL 2.0 should have been included with the program.
// If not, see http ://www.gnu.org/licenses/

#define _WINSOCKAPI_

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <unordered_map>

#include <ida.hpp>
#include <ua.hpp>
#include <nalt.hpp>
#include <idd.hpp>
#include <segment.hpp>
#include <dbg.hpp>

#include "debmod.h"
#include <ps3tmapi.h>

#ifdef DECI3DBG_DEBUG
#define debug_printf msg
#else
#define debug_printf(...)
#endif

#define DEBUGGER_NAME "deci3"
#define DEBUGGER_ID_PLAYSTATION_3 15
#define PROCESSOR_NAME "ppc"

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res);
void get_threads_info(void);
void clear_all_bp(uint32 tid);
uint32 read_pc_register(uint32 tid);
uint32 read_lr_register(uint32 tid);
uint32 read_ctr_register(uint32 tid);
int do_step(uint32 tid, uint32 dbg_notification);

static const char idc_threadlst_args[] = {0};

std::vector<SNPS3TargetInfo*> Targets;
std::string TargetName;
HTARGET TargetID;
uint32 ProcessID;

bool LaunchTargetPicker = true;
bool AlwaysDC = false;
bool ForceDC = true;
bool WasOriginallyConnected = false;

static bool attaching = false; 
static bool singlestep = false;
static bool continue_from_bp = false;
static bool dabr_is_set = false;
uint32 dabr_addr;
uint8 dabr_type;

eventlist_t events;
SNPS3_DBG_EVENT_DATA target_event;

std::unordered_map<int, std::string> modules;
std::unordered_map<int, int> main_bpts_map;

std::vector<uint32> step_bpts;
std::vector<uint32> main_bpts;

static const unsigned char bpt_code[] = {0x7f, 0xe0, 0x00, 0x08};

#define STEP_INTO 15
#define STEP_OVER 16

#define RC_GENERAL 1
#define RC_FLOAT   2
//#define RC_VECTOR  3

struct regval
{
	uint64 lval;
	uint64 rval;
};
typedef struct regval regval;

//--------------------------------------------------------------------------
const char* register_classes[] =
{
  "General registers",
  "Floating point registers",
  /*"Velocity Engine/VMX/AltiVec", // 128-bit Vector Registers*/
  NULL
};

static const char *const CReg[] =
{
	"cr7",
	"cr7",
	"cr7",
	"cr7",
	"cr6",
	"cr6",
	"cr6",
	"cr6",
	"cr5",
	"cr5",
	"cr5",
	"cr5",
	"cr4",
	"cr4",
	"cr4",
	"cr4",
	"cr3",
	"cr3",
	"cr3",
	"cr3",
	"cr2",
	"cr2",
	"cr2",
	"cr2",
	"cr1",
	"cr1",
	"cr1",
	"cr1",
	"cr0",
	"cr0",
	"cr0",
	"cr0",
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

static const char *const vmx_format[] =
{
  "VMX 128 bit",
};

//--------------------------------------------------------------------------
register_info_t registers[] =
{
  { "r0",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r1",     REGISTER_ADDRESS | REGISTER_SP, RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r2",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r3",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r4",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r5",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r6",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r7",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r8",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r9",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r10",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r11",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r12",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r13",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r14",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r15",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r16",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r17",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r18",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r19",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r20",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r21",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r22",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r23",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r24",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r25",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r26",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r27",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r28",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r29",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r30",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "r31",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
																	  
  { "PC",     REGISTER_ADDRESS | REGISTER_IP, RC_GENERAL,  dt_qword,  NULL,   0 },
  { "CR",     NULL,							  RC_GENERAL,  dt_qword,  CReg,   0xFFFFFFFF },
  //{ "CR",     NULL,							  RC_GENERAL,  dt_qword,  NULL,   0 },
  { "LR",     REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
  { "CTR",    REGISTER_ADDRESS,               RC_GENERAL,  dt_qword,  NULL,   0 },
																	  
  { "f0",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f1",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f2",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f3",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f4",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f5",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f6",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f7",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f8",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f9",     NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f10",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f11",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f12",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f13",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f14",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f15",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f16",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f17",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f18",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f19",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f20",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f21",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f22",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f23",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f24",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f25",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f26",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f27",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f28",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f29",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f30",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },
  { "f31",    NULL,							  RC_FLOAT,    dt_qword,  NULL,   0 },

  /*{ "v0",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v1",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v2",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v3",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v4",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v5",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v6",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v7",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v8",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v9",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v10",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v11",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v12",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v13",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v14",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v15",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v16",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v17",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v18",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v19",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v20",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v21",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v22",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v23",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v24",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v25",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v26",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v27",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v28",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v29",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v30",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 },
  { "v31",	  REGISTER_CUSTFMT,				  RC_VECTOR,   dt_byte16, vmx_format,   0 }*/
};

uint32 registers_id[68] = {
	SNPS3_gpr_0,
	SNPS3_gpr_1,
	SNPS3_gpr_2,	
	SNPS3_gpr_3,	
	SNPS3_gpr_4,	
	SNPS3_gpr_5,	
	SNPS3_gpr_6,	
	SNPS3_gpr_7,	
	SNPS3_gpr_8,	
	SNPS3_gpr_9,	
	SNPS3_gpr_10,
	SNPS3_gpr_11,
	SNPS3_gpr_12,
	SNPS3_gpr_13,
	SNPS3_gpr_14,
	SNPS3_gpr_15,
	SNPS3_gpr_16,
	SNPS3_gpr_17,
	SNPS3_gpr_18,
	SNPS3_gpr_19,
	SNPS3_gpr_20,
	SNPS3_gpr_21,
	SNPS3_gpr_22,
	SNPS3_gpr_23,
	SNPS3_gpr_24,
	SNPS3_gpr_25,
	SNPS3_gpr_26,
	SNPS3_gpr_27,
	SNPS3_gpr_28,
	SNPS3_gpr_29,
	SNPS3_gpr_30,
	SNPS3_gpr_31,

	SNPS3_pc,
	SNPS3_cr,
	SNPS3_lr,
	SNPS3_ctr,
	//SNPS3_xer		// "XER"
	//SNPS3_fpscr	// "fpscr"
	//SNPS3_vscr	// "vscr"
	//SNPS3_vrsave  // "vrsave"
	//SNPS3_msr		// "msr"

	SNPS3_fpr_0,
	SNPS3_fpr_1,
	SNPS3_fpr_2,
	SNPS3_fpr_3,
	SNPS3_fpr_4,
	SNPS3_fpr_5,
	SNPS3_fpr_6,
	SNPS3_fpr_7,
	SNPS3_fpr_8,
	SNPS3_fpr_9,
	SNPS3_fpr_10,
	SNPS3_fpr_11,
	SNPS3_fpr_12,
	SNPS3_fpr_13,
	SNPS3_fpr_14,
	SNPS3_fpr_15,
	SNPS3_fpr_16,
	SNPS3_fpr_17,
	SNPS3_fpr_18,
	SNPS3_fpr_19,
	SNPS3_fpr_20,
	SNPS3_fpr_21,
	SNPS3_fpr_22,
	SNPS3_fpr_23,
	SNPS3_fpr_24,
	SNPS3_fpr_25,
	SNPS3_fpr_26,
	SNPS3_fpr_27,
	SNPS3_fpr_28,
	SNPS3_fpr_29,
	SNPS3_fpr_30,
	SNPS3_fpr_31,

	/*SNPS3_vmx_0,
	SNPS3_vmx_1,
	SNPS3_vmx_2,
	SNPS3_vmx_3,
	SNPS3_vmx_4,
	SNPS3_vmx_5,
	SNPS3_vmx_6,
	SNPS3_vmx_7,
	SNPS3_vmx_8,
	SNPS3_vmx_9,
	SNPS3_vmx_10,
	SNPS3_vmx_11,
	SNPS3_vmx_12,
	SNPS3_vmx_13,
	SNPS3_vmx_14,
	SNPS3_vmx_15,
	SNPS3_vmx_16,
	SNPS3_vmx_17,
	SNPS3_vmx_18,
	SNPS3_vmx_19,
	SNPS3_vmx_20,
	SNPS3_vmx_21,
	SNPS3_vmx_22,
	SNPS3_vmx_23,
	SNPS3_vmx_24,
	SNPS3_vmx_25,
	SNPS3_vmx_26,
	SNPS3_vmx_27,
	SNPS3_vmx_28,
	SNPS3_vmx_29,
	SNPS3_vmx_30,
	SNPS3_vmx_31*/
};

//-------------------------------------------------------------------------
static inline uint32 bswap32(uint32 x)
{
	return ( (x << 24) & 0xff000000 ) |
           ( (x <<  8) & 0x00ff0000 ) |
           ( (x >>  8) & 0x0000ff00 ) |
           ( (x >> 24) & 0x000000ff );
}

static inline uint64 bswap64(uint64 x)
{
	return ( (x << 56) & 0xff00000000000000ULL ) |
           ( (x << 40) & 0x00ff000000000000ULL ) |
           ( (x << 24) & 0x0000ff0000000000ULL ) |
           ( (x <<  8) & 0x000000ff00000000ULL ) |
           ( (x >>  8) & 0x00000000ff000000ULL ) |
           ( (x >> 24) & 0x0000000000ff0000ULL ) |
           ( (x >> 40) & 0x000000000000ff00ULL ) |
           ( (x >> 56) & 0x00000000000000ffULL );
}

//-------------------------------------------------------------------------
bool ConnectToActiveTarget()
{
	char* pszUsage = NULL;
	SNRESULT snr;
	// Connect to the target.
	if (SN_FAILED(snr = SNPS3Connect(TargetID, NULL)))
	{
		if (snr == SN_E_TARGET_IN_USE && ForceDC)
		{
			if (SN_FAILED( snr = SNPS3ForceDisconnect(TargetID) ))
			{
				debug_printf("Unable to force disconnect %s\n", CUTF8ToWChar(pszUsage).c_str());
				return false;
			}
			else
			{
				snr = SNPS3Connect(TargetID, NULL);
			}
		}

		if (SN_FAILED(snr))
		{
			debug_printf("Failed to connect to target\n");
			return false;
		}
	}
	else
	{
		WasOriginallyConnected = (snr == SN_S_NO_ACTION);
	}

	msg("Connected to target\n");
	return true;
}

//-------------------------------------------------------------------------
int __stdcall EnumCallBack(HTARGET hTarget)
{
	SNPS3TargetInfo ti;
	std::auto_ptr<SNPS3TargetInfo> pti(new SNPS3TargetInfo);

	if (pti.get())
	{
		ti.hTarget = hTarget;
		ti.nFlags = SN_TI_TARGETID;

		if (SN_S_OK == SNPS3GetTargetInfo(&ti))
		{
			// Store target parameters.
			pti->hTarget = hTarget;
			pti->pszName = strdup(ti.pszName);
			pti->pszHomeDir = strdup(ti.pszHomeDir);
			pti->pszFSDir = strdup(ti.pszFSDir);

			// Store this target.
			Targets.push_back(pti.release());
		}
		else
		{
			// Terminate enumeration.
			return 1;
		}
	}

	// Carry on with enumeration.
	return 0;
}

void SetTargetName(std::string targetName)
{ 
	TargetName = targetName; 
}

void SetTargetId(HTARGET hTargetId) 
{ 
	TargetID = hTargetId; 
}

bool FindFirstConnectedTarget(void)
{
	ECONNECTSTATUS nStatus = (ECONNECTSTATUS) -1;
	char*  pszUsage = 0;

	std::vector<SNPS3TargetInfo*>::iterator iter = Targets.begin();

	while (iter != Targets.end())
	{
		SNRESULT snr = SNPS3GetConnectStatus((*iter)->hTarget,	&nStatus, &pszUsage);

		if (SN_SUCCEEDED( snr ))
		{
			if (nStatus == CS_CONNECTED)
			{
				SNPS3TargetInfo ti;

				ti.hTarget = (*iter)->hTarget;
				ti.nFlags = SN_TI_TARGETID;

				if (SN_S_OK == SNPS3GetTargetInfo(&ti))
				{
					// Store target parameters.
					SetTargetId(ti.hTarget);
					SetTargetName(ti.pszName);

					return true;
				}
			}
		}
		iter++;
	}

	return false;
}

bool FindFirstAvailableTarget(void)
{
	uint   nStatus = -1;
	char*  pszUsage = 0;

	std::vector<SNPS3TargetInfo*>::iterator iter = Targets.begin();

	while (iter != Targets.end())
	{
		SNRESULT snr = SNPS3Connect((*iter)->hTarget, NULL);

		if (SN_SUCCEEDED( snr ))
		{
			SNPS3TargetInfo ti;

			ti.hTarget = (*iter)->hTarget;
			ti.nFlags = SN_TI_TARGETID;

			if (SN_S_OK == SNPS3GetTargetInfo(&ti))
			{
				// Store target parameters.
				SetTargetId(ti.hTarget);
				SetTargetName(ti.pszName);
				return true;
			}
		}

		iter++;
	}

	return false;
}

bool GetHostnames(const char* input, std::string& ipOut, std::string& dnsNameOut)
{
	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		return false;
	}

	sockaddr_in remotemachine;
	char hostname[NI_MAXHOST];

	remotemachine.sin_family = AF_INET;
	remotemachine.sin_addr.s_addr = inet_addr(input);

	// IP->Hostname
	DWORD dwRetVal = getnameinfo((SOCKADDR *)&remotemachine, 
		sizeof(sockaddr), 
		hostname, 
		NI_MAXHOST, 
		NULL, 
		0, 
		NI_NAMEREQD);

	if (dwRetVal == 0)
	{
		dnsNameOut = hostname;
		return true;
	}

	// Hostname -> IP
	struct hostent *remoteHost;
	remoteHost = gethostbyname(input);

	int i = 0;
	struct in_addr addr = { 0 };
	if (remoteHost && remoteHost->h_addrtype == AF_INET)
	{
		if (remoteHost->h_addr_list[0] != 0)
		{
			addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
			ipOut = inet_ntoa(addr);
			return true;
		}
	}

	WSACleanup();
	return false;
}

bool GetTargetFromAddress(const char *pszIPAddr, HTARGET &hTarget)
{
	TMAPI_TCPIP_CONNECT_PROP oConnection;
	std::vector<SNPS3TargetInfo*>::iterator iter = Targets.begin();

	while (iter != Targets.end())
	{
		if (SN_SUCCEEDED( SNPS3GetConnectionInfo((*iter)->hTarget, &oConnection) ))
		{
			if (wcscmp(UTF8ToWChar(std::string(pszIPAddr)).c_str(), CUTF8ToWChar(oConnection.szIPAddress)) == 0)
			{
				hTarget = (*iter)->hTarget;
				return true;
			}
		}

		++iter;
	}

	// If we didn't find a match there, do a DNS lookup
	std::string ipAddress;
	std::string dnsName;
	if (!GetHostnames(pszIPAddr, ipAddress, dnsName))
		return false;

	// Now iterate again
	iter = Targets.begin();

	while (iter != Targets.end())
	{
		if (SN_SUCCEEDED( SNPS3GetConnectionInfo((*iter)->hTarget, &oConnection) ))
		{
			if (wcscmp(UTF8ToWChar(ipAddress).c_str(), CUTF8ToWChar(oConnection.szIPAddress)) == 0
				|| wcscmp(UTF8ToWChar(dnsName).c_str(), CUTF8ToWChar(oConnection.szIPAddress)) == 0)
			{
				hTarget = (*iter)->hTarget;
				return true;
			}
		}

		++iter;
	}

	return false;
}

bool SetUpTarget(void)
{
	SNRESULT snr;

	// Enumerate available targets.
	if (SN_FAILED( snr = SNPS3EnumerateTargets(EnumCallBack) ))
	{
		debug_printf("Failed to enumerate targets\n");
		return false;
	}

	// Attempt to get the target name from an environment variable...

	if (LaunchTargetPicker)
	{
		debug_printf("Launching target picker...\n");
		if (SN_FAILED(snr = SNPS3PickTarget(NULL, &TargetID)))
		{
			debug_printf("Failed to pick target\n");
			return false;
		}

		SNPS3TargetInfo targetInfo = {};
		targetInfo.hTarget = TargetID;
		targetInfo.nFlags = SN_TI_TARGETID;

		if (SN_FAILED( snr = SNPS3GetTargetInfo(&targetInfo) ))
		{
			debug_printf("Failed to get target info\n");
			return false;
		}

		TargetName = std::string(targetInfo.pszName);
	}

	if (TargetName.empty())
	{
		wchar_t* pEnv = _wgetenv(L"PS3TARGET");
		if (pEnv)
			TargetName = WCharToUTF8(pEnv);
	}

	if (Targets.size() == 1 && TargetName.empty())
	{
		TargetName = Targets[0]->pszName;
	}

	// If no target has been selected then use the default target
	if (TargetName.empty())
	{
		if (SN_S_OK == SNPS3GetDefaultTarget(&TargetID))
		{
			SNPS3TargetInfo targetInfo = {};
			targetInfo.hTarget = TargetID;
			targetInfo.nFlags = SN_TI_TARGETID;

			if (SN_FAILED( snr = SNPS3GetTargetInfo(&targetInfo) ))
			{
				debug_printf("Failed to get target info\n");
				return false;
			}

			TargetName = std::string(targetInfo.pszName);
		}
	}
	
	// If no target has been selected then use the first one connected or the first one available.
	if (TargetName.empty())
	{
		if (!FindFirstConnectedTarget())
		{
			FindFirstAvailableTarget();
		}
	}
	// Retrieve the target ID from the name or failing that IP.
	if (SN_FAILED(snr = SNPS3GetTargetFromName(TargetName.c_str(), &TargetID)))
	{
		if (!GetTargetFromAddress(TargetName.c_str(), TargetID))
		{
			debug_printf("Failed to find target! Please ensure target name/ip/hostname is correct\n");
			return false;
		}
	}

	return true;
}

//--------------------------------------------------------------------------
void Kick()
{
	SNRESULT snr = SN_S_OK;
	int Kicks = 0;

	do
	{
		snr = SNPS3Kick();
		++Kicks;
	
	} while (snr == SN_S_OK);
}

//--------------------------------------------------------------------------
//  Process target specific events (see TargetEventCallback).
static void ProcessTargetSpecificEvent(uint uDataLen, byte *pData)
{
	SNPS3_DBG_EVENT_HDR *pDbgHeader = (SNPS3_DBG_EVENT_HDR *)pData;
	SNPS3_DBG_EVENT_DATA *pDbgData = (SNPS3_DBG_EVENT_DATA *)(pData + sizeof(SNPS3_DBG_EVENT_HDR));
	debug_event_t ev;
	SNRESULT snr = SN_S_OK;

	switch (pDbgData->uEventType)
	{
	case SNPS3_DBG_EVENT_PROCESS_CREATE:
		{
			debug_printf("SNPS3_DBG_EVENT_PROCESS_CREATE\n");
		}
		break;

	case SNPS3_DBG_EVENT_PROCESS_EXIT:
		{
			debug_printf("SNPS3_DBG_EVENT_PROCESS_EXIT\n");

			ev.pid     = ProcessID;
			ev.tid     = NO_THREAD;
			ev.ea      = BADADDR;
			ev.handled = true;
			ev.set_exit_code(PROCESS_EXITED, bswap64(pDbgData->ppu_process_exit.uExitCode));

			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_TRAP:
		{
			debug_printf("-> SNPS3_DBG_EVENT_PPU_EXP_TRAP <-\n");

			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_trap.uPPUThreadID), bswap64(pDbgData->ppu_exc_trap.uPC));

			if (target_event.uEventType == SNPS3_DBG_EVENT_PPU_EXP_TRAP)
				break;

			if (singlestep == true || continue_from_bp == true) {

				uint32 addr;
				std::vector<uint32>::iterator it;

				ev.set_eid(STEP);
				ev.pid     = ProcessID;
				ev.tid     = bswap64(pDbgData->ppu_exc_trap.uPPUThreadID);
				ev.ea      = bswap64(pDbgData->ppu_exc_trap.uPC);
				ev.handled = true;

				events.enqueue(ev, IN_BACK);

				while (!step_bpts.empty())
				{
					addr = step_bpts.back();
					step_bpts.pop_back();

					it = std::find(main_bpts.begin(), main_bpts.end(), addr);
					if (it == main_bpts.end()) {

						main_bpts_map.erase(addr);

						if (SN_FAILED( snr = SNPS3ClearBreakPoint(TargetID, PS3_UI_CPU, ProcessID, bswap64(pDbgData->ppu_exc_trap.uPPUThreadID), addr)))
						{
							msg("SNPS3ClearBreakPoint Error: %d\n", snr);

						} else {

							debug_printf("step bpt cleared\n");
						}
					}

				}

				if (continue_from_bp == true)
				{
					continue_from_bp = false;
				} else {
					singlestep = false;
				}

			} else {

				ev.pid     = ProcessID;
				ev.tid     = bswap64(pDbgData->ppu_exc_trap.uPPUThreadID);
				ev.ea      = bswap64(pDbgData->ppu_exc_trap.uPC);
				ev.handled = true;
				ev.set_bpt();

				events.enqueue(ev, IN_BACK);

			}
		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_PREV_INT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_PREV_INT\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_prev_int.uPPUThreadID), bswap64(pDbgData->ppu_exc_prev_int.uPC));

			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_prev_int.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;

			struct excinfo_t exc = ev.set_exception();
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_prev_int.uPC);
			exc.info = "privilege instruction";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_ALIGNMENT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_ALIGNMENT\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_alignment.uPPUThreadID), bswap64(pDbgData->ppu_exc_alignment.uPC));

			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_alignment.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			struct excinfo_t exc = ev.set_exception();

			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_alignment.uPC);
			exc.info = "alignment interrupt";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_ILL_INST:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_ILL_INST\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_ill_inst.uPPUThreadID), bswap64(pDbgData->ppu_exc_ill_inst.uPC));
			debug_printf("DSISR = 0x%llX\n", bswap64(pDbgData->ppu_exc_ill_inst.uDSISR));

			excinfo_t& exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_ill_inst.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_ill_inst.uPC);
			exc.info = "illegal instruction";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_TEXT_HTAB_MISS:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_TEXT_HTAB_MISS\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_text_htab_miss.uPPUThreadID), bswap64(pDbgData->ppu_exc_text_htab_miss.uPC));
			
			excinfo_t& exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_text_htab_miss.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_text_htab_miss.uPC);
			exc.info = "instruction storage interrupt";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_TEXT_SLB_MISS:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_TEXT_SLB_MISS\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_text_slb_miss.uPPUThreadID), bswap64(pDbgData->ppu_exc_text_slb_miss.uPC));
			
			excinfo_t& exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_text_slb_miss.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_text_slb_miss.uPC);
			exc.info = "instruction segment interrupt";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_DATA_HTAB_MISS:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_DATA_HTAB_MISS\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_data_htab_miss.uPPUThreadID), bswap64(pDbgData->ppu_exc_data_htab_miss.uPC));

			excinfo_t& exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_data_htab_miss.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_data_htab_miss.uPC);
			exc.info = "data storage interrupt";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_FLOAT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_FLOAT\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_float.uPPUThreadID), bswap64(pDbgData->ppu_exc_float.uPC));

			excinfo_t& exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_float.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = true;
			exc.ea = bswap64(pDbgData->ppu_exc_float.uPC);
			exc.info = "floating point enabled exception";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_DATA_SLB_MISS:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_DATA_SLB_MISS\n");
			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_data_slb_miss.uPPUThreadID), bswap64(pDbgData->ppu_exc_data_slb_miss.uPC));

			excinfo_t&  exc = ev.set_exception();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_data_slb_miss.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			exc.code = 0;
			exc.can_cont = false;
			exc.ea = bswap64(pDbgData->ppu_exc_data_slb_miss.uPC);
			exc.info = "data segment interrupt";
			
			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_EXP_DABR_MATCH:
		{
			debug_printf("-> SNPS3_DBG_EVENT_PPU_EXP_DABR_MATCH <-\n");

			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_dabr_match.uPPUThreadID), bswap64(pDbgData->ppu_exc_dabr_match.uPC));

			if (target_event.uEventType == SNPS3_DBG_EVENT_PPU_EXP_DABR_MATCH)
				break;
			
			bptaddr_t& bpt = ev.set_bpt();
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_exc_dabr_match.uPPUThreadID);
			ev.ea      = bswap64(pDbgData->ppu_exc_dabr_match.uPC);
			ev.handled = true;
			bpt.hea = dabr_addr;
			bpt.kea = BADADDR;
			ev.exc().ea = BADADDR;
			
			events.enqueue(ev, IN_BACK);
		}
		break;

	//! Notification that a PPU thread was stopped by DBGP_STOP_PPU_THREAD.
	case SNPS3_DBG_EVENT_PPU_EXP_STOP:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_STOP\n");

			debug_printf("ThreadID = 0x%llX, PC = 0x%llX\n", bswap64(pDbgData->ppu_exc_stop.uPPUThreadID), bswap64(pDbgData->ppu_exc_stop.uPC));

			//suspend_thread(bswap64(pDbgData->ppu_exc_stop.uPPUThreadID));

		}
		break;

	//! Notification that a primary PPU thread was stopped at entry point after process was created.
	case SNPS3_DBG_EVENT_PPU_EXP_STOP_INIT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXP_STOP_INIT\n");
			//pDbgData->ppu_exc_stop_init;
		}
		break;

	//! Notification that a memory access trap interrupt occurred.
	case SNPS3_DBG_EVENT_PPU_EXC_DATA_MAT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_EXC_DATA_MAT\n");
			//pDbgData->ppu_exc_data_mat;
		}
		break;

	case SNPS3_DBG_EVENT_PPU_THREAD_CREATE:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_THREAD_CREATE\n");

			debug_printf("ThreadID = 0x%llX\n", bswap64(pDbgData->ppu_thread_create.uPPUThreadID));

			ev.set_eid(THREAD_STARTED);
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_thread_create.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;

			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PPU_THREAD_EXIT:
		{
			debug_printf("SNPS3_DBG_EVENT_PPU_THREAD_EXIT\n");

			debug_printf("ThreadID = 0x%llX\n", bswap64(pDbgData->ppu_thread_exit.uPPUThreadID));

			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->ppu_thread_exit.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			ev.set_exit_code(THREAD_EXITED, 0);

			events.enqueue(ev, IN_BACK);

		}
		break;

	case SNPS3_DBG_EVENT_PRX_LOAD:
		{
			debug_printf("SNPS3_DBG_EVENT_PRX_LOAD\n");

			debug_printf("ThreadID = 0x%llX, ModuleID = 0x%X\n", bswap64(pDbgData->prx_load.uPPUThreadID), bswap32(pDbgData->prx_load.uPRXID));

			uint64 ModuleInfoSize = 1024;
			SNPS3MODULEINFO *ModuleInfo;

			ModuleInfo = (SNPS3MODULEINFO *)malloc(ModuleInfoSize);

			SNPS3GetModuleInfo(TargetID, ProcessID, bswap32(pDbgData->prx_load.uPRXID), &ModuleInfoSize, ModuleInfo);

			modinfo_t& modinfo = ev.set_modinfo(LIB_LOADED);
			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->prx_load.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;
			

			modinfo.name.clear();
			modinfo.name += ModuleInfo->Hdr.aElfName;
			modinfo.name += " - ";
			modinfo.name += ModuleInfo->Hdr.aName;

			
			modinfo.base = ModuleInfo->Segments->uBase;
			modinfo.size = ModuleInfo->Segments->uMemSize;
			modinfo.rebase_to = BADADDR;
			
			events.enqueue(ev, IN_BACK);

			modules[bswap32(pDbgData->prx_load.uPRXID)] = modinfo.name.c_str();

			free(ModuleInfo);
		}
		break;

	case SNPS3_DBG_EVENT_PRX_UNLOAD:
		{
			debug_printf("SNPS3_DBG_EVENT_PRX_UNLOAD\n");

			debug_printf("ThreadID = 0x%llX, ModuleID = 0x%X\n", bswap64(pDbgData->prx_unload.uPPUThreadID), bswap32(pDbgData->prx_unload.uPRXID));

			ev.pid     = ProcessID;
			ev.tid     = bswap64(pDbgData->prx_unload.uPPUThreadID);
			ev.ea      = BADADDR;
			ev.handled = true;

			qstring& info = ev.set_info(LIB_UNLOADED);
			info.clear();
			info += modules[bswap32(pDbgData->prx_unload.uPRXID)].c_str();
		
			events.enqueue(ev, IN_BACK);

			modules.erase(bswap32(pDbgData->prx_unload.uPRXID));
		}
		break;

	}
}

//--------------------------------------------------------------------------
//  Prints details of received target events.
static void ProcessTargetEvent(HTARGET hTarget, uint uDataLen, byte *pData)
{
	uint uDataRemaining = uDataLen;

	while (uDataRemaining)
	{
		SN_EVENT_TARGET_HDR *pHeader = (SN_EVENT_TARGET_HDR *)pData;

		switch (pHeader->uEvent)
		{
		case SN_TGT_EVENT_TARGET_SPECIFIC:
			{
				ProcessTargetSpecificEvent(pHeader->uSize, pData + sizeof(SN_EVENT_TARGET_HDR));

				memcpy(&target_event, pData + sizeof(SN_EVENT_TARGET_HDR) + sizeof(SNPS3_DBG_EVENT_HDR), 0x20);

				break;
			}
		}

		uDataRemaining -= pHeader->uSize;
		pData += pHeader->uSize;
	}
}

//--------------------------------------------------------------------------
//  Process target event notifications.
static void __stdcall TargetEventCallback(HTARGET hTarget, uint uEventType, uint /*uEvent*/, 
						 SNRESULT snr, uint uDataLen, byte *pData, void* /*pUser*/)
{
	if (SN_FAILED( snr ))
		return;

	switch (uEventType)
	{
	case SN_EVENT_TARGET:
		ProcessTargetEvent(hTarget, uDataLen, pData);
		break;
	}
}

//--------------------------------------------------------------------------
// Initialize debugger
static bool idaapi init_debugger(const char *hostname, int port_num, const char *password, qstring* errbuf)
{
	SNRESULT snr = SN_S_OK;

	if (SN_FAILED( snr = SNPS3InitTargetComms() ))
	{
		msg("Failed to initialize PS3TM SDK\n");
		return false;
	}
	else {
		msg("SNPS3InitTargetComms succeeded\n");
	}

	if (!SetUpTarget() || !ConnectToActiveTarget())
	{
		msg("Error connecting to target %s!\n", UTF8ToWChar(TargetName).c_str());
		return false;
	}

	SNPS3RegisterTargetEventHandler(TargetID, TargetEventCallback, NULL);

	//set_idc_func_ex("threadlst", idc_threadlst, idc_threadlst_args, 0); ///XXX: do thread list

	return true;
}

//--------------------------------------------------------------------------
// Terminate debugger
static bool idaapi term_debugger(void)
{
	// Do post stuff like disconnecting from target
	if (AlwaysDC || (!WasOriginallyConnected))
	{
		if (TargetID != 0xffffffff)
		{
			SNPS3Disconnect(TargetID);
			debug_printf("Disconnect\n");
		}
	}

	SNPS3CloseTargetComms();
	//SNPS3Exit();

	///set_idc_func_ex("threadlst", NULL, idc_threadlst_args, 0); ///XXX: do thread list

	return true;
}

//--------------------------------------------------------------------------
int idaapi process_get_info(procinfo_vec_t* procInfo, qstring *errbuf)
{
	uint32 NumProcesses;
	uint32* ProcessesList;
	SNPS3PROCESSINFO* ProcessesInfo;
	uint32 ProcessesInfoSize;
	SNRESULT snr = SN_S_OK;
	char* p;

	if (SN_FAILED( snr = SNPS3ProcessList(TargetID, &NumProcesses, NULL)))
	{
		debug_printf("SNPS3ProcessList 1 Error: %d\n", snr);
		return DRC_NONE;
	}

	if (NumProcesses < 1)
		return DRC_NONE;

	ProcessesList = (uint32 *)malloc(NumProcesses * sizeof(uint32));

	if (SN_FAILED( snr = SNPS3ProcessList(TargetID, &NumProcesses, ProcessesList)))
	{
		debug_printf("SNPS3ProcessList 2 Error: %d\n", snr);
		return DRC_NONE;
	}

	debug_printf("Got %d processes\n", NumProcesses);

	for (int n = 0; n < NumProcesses; n++) {
		snr = SNPS3ProcessInfo(TargetID, ProcessesList[n], &ProcessesInfoSize, NULL);

		ProcessesInfo = (SNPS3PROCESSINFO*)malloc(ProcessesInfoSize);

		if (SN_FAILED(snr = SNPS3ProcessInfo(TargetID, ProcessesList[n], &ProcessesInfoSize, ProcessesInfo)))
		{
			debug_printf("SNPS3ProcessInfo Error: %d\n", snr);
			//return DRC_NONE;
		}
		else {
			process_info_t& info = procInfo->push_back();
			info.pid = ProcessesList[n];
			info.name = ProcessesInfo->Hdr.szPath;
			debug_printf("Found process: %s\n", info.name.c_str());
		}

		free(ProcessesInfo);
	}

	free(ProcessesList);

	return DRC_OK;
}

static const char *get_state_name(uint32 State)
{
	switch ( State )
	{
		case SNPS3_PPU_IDLE:			return "IDLE";
		case SNPS3_PPU_RUNNABLE:        return "RUNNABLE";
		case SNPS3_PPU_ONPROC:			return "ONPROC";
		case SNPS3_PPU_SLEEP:			return "SLEEP";
		case SNPS3_PPU_SUSPENDED:       return "SUSPENDED";
		case SNPS3_PPU_SLEEP_SUSPENDED: return "SLEEP_SUSPENDED";
		case SNPS3_PPU_STOP:			return "STOP";
		case SNPS3_PPU_ZOMBIE:			return "ZOMBIE";
		case SNPS3_PPU_DELETED:			return "DELETED";
		default:						return "???";
	}
}

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res)
{
	get_threads_info();
	return eOk;
}

void get_threads_info(void)
{
	uint32 NumPPUThreads;
	uint32 NumSPUThreadGroups;
	uint64 *PPUThreadIDs;
	uint64 *SPUThreadGroupIDs;
	uint32 ThreadInfoSize = 1024;
	SNPS3_PPU_THREAD_INFO *ThreadInfo;
	SNRESULT snr = SN_S_OK;
	debug_event_t ev;

	SNPS3ThreadList(TargetID, ProcessID, &NumPPUThreads, NULL, &NumSPUThreadGroups, NULL);

	PPUThreadIDs = (uint64 *)malloc(NumPPUThreads * sizeof(uint64));
	SPUThreadGroupIDs = (uint64 *)malloc(NumSPUThreadGroups * sizeof(uint64));

	SNPS3ThreadList(TargetID, ProcessID, &NumPPUThreads, PPUThreadIDs, &NumSPUThreadGroups, SPUThreadGroupIDs);

	ThreadInfo = (SNPS3_PPU_THREAD_INFO *)malloc(ThreadInfoSize);

	//debug_printf(" === PPU THREAD INFO === \n");

	for(uint32 i=0;i<NumPPUThreads;i++) {

		ThreadInfoSize = 1024;

		if (SN_FAILED( snr = SNPS3ThreadInfo(TargetID, PS3_UI_CPU, ProcessID, PPUThreadIDs[i], &ThreadInfoSize, (byte *)ThreadInfo)))
		{
			msg("SNPS3ThreadInfo Error: %d\n", snr);

		} else {

			msg("[%d] ThreadID: 0x%llX, State: %s, Name: %s\n", i, ThreadInfo->uThreadID, get_state_name(ThreadInfo->uState), (const char*)(ThreadInfo + 1));

			if (attaching == true) 
			{
				qstring &info = ev.set_info(THREAD_STARTED);
				ev.pid     = ProcessID;
				ev.tid     = ThreadInfo->uThreadID;

				info.clear();
				info += (const char*)(ThreadInfo + 1);
				
				ev.ea      = read_pc_register((uint32)ThreadInfo->uThreadID);
				ev.handled = true;

				events.enqueue(ev, IN_BACK);

				clear_all_bp(ThreadInfo->uThreadID);

				if (ThreadInfo->uState == SNPS3_PPU_STOP)
				{
					//suspend_thread(ThreadInfo->uThreadID);
				}
			}
		}
	}

	//debug_printf(" === END === \n");

	free(ThreadInfo);

	free(PPUThreadIDs);
	free(SPUThreadGroupIDs);
}

int get_thread_state(uint32 tid)
{
	SNRESULT snr = SN_S_OK;
	uint32 ThreadInfoSize = 1024;
	SNPS3_PPU_THREAD_INFO *ThreadInfo;
	int state;

	ThreadInfo = (SNPS3_PPU_THREAD_INFO *)malloc(ThreadInfoSize);

	if (SN_FAILED( snr = SNPS3ThreadInfo(TargetID, PS3_UI_CPU, ProcessID, tid, &ThreadInfoSize, (byte *)ThreadInfo)))
	{
		msg("SNPS3ThreadInfo Error: %d\n", snr);
		state = -1;

	} else {

		msg("ThreadID: 0x%llX, State: %s, Name: %s\n", ThreadInfo->uThreadID, get_state_name(ThreadInfo->uState), (const char*)(ThreadInfo + 1));
		state = ThreadInfo->uState;
	}

	free(ThreadInfo);

	return state;
}

void get_modules_info(void)
{
	uint32 NumModules;
	uint32 *ModuleIDs;
	uint64 ModuleInfoSize = 1024;
	SNPS3MODULEINFO *ModuleInfo;
	SNRESULT snr = SN_S_OK;
	debug_event_t ev;

	SNPS3GetModuleList(TargetID, ProcessID, &NumModules, NULL);

	ModuleIDs = (uint32 *)malloc(NumModules * sizeof(uint32));

	SNPS3GetModuleList(TargetID, ProcessID, &NumModules, ModuleIDs);

	ModuleInfo = (SNPS3MODULEINFO *)malloc(ModuleInfoSize);

	//debug_printf(" === MODULE INFO === \n");

	for(uint32 i=0;i<NumModules;i++) {

		ModuleInfoSize = 1024;

		if (SN_FAILED( snr = SNPS3GetModuleInfo(TargetID, ProcessID, ModuleIDs[i], &ModuleInfoSize, ModuleInfo)))
		{
			msg("SNPS3GetModuleInfo Error: %d\n", snr);

		} else {

			//debug_printf("[%d] ModuleID: 0x%X, %s, %s, Version: 0x%X, Attribute: 0x%X, StartEntry: 0x%X, StopEntry: 0x%X, Segments: %d\n", i, ModuleIDs[i], ModuleInfo->Hdr.aElfName, ModuleInfo->Hdr.aName, *(uint16 *)ModuleInfo->Hdr.aVersion, ModuleInfo->Hdr.uAttribute, ModuleInfo->Hdr.uStartEntry, ModuleInfo->Hdr.uStopEntry, ModuleInfo->Hdr.uNumSegments);

			if (attaching == true)
			{
				modinfo_t& modinfo = ev.set_modinfo(LIB_LOADED);
				ev.pid     = ProcessID;
				ev.tid     = NO_THREAD;
				ev.ea      = BADADDR;
				ev.handled = true;

				modinfo.name.clear();
				modinfo.name += ModuleInfo->Hdr.aElfName;
				modinfo.name += " - ";
				modinfo.name += ModuleInfo->Hdr.aName;

				modinfo.base = ModuleInfo->Segments->uBase;
				modinfo.size = ModuleInfo->Segments->uMemSize;
				modinfo.rebase_to = BADADDR;

				events.enqueue(ev, IN_BACK);

				modules[ModuleIDs[i]] = modinfo.name.c_str();
			}

			for(uint32 j=0;j<ModuleInfo->Hdr.uNumSegments;j++) {

				//debug_printf("\t %lld: Base: 0x%llX, FileSize: 0x%llX, MemSize: 0x%llX, ElfType: 0x%llX\n", ModuleInfo->Segments[j].uIndex, ModuleInfo->Segments[j].uBase, ModuleInfo->Segments[j].uFileSize, ModuleInfo->Segments[j].uMemSize, ModuleInfo->Segments[j].uElfType);

			}
		}
	}

	//debug_printf(" === END === \n");

	free(ModuleInfo);

	free(ModuleIDs);
}

void clear_all_bp(uint32 tid)
{
	uint32 BPCount;
	uint64 *BPAddress;

	SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, tid, &BPCount, NULL);

	if (BPCount != 0)
	{
		BPAddress = (uint64 *)malloc(BPCount * sizeof(uint64));

		SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, tid, &BPCount, BPAddress);

		for(uint32 i=0;i<BPCount;i++) {

			SNPS3ClearBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, BPAddress[i]);

		}

		SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, tid, &BPCount, NULL);

		free(BPAddress);
	}
}

void bp_list(void)
{
	uint32 BPCount;
	uint64 *BPAddress;

	SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, NULL);

	if (BPCount != 0)
	{
		BPAddress = (uint64 *)malloc(BPCount * sizeof(uint64));

		SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, BPAddress);

		for(uint32 i=0;i<BPCount;i++) {

			msg("0x%llX\n", BPAddress[i]);

		}

		free(BPAddress);
	}
}

int addr_has_bp(uint32 ea)
{
	uint32 BPCount;
	uint64 *BPAddress;

	SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, NULL);

	if (BPCount != 0)
	{
		BPAddress = (uint64 *)malloc(BPCount * sizeof(uint64));

		SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, BPAddress);

		for(uint32 i=0;i<BPCount;i++) {

			if (ea == BPAddress[i])
			{
				return 1;
			}
		}

		free(BPAddress);
	}

	return 0;
}

//--------------------------------------------------------------------------
// Start an executable to debug
static int idaapi deci3_start_process(const char *path,
                              const char *args,
                              const char *startdir,
                              int dbg_proc_flags,
                              const char *input_path,
                              uint32 input_file_crc32)
{
	SNRESULT snr = SN_S_OK;
	//uint64 tid;

	debug_printf("start_process\n");
	debug_printf("path: %s\n", path);

	//SNPS3Reset(TargetID, SNPS3TM_RESETP_QUICK_RESET);

	SNPS3Reset(TargetID, SNPS3TM_BOOTP_DEFAULT);

	//SNPS3ResetEx(TargetID, SNPS3TM_BOOTP_DEBUG_MODE, SNPS3TM_BOOTP_SYSTEM_MODE, 0, (uint64) -1, 0, 0);

	if (SN_FAILED( snr = SNPS3ProcessLoad(TargetID, SNPS3_DEF_PROCESS_PRI, path, 0, NULL, 0, NULL, &ProcessID, NULL, SNPS3_LOAD_FLAG_ENABLE_DEBUGGING | SNPS3_LOAD_FLAG_USE_ELF_PRIORITY | SNPS3_LOAD_FLAG_USE_ELF_STACKSIZE)))
	{
		msg("SNPS3ProcessLoad Error: %d\n", snr);
		return DRC_NONE;
	}

	debug_printf("ProcessID: 0x%X\n", ProcessID);

	/*debug_event_t ev;
	ev.eid     = PROCESS_START;
	ev.pid     = ProcessID;
	ev.tid     = NO_THREAD;
	ev.ea      = BADADDR;
	ev.handled = true;

    qstrncpy(ev.modinfo.name, path, sizeof(ev.modinfo.name));
    ev.modinfo.base = 0x10200;
    ev.modinfo.size = 0;
    ev.modinfo.rebase_to = BADADDR;

	events.enqueue(ev, IN_BACK);*/

	return DRC_OK;
}

//--------------------------------------------------------------------------
// Attach to an existing running process
drc_t deci3_attach_process(pid_t process_id,
	int event_id,
	int flags,
	qstring* errbuf)
{
	debug_event_t ev;

	modinfo_t& modinfo = ev.set_modinfo(PROCESS_STARTED);
	modinfo.base = 0x10200;
	modinfo.size = 0;
	modinfo.rebase_to = BADADDR;

	ev.pid = ProcessID;
	ev.tid = NO_THREAD;
	ev.ea = BADADDR;
	ev.handled = true;

	SNRESULT snr;
	//block the process until all generated events are processed
	attaching = true;

	SNPS3ProcessAttach(TargetID, PS3_UI_CPU, process_id);
	ProcessID = process_id;

	UINT32 ProcessesInfoSize;
	if (SN_FAILED(snr = SNPS3ProcessInfo(TargetID, ProcessID, &ProcessesInfoSize, NULL))) {
		debug_printf("SNPS3ProcessInfo Error: %d\n", snr);
		return DRC_NONE;
	}

	SNPS3PROCESSINFO *ProcessesInfo = (SNPS3PROCESSINFO*)malloc(ProcessesInfoSize);
	if (ProcessesInfo == NULL) {
		return DRC_NONE;
	}
	if (SN_FAILED(snr = SNPS3ProcessInfo(TargetID, ProcessID, &ProcessesInfoSize, ProcessesInfo))) {
		debug_printf("SNPS3ProcessInfo Error: %d\n", snr);
		return DRC_NONE;
	}
	
	modinfo.name += ProcessesInfo->Hdr.szPath;

	events.enqueue(ev, IN_BACK);

	get_threads_info();
	get_modules_info();
	clear_all_bp(-1);

	modinfo_t& modinfo_pa = ev.set_modinfo(PROCESS_ATTACHED);
	modinfo_pa.base = 0x10200;
	modinfo_pa.size = 0;
	modinfo_pa.rebase_to = BADADDR;
	modinfo_pa.name += ProcessesInfo->Hdr.szPath;

    events.enqueue(ev, IN_BACK);

	free(ProcessesInfo);

    return DRC_OK;
}

//--------------------------------------------------------------------------
int idaapi deci3_detach_process(void)
{
	// TMAPI cant detach

	debug_event_t ev;
    ev.set_eid(PROCESS_DETACHED);
    ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

    return 1;
}

//-------------------------------------------------------------------------
void idaapi rebase_if_required_to(ea_t new_base)
{
}

//--------------------------------------------------------------------------
int idaapi prepare_to_pause_process(void)
{
	SNPS3ProcessStop(TargetID, ProcessID);

	debug_event_t ev;
	ev.set_eid(PROCESS_SUSPENDED);
	ev.pid     = ProcessID;

    events.enqueue(ev, IN_BACK);

	return 1;
}

//--------------------------------------------------------------------------
int idaapi deci3_exit_process(void)
{
	//SNPS3ProcessKill
	//SNPS3TerminateGameProcess

    debug_event_t ev;
    ev.pid     = ProcessID;
    ev.tid     = NO_THREAD;
    ev.ea      = BADADDR;
	ev.set_exit_code(PROCESS_EXITED, 0);
    ev.handled = true;

    events.enqueue(ev, IN_BACK);

	return 1;
}

#ifdef DECI3DBG_DEBUG

static const char *get_event_name(event_id_t id)
{
	switch ( id )
	{
		case NO_EVENT:        return "NO_EVENT";
		case THREAD_STARTED:    return "THREAD_START";
		case THREAD_EXITED:     return "THREAD_EXIT";
		case PROCESS_ATTACHED:  return "PROCESS_ATTACH";
		case PROCESS_DETACHED:  return "PROCESS_DETACH";
		case PROCESS_STARTED:   return "PROCESS_START";
		case PROCESS_SUSPENDED: return "PROCESS_SUSPEND";
		case PROCESS_EXITED:    return "PROCESS_EXIT";
		case LIB_LOADED:    return "LIBRARY_LOAD";
		case LIB_UNLOADED:  return "LIBRARY_UNLOAD";
		case BREAKPOINT:      return "BREAKPOINT";
		case STEP:            return "STEP";
		case EXCEPTION:       return "EXCEPTION";
		case INFORMATION:     return "INFORMATION";
		//case SYSCALL:         return "SYSCALL";
		//case WINMESSAGE:      return "WINMESSAGE";
		default:              return "???";
	}

}

#endif

//--------------------------------------------------------------------------
// Get a pending debug event and suspend the process
gdecode_t idaapi get_debug_event(debug_event_t *event, int ida_is_idle)
{
	if ( event == NULL )
		return GDE_NO_EVENT;

	while ( true )
	{
		if ( events.retrieve(event) )
		{

#ifdef DECI3DBG_DEBUG

			if (event->eid() == BREAKPOINT && event->bpt().hea != BADADDR)
			{
				debug_printf("get_debug_event: BREAKPOINT (HW)\n");

			} else {

				debug_printf("get_debug_event: %s\n", get_event_name(event->eid()));
			}

#endif

			if (event->eid() == PROCESS_ATTACHED)
			{
				attaching = false;
			}

			if (attaching == false) 
			{
				memset(&target_event, 0, 0x20);

				Kick();
			}

			return GDE_ONE_EVENT;
		}

		if (events.empty())
			break;

	};

	if (attaching == false)
	{
		memset(&target_event, 0, 0x20);

		Kick();
	}

	return GDE_NO_EVENT;
}

//--------------------------------------------------------------------------
// Continue after handling the event
int idaapi continue_after_event(const debug_event_t *event)
{
	if ( event == NULL )
		return false;

#ifdef DECI3DBG_DEBUG

	if (event->eid() == BREAKPOINT && event->bpt().hea != BADADDR)
	{
		debug_printf("continue_after_event: BREAKPOINT (HW)\n");

	} else {

		debug_printf("continue_after_event: %s\n", get_event_name(event->eid()));
	}

#endif

	if (event->eid() == PROCESS_ATTACHED || event->eid() == PROCESS_SUSPENDED || event->eid() == STEP || event->eid() == BREAKPOINT) {

		if (event->eid() == BREAKPOINT)
		{
			if (addr_has_bp(event->ea))
			{	
				SNPS3ClearBreakPoint(TargetID, PS3_UI_CPU, ProcessID, -1, event->ea);

				do_step(event->tid, 0);

				SNPS3ProcessContinue(TargetID, ProcessID);

				memset(&target_event, 0, 0x20);

				continue_from_bp = true;

				Kick();

				SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, -1, event->ea);
			}

			if (event->bpt().hea == dabr_addr)
			{
				SNPS3SetDABR(TargetID, ProcessID, dabr_addr | 4);

				do_step(event->tid, 0);

				SNPS3ProcessContinue(TargetID, ProcessID);

				memset(&target_event, 0, 0x20);

				continue_from_bp = true;

				Kick();

				SNPS3SetDABR(TargetID, ProcessID, dabr_addr | dabr_type);

			}
		}

		SNPS3ProcessContinue(TargetID, ProcessID);

		memset(&target_event, 0, 0x20);

		//get_threads_info();

		Kick();

	}

	return true;
}

//--------------------------------------------------------------------------
void idaapi stopped_at_debug_event(thread_name_vec_t* thr_names, bool dlls_added)
{
}

//--------------------------------------------------------------------------
int idaapi thread_suspend(thid_t tid)
{
	debug_printf("thread_suspend: tid = 0x%X\n", tid);

	SNPS3ThreadStop(TargetID, PS3_UI_CPU, ProcessID, tid);

	get_thread_state(tid);

	return 1;
}

//--------------------------------------------------------------------------
int idaapi thread_continue(thid_t tid)
{
	debug_printf("thread_continue: tid = 0x%X\n", tid);

	SNPS3ThreadContinue(TargetID, PS3_UI_CPU, ProcessID, tid);

	get_thread_state(tid);

	return 1;
}

//-------------------------------------------------------------------------
int do_step(uint32 tid, uint32 dbg_notification)
{
	uint32 ea;
	uint32 instruction;
	uint32 next_addr;
	uint32 resolved_addr;
	uint32 addr;
	uint32 v;
	int state;
	
	ea = read_pc_register(tid);

	SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, ea, 4, (byte *)&instruction);
	if (instruction == *(uint32*)bpt_code)
		instruction = main_bpts_map[ea];

	instruction = bswap32(instruction);
	
	state = get_thread_state(tid);

	if (state == SNPS3_PPU_SLEEP)
	{
		msg("THIS THREAD SLEEPS!\n");
	}

	next_addr = ea + 4;
	resolved_addr = next_addr;
	
	//case 1 - bge, bne, beq, blt...
	if ( instruction >> 26 == 16 )
	{
		addr = instruction & 0xFFFC;
		
		if ( addr & 0x8000 )
			addr = addr | 0xFFFF0000;
		
		if ( !(instruction & 2) )
			addr += ea;
		
		resolved_addr = addr;
		
		if ( instruction & 1 )
		{
			SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, next_addr, 4, (byte *)&instruction);
			if (instruction != *(uint32*)bpt_code)
				main_bpts_map[next_addr] = instruction;

			SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, next_addr);
			step_bpts.push_back(next_addr);

			SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
			if (instruction != *(uint32*)bpt_code)
				main_bpts_map[resolved_addr] = instruction;

			SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
			step_bpts.push_back(resolved_addr);
			
			return 1;
		}

		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, next_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[next_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, next_addr);
		step_bpts.push_back(next_addr);
		
		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[resolved_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
		step_bpts.push_back(resolved_addr);
		
    	return 1;
	}

	//case 2 - bl, b
	if ( instruction >> 26 == 18 )
	{
		addr = instruction & 0x3FFFFFC;
		
		if ( addr & 0x2000000 )
			addr = addr | 0xFC000000;
		
		if ( !(instruction & 2) )
			addr += ea;
		
		resolved_addr = addr;
		
		if ( instruction & 1 )
		{
    		// bl

			SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
			if (instruction != *(uint32*)bpt_code)
				main_bpts_map[resolved_addr] = instruction;

		  	SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
		  	step_bpts.push_back(resolved_addr);

      		return 1;
    	}

		// b

		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[resolved_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
		step_bpts.push_back(resolved_addr);
		
		return 1;
	}

	//case 3 - all
	if ( instruction >> 26 != 19 || instruction & 0xE000 ) 
	{
		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, next_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[next_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, next_addr);
		step_bpts.push_back(next_addr);
	
		return 1;
	}
	
	v = (instruction >> 1) & 0x3FF;
	
	//case 4 - blr, beqlr, blelr...
	if ( v == 16 )
	{		
		resolved_addr = read_lr_register(tid);
		
		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, next_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[next_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, next_addr);
		step_bpts.push_back(next_addr);
		
		SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
		if (instruction != *(uint32*)bpt_code)
			main_bpts_map[resolved_addr] = instruction;

		SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
		step_bpts.push_back(resolved_addr);
		
		return 1;
	}

	//case 5 - bctrl, bctr, bltctr, bgtctrl...
	if ( v != 528 )
		return 1;

	resolved_addr = read_ctr_register(tid);
	
	SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, next_addr, 4, (byte *)&instruction);
	if (instruction != *(uint32*)bpt_code)
		main_bpts_map[next_addr] = instruction;

	SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, next_addr);
	step_bpts.push_back(next_addr);
	
	SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, resolved_addr, 4, (byte *)&instruction);
	if (instruction != *(uint32*)bpt_code)
		main_bpts_map[resolved_addr] = instruction;

	SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, tid, resolved_addr);
	step_bpts.push_back(resolved_addr);

	return 1;
}

//--------------------------------------------------------------------------
// Run one instruction in the thread
int idaapi thread_set_step(thid_t tid)
{
	int dbg_notification;
	int result = 0;

	dbg_notification = get_running_notification();

	if (dbg_notification == STEP_INTO || dbg_notification == STEP_OVER) {
		result = do_step(tid, dbg_notification);
		singlestep = true;
	}

	return result;
}

//-------------------------------------------------------------------------
uint32 read_pc_register(uint32 tid) 
{
	SNRESULT snr = SN_S_OK;
	uint32 reg = SNPS3_pc;
	byte result[SNPS3_REGLEN];

	if (SN_FAILED( snr = SNPS3ThreadGetRegisters(TargetID, PS3_UI_CPU, ProcessID, tid, 1, &reg, result)))
	{
		msg("read_pc_register -> SNPS3ThreadGetRegisters Error: %d\n", snr);
		return BADADDR;
	}

	return bswap32(*(uint32 *)(result + 4));
}

uint32 read_lr_register(uint32 tid) 
{
	SNRESULT snr = SN_S_OK;
	uint32 reg = SNPS3_lr;
	byte result[SNPS3_REGLEN];

	if (SN_FAILED( snr = SNPS3ThreadGetRegisters(TargetID, PS3_UI_CPU, ProcessID, tid, 1, &reg, result)))
	{
		msg("read_lr_register -> SNPS3ThreadGetRegisters Error: %d\n", snr);
		return BADADDR;
	}

	return bswap32(*(uint32 *)(result + 4));
}

uint32 read_ctr_register(uint32 tid) 
{
	SNRESULT snr = SN_S_OK;
	uint32 reg = SNPS3_ctr;
	byte result[SNPS3_REGLEN];

	if (SN_FAILED( snr = SNPS3ThreadGetRegisters(TargetID, PS3_UI_CPU, ProcessID, tid, 1, &reg, result)))
	{
		msg("read_ctr_register -> SNPS3ThreadGetRegisters Error: %d\n", snr);
		return BADADDR;
	}

	return bswap32(*(uint32 *)(result + 4));
}

//--------------------------------------------------------------------------
// Read thread registers
int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
	SNRESULT snr = SN_S_OK;
	regval *RegsBuf;

	if ( values == NULL ) 
	{
		debug_printf("NULL ptr detected !\n");
		return false;
	}

	RegsBuf = (regval *)malloc(qnumber(registers_id) * SNPS3_REGLEN);

	if (SN_FAILED( snr = SNPS3ThreadGetRegisters(TargetID, PS3_UI_CPU, ProcessID, tid, qnumber(registers_id), registers_id, (byte *)RegsBuf)))
	{
		debug_printf("read_registers -> SNPS3ThreadGetRegisters Error: %d\n", snr);
		return 1;

	} else {

		for(int i=0;i<qnumber(registers_id);i++) {

			if (clsmask == RC_GENERAL || clsmask == RC_FLOAT)
			{
				values[i].ival = bswap64(RegsBuf[i].lval);

				if (i == 33) // CR
				{
					values[i].ival = (values[i].ival << 32) | (values[i].ival >> 32);
				}

			} else {
				//for ( int i=R_XMM0; i < R_MXCSR; i++,xptr+=16 )
				//  values[i].set_bytes(xptr, 16);
			}
		}
	}

	return 1;
}

//--------------------------------------------------------------------------
// Write one thread register
int idaapi write_register(thid_t tid, int reg_idx, const regval_t *value)
{
	SNRESULT snr = SN_S_OK;
	uint32 reg;
	uint64 val;

	if ( value == NULL )
	{
		debug_printf("NULL ptr detected !\n");
		return false;
	}

	//Ida Pro 6.1 has sign extension bug: if val is 32 bits, high 32 bits will be 0xFFFFFFFF

	if ( reg_idx > qnumber(registers) )
	{
		debug_printf("wrong reg_idx !\n");
		return false;
	}

	reg = registers_id[reg_idx];

	val = bswap64(value->ival);

	if (SN_FAILED( snr = SNPS3ThreadSetRegisters(TargetID, PS3_UI_CPU, ProcessID, tid, 1, &reg, (byte *)&val)))
	{
		msg("SNPS3ThreadSetRegisters Error: %d\n", snr);
		return false;
	}

	return 1;
}

//--------------------------------------------------------------------------
// Get information on the memory areas
// The debugger module fills 'areas'. The returned vector MUST be sorted.
// Returns:
//   -3: use idb segmentation
//   -2: no changes
//   -1: the process does not exist anymore
//    0: failed
//    1: new memory layout is returned
int idaapi get_memory_info(meminfo_vec_t &areas)
{
	/*SNRESULT snr = SN_S_OK;
	uint32 AreaCount;
	uint32 BufSize;
	SNPS3VirtualMemoryArea* Buf;

	debug_printf("get_memory_info\n");

	SNPS3GetVirtualMemoryInfo(TargetID, ProcessID, true, &AreaCount, &BufSize, NULL);

	debug_printf("BufSize: 0x%X\n", BufSize);

	Buf = (SNPS3VirtualMemoryArea *)malloc(BufSize);

	if (SN_FAILED( snr = SNPS3GetVirtualMemoryInfo(TargetID, ProcessID, true, &AreaCount, &BufSize, (byte *)Buf)))
	{
		msg("SNPS3GetVirtualMemoryInfo Error: %d\n", snr);
		return -3;
	}

	debug_printf("AreaCount: 0x%X\n", AreaCount);

	memory_info_t info;

	for(uint32 i = 0; i < AreaCount; i++) {

		debug_printf("Address: 0x%llX, Size: 0x%llX\n", Buf[i].uAddress, Buf[i].uVSize);

		info.startEA = Buf[i].uAddress;
		info.endEA = Buf[i].uAddress + Buf[i].uVSize;
		info.name = NULL;
		info.sclass = NULL;
		info.sbase = 0;
		info.bitness = 1;
		info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ

		areas.push_back(info);

	}

	free(Buf);*/

	memory_info_t info;

	info.start_ea = 0;
	info.end_ea = 0xFFFF0000;
	info.name = NULL;
	info.sclass = NULL;
	info.sbase = 0;
	info.bitness = 1;
	info.perm = 0; // SEGPERM_EXEC / SEGPERM_WRITE / SEGPERM_READ
	
	areas.push_back(info);

	return 1;
}

//--------------------------------------------------------------------------
// Read process memory
ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
	SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, ea, size, (byte *)buffer);

	for(int i=0;i<size;i+=4) {

		if(*(uint32 *)((char*)buffer+i) == *(uint32 *)bpt_code) 
		{
			*(uint32 *)((char*)buffer+i) = main_bpts_map[ea+i];
		}
	}

	return size;
}

//--------------------------------------------------------------------------
// Write process memory
ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
	SNRESULT snr = SN_S_OK;

	if (SN_FAILED( snr = SNPS3ProcessSetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, ea, size, (byte *)buffer)))
	{
		msg("SNPS3ProcessSetMemory Error: %d\n", snr);
		return -1;
	}

	return size;
}

//--------------------------------------------------------------------------
int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	switch(type)
	{
		case BPT_SOFT:
			{
				debug_printf("Software breakpoint\n");

				return BPT_OK;
			}
			break;

		case BPT_EXEC:
			{
				debug_printf("Execute instruction\n");

				return BPT_BAD_TYPE;
			}
			break;

		case BPT_WRITE:
			{
				debug_printf("Write access\n");

				/*if (len != 8)
				{
					msg("Hardware breakpoints must be 8 bytes long\n");
					return BPT_BAD_LEN;
				}*/
				
				if (ea % 8 != 0)
				{
					msg("Hardware breakpoints must be 8 byte aligned\n");
					return BPT_BAD_ALIGN;
				}
				
				if (dabr_is_set == false)
				{
					//dabr_is_set is not set yet bug
					return BPT_OK;
				
				} else {
				
					msg("It's possible to set a single hardware breakpoint\n");
					return BPT_TOO_MANY;
				}
			}
			break;

			// No read access?

		case BPT_RDWR:
			{
				debug_printf("Read/write access\n");

				/*if (len != 8)
				{
					msg("Hardware breakpoints must be 8 bytes long\n");
					return BPT_BAD_LEN;
				}*/

				if (ea % 8 != 0)
				{
					msg("Hardware breakpoints must be 8 byte aligned\n");
					return BPT_BAD_ALIGN;
				}

				if (dabr_is_set == false)
				{
					//dabr_is_set is not set yet bug
					return BPT_OK;

				} else {

					msg("It's possible to set a single hardware breakpoint\n");
					return BPT_TOO_MANY;
				}
			}
			break;

		default:
			debug_printf("Unsupported BP type !\n");
			return BPT_BAD_TYPE;
	}

}

//--------------------------------------------------------------------------
int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	int i;
	std::vector<uint32>::iterator it;
	uint32 orig_inst = -1;
	uint32 BPCount;
	int cnt = 0;

	//SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, NULL);
	//debug_printf("BreakPoints sum: %d\n", BPCount);

	//bp_list();

	for(i = 0; i < nadd; i++) {

		debug_printf("add_bpt: type: %d, ea: 0x%X, code: %d\n", bpts[i].type, bpts[i].ea, bpts[i].code);

		//BPT_SKIP

		switch(bpts[i].type)
		{
			case BPT_SOFT:
				{
					debug_printf("Software breakpoint\n");

					SNPS3ProcessGetMemory(TargetID, PS3_UI_CPU, ProcessID, -1, bpts[i].ea, 4, (byte *)&orig_inst);

					if (orig_inst != *(uint32*)bpt_code)
						main_bpts_map[bpts[i].ea] = orig_inst;

					//debug_printf("orig_inst = 0x%X\n", bswap32(orig_inst));

					bpts[i].orgbytes.push_back(orig_inst);

					SNPS3SetBreakPoint(TargetID, PS3_UI_CPU, ProcessID, -1, bpts[i].ea);

					bpts[i].code = BPT_OK;

					main_bpts.push_back(bpts[i].ea);

					cnt++;
				}
				break;

			case BPT_EXEC:
				{
					debug_printf("Execute instruction\n");
					//bpts[i].size

					bpts[i].code = BPT_BAD_TYPE;
				}
				break;

			case BPT_WRITE:
				{
					debug_printf("Write access\n");
					//bpts[i].size

					if (dabr_is_set == false)
					{
						SNPS3ProcessStop(TargetID, ProcessID);
					
						SNPS3SetDABR(TargetID, ProcessID, bpts[i].ea | 6);
					
						debug_printf("DABR: 0x%X\n", bpts[i].ea | 6);
					
						SNPS3ProcessContinue(TargetID, ProcessID);
					
						dabr_addr = bpts[i].ea;

						dabr_type = 6;

						dabr_is_set = true;
					
						bpts[i].code = BPT_OK;
					
						cnt++;
					
					} else {
					
						msg("It's possible to set a single hardware breakpoint, DABR 0x%X is not set\n", bpts[i].ea);
						bpts[i].code = BPT_TOO_MANY;
					}
				}
				break;

				// No read access?

			case BPT_RDWR:
				{
					debug_printf("Read/write access\n");
					//bpts[i].size

					if (dabr_is_set == false)
					{
						SNPS3ProcessStop(TargetID, ProcessID);

						SNPS3SetDABR(TargetID, ProcessID, bpts[i].ea | 7);

						debug_printf("DABR: 0x%X\n", bpts[i].ea | 7);

						SNPS3ProcessContinue(TargetID, ProcessID);

						dabr_addr = bpts[i].ea;

						dabr_type = 7;

						dabr_is_set = true;

						bpts[i].code = BPT_OK;

						cnt++;

					} else {

						msg("It's possible to set a single hardware breakpoint, DABR 0x%X is not set\n", bpts[i].ea);
						bpts[i].code = BPT_TOO_MANY;
					}
				}
				break;

			default:
				debug_printf("Unsupported BP type !\n");
		}
	}

	for(i = 0; i < ndel; i++) {

		debug_printf("del_bpt: type: %d, ea: 0x%X, code: %d\n", bpts[nadd + i].type, bpts[nadd + i].ea, bpts[nadd + i].code);

		bpts[nadd + i].code = BPT_OK;
		cnt++;

		switch(bpts[nadd + i].type)
		{
			case BPT_SOFT:
				{
					debug_printf("Software breakpoint\n");

					bpts[nadd + i].orgbytes.pop_back();

					SNPS3ClearBreakPoint(TargetID, PS3_UI_CPU, ProcessID, -1, bpts[nadd + i].ea);
					
					it = std::find(main_bpts.begin(), main_bpts.end(), bpts[nadd + i].ea);

					main_bpts.erase(it);

					main_bpts_map.erase(bpts[nadd + i].ea);
				}
				break;

			case BPT_WRITE:
			case BPT_RDWR:
				{
					if (bpts[nadd + i].type == BPT_RDWR)
					{
						debug_printf("Read/write access\n");

					} else {

						debug_printf("Write access\n");
					}

					dabr_is_set = false;

					dabr_addr = 0;

					SNPS3ProcessStop(TargetID, ProcessID);
					
					SNPS3SetDABR(TargetID, ProcessID, bpts[nadd + i].ea | 4);
					
					debug_printf("DABR: 0x%X\n", bpts[nadd + i].ea | 4);

					SNPS3ProcessContinue(TargetID, ProcessID);
				}
				break;
		}
	}

	//SNPS3GetBreakPoints(TargetID, PS3_UI_CPU, ProcessID, -1, &BPCount, NULL);
	//debug_printf("BreakPoints sum: %d\n", BPCount);

	//bp_list();

	return cnt;
}

//--------------------------------------------------------------------------
// Map process address
ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
	if (regnum == 0)
	{
	}

	if (regs == NULL) // jump prediction
	{
		return BADADDR;
	}

	if (regs[regnum].ival < 0x100000000 && regs[regnum].ival > 0x10200)
	{
		return regs[regnum].ival;
	}

	return BADADDR;
}

//-------------------------------------------------------------------------
int idaapi send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
	return 0;
}

static ssize_t idaapi idd_notify(void* user_data, int msgid, va_list va)
{
	int retcode = DRC_NONE;
	qstring* errbuf;

	switch (msgid)
	{
		case debugger_t::ev_init_debugger:
		{
			const char* hostname = va_arg(va, const char*);
			int portnum = va_arg(va, int);
			const char* password = va_arg(va, const char*);
			errbuf = va_arg(va, qstring*);
			QASSERT(1522, errbuf != NULL);
			retcode = init_debugger(hostname, portnum, password, errbuf);
			break;
		}
		case debugger_t::ev_term_debugger:
			retcode = term_debugger();
			break;
		case debugger_t::ev_get_processes:
		{
			procinfo_vec_t* procs = va_arg(va, procinfo_vec_t*);
			errbuf = va_arg(va, qstring*);
			retcode = process_get_info(procs, errbuf);
			break;
		}
		case debugger_t::ev_start_process:
		{
			const char* path = va_arg(va, const char*);
			const char* args = va_arg(va, const char*);
			const char* startdir = va_arg(va, const char*);
			uint32 dbg_proc_flags = va_arg(va, uint32);
			const char* input_path = va_arg(va, const char*);
			uint32 input_file_crc32 = va_arg(va, uint32);
			errbuf = va_arg(va, qstring*);
			retcode = deci3_start_process(path, args, startdir, dbg_proc_flags, input_path, input_file_crc32);
			break;
		}
		case debugger_t::ev_attach_process: {
			pid_t pid = va_argi(va, pid_t);
			int event_id = va_arg(va, int);
			uint32 dbg_proc_flags = va_arg(va, uint32);
			errbuf = va_arg(va, qstring*);
			retcode = deci3_attach_process(pid, event_id, dbg_proc_flags, errbuf);
			break;
		}
		case debugger_t::ev_get_debug_event: {
			gdecode_t* code = va_arg(va, gdecode_t*);
			debug_event_t* event = va_arg(va, debug_event_t*);
			int timeout_ms = va_arg(va, int);
			*code = get_debug_event(event, timeout_ms);
			retcode = DRC_OK;
			break;
		}
		case debugger_t::ev_get_debapp_attrs: {
			debapp_attrs_t* out_pattrs = va_arg(va, debapp_attrs_t*);
			out_pattrs->platform = "linux";
			out_pattrs->addrsize = 8;
			out_pattrs->is_be = true;
			out_pattrs->cbsize = 0;
			retcode = DRC_OK;

			break;
		}
		case debugger_t::ev_rebase_if_required_to: {
			ea_t new_base = va_arg(va, ea_t);
			rebase_if_required_to(new_base);
			retcode = DRC_OK;
			break;
		}
		case debugger_t::ev_request_pause: {
			retcode = prepare_to_pause_process();
			break;
												 }
		case debugger_t::ev_resume: {
			debug_event_t* event = va_arg(va, debug_event_t*);
			retcode = continue_after_event(event);
			break;
		}
		case debugger_t::ev_suspended: {
			bool dlls_added = va_argi(va, bool);
			thread_name_vec_t* thr_names = va_arg(va, thread_name_vec_t*);
			stopped_at_debug_event(thr_names, dlls_added);
			retcode = DRC_OK;
			break;
		}
		case debugger_t::ev_exit_process: {
			retcode = deci3_exit_process();
			break;
		}
		case debugger_t::ev_get_memory_info: {
			meminfo_vec_t* ranges = va_arg(va, meminfo_vec_t*);
			retcode = get_memory_info(*ranges);
			break;
		}
		case debugger_t::ev_read_registers: {
			thid_t tid = va_argi(va, thid_t);
			int clsmask = va_arg(va, int);
			regval_t* values = va_arg(va, regval_t*);
			errbuf = va_arg(va, qstring*);
			retcode = read_registers(tid, clsmask, values);
			break;
		}
		case debugger_t::ev_write_register: {
			thid_t tid = va_argi(va, thid_t);
			int regidx = va_arg(va, int);
			const regval_t* value = va_arg(va, const regval_t*);
			errbuf = va_arg(va, qstring*);
			retcode = write_register(tid, regidx, value);
			break;
		}
		case debugger_t::ev_read_memory: {
			size_t* nbytes = va_arg(va, size_t*);
			ea_t ea = va_arg(va, ea_t);
			void* buffer = va_arg(va, void*);
			size_t size = va_arg(va, size_t);
			errbuf = va_arg(va, qstring*);
			ssize_t code = read_memory(ea, buffer, size);
			*nbytes = code >= 0 ? code : 0;
			retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
			break;
		}
		case debugger_t::ev_write_memory: {
			size_t* nbytes = va_arg(va, size_t*);
			ea_t ea = va_arg(va, ea_t);
			const void* buffer = va_arg(va, void*);
			size_t size = va_arg(va, size_t);
			errbuf = va_arg(va, qstring*);
			ssize_t code = write_memory(ea, buffer, size);
			*nbytes = code >= 0 ? code : 0;
			retcode = code >= 0 ? DRC_OK : DRC_NOPROC;
			break;
		}
		case debugger_t::ev_check_bpt: {
			int* bptvc = va_arg(va, int*);
			bpttype_t type = va_argi(va, bpttype_t);
			ea_t ea = va_arg(va, ea_t);
			int len = va_arg(va, int);
			*bptvc = is_ok_bpt(type, ea, len);
			retcode = DRC_OK;
			break;
		}
		case debugger_t::ev_update_bpts: {
			int* nbpts = va_arg(va, int*);
			update_bpt_info_t* bpts = va_arg(va, update_bpt_info_t*);
			int nadd = va_arg(va, int);
			int ndel = va_arg(va, int);
			retcode = update_bpts(bpts, nadd, ndel);
			break;
		}
		default: {
			debug_printf("Unhandled event %d\n", msgid);
			break;
		}
	}
	return retcode;
}

//--------------------------------------------------------------------------
//
//      DEBUGGER DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
debugger_t debugger =
{
  IDD_INTERFACE_VERSION,
  DEBUGGER_NAME,				// Short debugger name
  DEBUGGER_ID_PLAYSTATION_3,	// Debugger API module id
  PROCESSOR_NAME,				// Required processor name
  DBG_FLAG_REMOTE | DBG_FLAG_NOHOST | DBG_FLAG_CAN_CONT_BPT,
  DBG_HAS_GET_PROCESSES | DBG_HAS_ATTACH_PROCESS
| DBG_HAS_REQUEST_PAUSE
| DBG_HAS_SET_EXCEPTION_INFO
| DBG_HAS_THREAD_SUSPEND
| DBG_HAS_THREAD_CONTINUE,
  register_classes,				// Array of register class names
  RC_GENERAL,					// Mask of default printed register classes
  registers,					// Array of registers
  qnumber(registers),			// Number of registers

  0x1000,						// Size of a memory page

  bpt_code,						// Array of bytes for a breakpoint instruction
  qnumber(bpt_code),			// Size of this array
  0,							// for miniidbs: use this value for the file type after attaching
  0,							// resume mode
  NULL, //dbg options
  idd_notify, //notify callback
  
  /*init_debugger,
  term_debugger,
  
  process_get_info,
  deci3_start_process,
  deci3_attach_process,
  deci3_detach_process,
  rebase_if_required_to,
  prepare_to_pause_process,
  deci3_exit_process,

  get_debug_event,
  continue_after_event,
  NULL, //set_exception_info,
  stopped_at_debug_event,

  thread_suspend,
  thread_continue,
  thread_set_step,
  read_registers,
  write_register,
  NULL, //thread_get_sreg_base

  get_memory_info,
  read_memory,
  write_memory,

  is_ok_bpt,
  update_bpts,
  NULL, //update_lowcnds
  NULL, //open_file
  NULL, //close_file
  NULL, //read_file
  map_address,
  NULL, //set_dbg_options
  NULL, //get_debmod_extensions
  NULL, //update_call_stack
  NULL, //appcall
  NULL, //cleanup_appcall
  NULL, //eval_lowcnd
  NULL, //write_file
  send_ioctl,*/
};
