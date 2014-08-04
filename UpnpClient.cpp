// UpnpClient.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "UpnpClient.h"
#include "sha1.h"
#include "Base64.h"
#include <fstream>

//#include <stdlib.h>
//#include <windows.h>

#include <string>
using namespace std;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define PRINT_DEBUG	1

PDEVICE_LIST		g_pDeviceList = NULL; 

//
//TODO: If this DLL is dynamically linked against the MFC DLLs,
//		any functions exported from this DLL which call into
//		MFC must have the AFX_MANAGE_STATE macro added at the
//		very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

// CUpnpClientApp

BEGIN_MESSAGE_MAP(CUpnpClientApp, CWinApp)
END_MESSAGE_MAP()

PDEVICE_LIST Discovery(void);
BOOL Get_Device_Service(CString url, CString csUser, CString csPWD, char * szONVIF_URL);
BOOL Get_RTSP_URI(CString url, CString csUser, CString csPWD, CString *pcsURL);
BOOL Get_PTZ_Capability(CString url, CString csUser, CString csPWD, CString *pcsURL);
void Set_PTZ(CString url, CString csUser, CString csPWD, PTZ_MOVE enumMove);

static BOOL Initialize(void)
{
	//zack err code 10093
	{
		WORD		wVersionRequested = MAKEWORD(2, 2); 
		WSADATA		wsaData; 
		
		if(WSAStartup(wVersionRequested, &wsaData) != 0)  
		    return FALSE; 
	}

	g_saAdvertisement.sin_family = AF_INET;
	g_saAdvertisement.sin_port = htons(UPNP_PORT);
	g_saAdvertisement.sin_addr.s_addr = inet_addr(UPNP_MULTICAST_IP);

	g_iLenResponseHeader = strlen(UPNP_RESPONSE_HEADER);

	g_iLenKEY_MAC = strlen(DISCOVERY_KEY_MAC);
	g_iLenKEY_Function = strlen(DISCOVERY_KEY_FUNCTION);
	g_iLenKEY_Model = strlen(DISCOVERY_KEY_MODEL);
	g_iLenKEY_Service = strlen(DISCOVERY_KEY_SERVICE);

	return TRUE;
}

// CUpnpClientApp construction

CUpnpClientApp::CUpnpClientApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
	Initialize();
}


// The one and only CUpnpClientApp object

CUpnpClientApp theApp;


// CUpnpClientApp initialization

BOOL CUpnpClientApp::InitInstance()
{
	CWinApp::InitInstance();
	return TRUE;
}


//extern "C" __declspec(dllexport) int ONVIF_Discovery(int i)
extern "C" __declspec(dllexport) PDEVICE_LIST ONVIF_Discovery(int i)
{
	CString		csUser, csPass, csCgiUrl;

	//TRACE(L"DLL Enter ONVIF_Discovery\n");
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
	//AfxMessageBox(L"ONVIF_Discovery", 0, 0);

	g_pDeviceList = Discovery();

	if(g_pDeviceList->dwFound)
	{
		//http://10.1.21.127/onvif/device_service
		//csCgiUrl.Format(_T("http://10.1.21.127/onvif/device_service"));
		//csUser.Format(_T("admin"));
		//csPass.Format(_T("admin"));
		//Get_RTSP_URI(csCgiUrl, csUser, csPass);

		//http://10.1.21.92/onvif/device_service
		//csCgiUrl.Format(_T("http://10.1.21.92/onvif/device_service"));
		//csUser.Format(_T("root"));
		//csPass.Format(_T("pass"));
		//Get_RTSP_URI(csCgiUrl, csUser, csPass);
	}

	if(g_pDeviceList) 
		return g_pDeviceList;
	else
		return NULL;
	//return 100;
}

extern "C" __declspec(dllexport) CString ONVIF_GET_RTSP(CString url, CString csUser, CString csPWD)
{
	CString	CsRTSP_URL;
	BOOL	fGet;
	
	//TRACE(L"DLL Enter ONVIF_GET_RTSP\n");
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	fGet = Get_RTSP_URI(url, csUser, csPWD, &CsRTSP_URL);
	//AfxMessageBox(L"ONVIF_GET_RTSP", 0, 0);
	if(fGet)
		return CsRTSP_URL;
	else
		return NULL;
		
}

extern "C" __declspec(dllexport) CString ONVIF_GET_PTZ_Capability(CString url, CString csUser, CString csPWD)
{
	CString	CsPTZ_URL;
	BOOL	fPTZ = FALSE;
	
	//TRACE(L"\nDLL Enter ONVIF_GET_PTZ_Capability\n");
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	fPTZ = Get_PTZ_Capability(url, csUser, csPWD, &CsPTZ_URL);
	//AfxMessageBox(L"ONVIF_GET_RTSP", 0, 0);
	if(fPTZ)
		return CsPTZ_URL;
	else
		return NULL;
}

extern "C" __declspec(dllexport) void ONVIF_SET_PTZ(CString url, CString csUser, CString csPWD, PTZ_MOVE enumMove)
{
	CString	CsPTZ_URL;
	BOOL	fPTZ = FALSE;
	
//	TRACE(L"\nDLL Enter ONVIF_SET_PTZ\n");
	AFX_MANAGE_STATE(AfxGetStaticModuleState());

	Set_PTZ(url, csUser, csPWD, enumMove);
}

extern "C" __declspec(dllexport) void ONVIF_FreeListBuffer(void)
{
	//TRACE(L"DLL Enter ONVIF_FreeListBuffer\n");
	if(g_pDeviceList)
		free(g_pDeviceList);
	g_pDeviceList = NULL;
	AFX_MANAGE_STATE(AfxGetStaticModuleState());
}

PDEVICE_LIST Discovery(void)
{
	char			szTemp[UPNP_UDP_PACKET_SIZE];
	DWORD			dwDeviceList;
	SOCKET			so;
	SOCKADDR_IN		sa, sa_from;
	int				iTtl = 1;
	int				iLoop = 0;
	fd_set 			in_fds;
	struct timeval	tv;
	int				iNum;
	int				iSizeSoFrom;
	char			szContent[UPNP_UDP_PACKET_SIZE];
	int				iContent;
	int				bcast = 1;
	//LPSTR			pszIP, pszLocation, pszModel, pszMac;
	LPSTR			pszLocation, pszModel, pszMac;
	DEV_CAMERA		DevCamera;
	//unsigned		a_uiIP[4];
	DWORD			dw, dwTime;
	CString 		err;

	#if	PRINT_DEBUG
		TRACE(L"WS-Discovery:  <<< \n\n");
	#endif

	sa.sin_family = AF_INET;
	sa.sin_port = htons(UPNP_CAM_PORT);
	//sa.sin_addr.s_addr = inet_addr("10.1.21.4");
	//sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_addr.s_addr = htonl(INADDR_ANY); 
	
	so = socket(AF_INET,SOCK_DGRAM, 0);
	if(so == INVALID_SOCKET)
	{
		//err.Format(_T("socket() error  WSAGetLastError=%d,GetLastError=%d"), WSAGetLastError(), ::GetLastError());
		err.Format(_T("socket( ) error  WSAGetLastError=%d\n"), WSAGetLastError());
		AfxMessageBox(err);
		#if	PRINT_DEBUG
			TRACE(L"ONVIF: Failed to create socket !\n");
		#endif
		return NULL;
	}

	if(SOCKET_ERROR == bind(so, (struct sockaddr *)&sa, sizeof(sa)))
	{
		#if	PRINT_DEBUG
			TRACE(L"ONVIF: Failed to bind !\n");
		#endif

		int  iPort = UPNP_CAM_PORT, iErrorNum;

		iErrorNum = WSAGetLastError();
		if(iErrorNum == 10048)
		{
			//err bind
			while((iErrorNum = WSAGetLastError()) == 10048)
			 {
				iPort++;
				sa.sin_port = htons(iPort);
				bind(so, (SOCKADDR*)&sa, sizeof(sa));
				TRACE(L"ONVIF: Re Bind iErrorNum >>> %d\n", iErrorNum);
			 }
		}
		else
		{
			closesocket(so);
			return NULL;
		}
	}

	setsockopt(so, IPPROTO_IP,IP_MULTICAST_TTL, (char*)&iTtl, sizeof(iTtl));
	setsockopt(so, IPPROTO_IP,IP_MULTICAST_LOOP,(char*) &iLoop, sizeof(iLoop));
	dwTime = GetCurrentTime();
	sprintf(szTemp, "%s%012d%s", szDiscovery_1, dwTime, szDiscovery_2);
	if(SOCKET_ERROR == sendto(so, szTemp,  strlen(szTemp), 0, (struct sockaddr *)&g_saAdvertisement, sizeof(g_saAdvertisement)))
	//if(SOCKET_ERROR == sendto(so, SEARCH_REQUEST1,  (sizeof(SEARCH_REQUEST1) - 1), 0, (struct sockaddr *)&g_saAdvertisement, sizeof(g_saAdvertisement)))
	{
		#if	PRINT_DEBUG
			TRACE(L"ONVIF: Failed on sendto!\n");
		#endif
		closesocket(so);
		return NULL;
	}
	else
	{
		closesocket(so);
		
		so = socket(AF_INET,SOCK_DGRAM, 0);
		if(so == INVALID_SOCKET)
		{
			err.Format(_T("1 socket( ) error  WSAGetLastError=%d\n"), WSAGetLastError());
			AfxMessageBox(err);
			#if	PRINT_DEBUG
				TRACE(L"1 ONVIF: Failed to establish !\n");
			#endif
			return NULL;
		}
		if(SOCKET_ERROR == bind(so, (struct sockaddr *)&sa, sizeof(sa)))
		{
			#if	PRINT_DEBUG
				TRACE(L"1 ONVIF:  Failed to bind !\n");
			#endif
			
			int  iPort = UPNP_CAM_PORT, iErrorNum;

			iErrorNum = WSAGetLastError();
			if(iErrorNum == 10048)
			{
				//err bind
				while((iErrorNum = WSAGetLastError()) == 10048)
				 {
					iPort++;
					sa.sin_port = htons(iPort);
					bind(so, (SOCKADDR*)&sa, sizeof(sa));
					TRACE(L"ONVIF: Re Bind iErrorNum >>> %d\n", iErrorNum);
				 }
			}
			else
			{
				closesocket(so);
				return NULL;
			}
		}

		setsockopt(so, IPPROTO_IP,IP_MULTICAST_TTL, (char*)&iTtl, sizeof(iTtl));
		setsockopt(so, IPPROTO_IP,IP_MULTICAST_LOOP,(char*) &iLoop, sizeof(iLoop));
		dwTime = GetCurrentTime();
		sprintf(szTemp, "%s%012d%s", szDiscovery_3, dwTime, szDiscovery_4);
		if(SOCKET_ERROR == sendto(so, szTemp, strlen(szTemp), 0, (struct sockaddr *)&g_saAdvertisement, sizeof(g_saAdvertisement)))
		//if(SOCKET_ERROR == sendto(so, SEARCH_REQUEST2,  (sizeof(SEARCH_REQUEST2) - 1), 0, (struct sockaddr *)&g_saAdvertisement, sizeof(g_saAdvertisement)))
		{
			#if	PRINT_DEBUG
				TRACE(L"1 ONVIF: Failed on sendto!\n");
			#endif
			closesocket(so);
			return NULL;
		}
	}
	
	dwDeviceList = 10;
	g_pDeviceList = (PDEVICE_LIST) malloc(sizeof(DEVICE_LIST) + sizeof(DEV_CAMERA) * (dwDeviceList - 1));
	if(g_pDeviceList != NULL)
	{
		g_pDeviceList->dwFound = 0;
		while(g_pDeviceList != NULL) 
		{
			FD_ZERO(&in_fds);
			FD_SET(so,&in_fds);
			bzero(&tv,sizeof(tv));
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			iNum = select(so + 1,&in_fds,(fd_set *)NULL,(fd_set *)NULL,&tv);
			if(iNum <= 0)
				break;
			iSizeSoFrom = sizeof(sa_from);
			iContent = recvfrom(so, szContent, UPNP_UDP_PACKET_SIZE, 0, (struct sockaddr *) &sa_from, (socklen_t *)&iSizeSoFrom);
			TRACE(L"UPnP.iContent >>> %d\n", iContent);
			

			/*
			if(iContent)
			{
				memset(szTemp, 0, sizeof(szTemp));
				strcpy(szTemp, inet_ntoa(sa_from.sin_addr));
				OutputDebugStringA(szTemp);
				//TRACE(L"\tUPnP.iContent >>> %d\n", iContent);
				TRACE(L"\n");
			}
			*/
			
			if(//zack 2014 0418 ((pszModel = strstr(szContent, DISCOVERY_KEY_MODEL)) != NULL) && 
				((pszMac = strstr(szContent, DISCOVERY_KEY_MAC)) != NULL) &&
				((pszLocation = strstr(szContent, DISCOVERY_KEY_SERVICE)) != NULL))
			{
				//zack 2014 04 18 (+)
				BOOL	fModelName = TRUE;
				//zack 2014 04 18 (-)
				
				szContent[iContent] = 0;
				
				//zack 2014 04 18 (+)
				if((pszModel = strstr(szContent, DISCOVERY_KEY_MODEL)) == NULL)
					fModelName = FALSE;
				if(fModelName)
				//zack 2014 04 18 (-)
					pszModel += g_iLenKEY_Model;
				pszMac += (g_iLenKEY_MAC + 24);
				pszLocation += g_iLenKEY_Service ;
				//pszIP += 2;
				
				//if(4 == sscanf(pszIP,"%u.%u.%u.%u", &a_uiIP[0], &a_uiIP[1], &a_uiIP[2], &a_uiIP[3]))
				//{
					for(dw = 0; dw < g_pDeviceList->dwFound; dw++)
						if (g_pDeviceList->Camera[dw].ip.in.s_addr == sa_from.sin_addr.s_addr)
							break;
					if(dw >= g_pDeviceList->dwFound)
					{		
						//http://10.1.21.126/onvif/device_service
						if(1 == sscanf(pszLocation,"%s/device_service", &DevCamera.Xml))
						{
							LPSTR pszDevice_service;
							
							pszDevice_service =  strstr(pszLocation, "/device_service");
							if(pszDevice_service)
							{
								pszDevice_service += 15;
								DevCamera.Xml[pszDevice_service - pszLocation] = 0;
								//strcpy(szTemp, DevCamera.Xml);
								//OutputDebugStringA(szTemp);
							}
							//TRACE(L"\n");
						}
						
						//Model
						
						//zack 2014 04 18 (+)
						if(fModelName)
						//zack 2014 04 18 (-)
						{
							LPSTR pszModelEnd;
							
							pszModelEnd =  strstr(pszModel, "<");
							if(pszModelEnd)
							{
								//zack 2014 04 18 (+)
								int	iCheck = pszModelEnd - pszModel;

								if(iCheck > 32)
								{
									//for sony
									LPSTR pszEnd = strstr(pszModel, " ");

									if(pszEnd)
										iCheck = pszEnd - pszModel;
									else
										iCheck = 32;
								}
								
								strncpy(DevCamera.Name, pszModel, iCheck);
								DevCamera.Name[iCheck] = 0;
								//zack 2014 04 18 (-)
								
								//strcpy(szTemp, DevCamera.Name);
								//OutputDebugStringA(szTemp);
							}
							else
							{
								strcpy(DevCamera.Name, "ONVIF");
							}
							//TRACE(L"\t");
						}
						//zack 2014 04 18 (+)
						else
							strcpy(DevCamera.Name, "ONVIF");
						//zack 2014 04 18 (-)

						//MAC
						{
							//strncpy(DevCamera.MAC, pszMac, 12);
							//DevCamera.MAC[12] = 0;
							sscanf(pszMac,"%02x%02x%02x%02x%02x%02x</"
								, &DevCamera.MAC[0], &DevCamera.MAC[1], &DevCamera.MAC[2]
								, &DevCamera.MAC[3], &DevCamera.MAC[4], &DevCamera.MAC[5]);
							//DevCamera.MAC[iMac] = atoi(pszMac);
							
						}
						DevCamera.uuid[0] = 0;
						DevCamera.wPort = 80;
						//strcpy(szTemp, DevCamera.MAC);
						//OutputDebugStringA(szTemp);
						//TRACE(L"\n");
						
						DevCamera.ip.in = sa_from.sin_addr;
							
						if(g_pDeviceList->dwFound == dwDeviceList)
						{
							PDEVICE_LIST	pDeviceListNew;

							dwDeviceList += 10;
							pDeviceListNew = (PDEVICE_LIST) realloc(g_pDeviceList,sizeof(*g_pDeviceList) + sizeof(g_pDeviceList->Camera[0]) * (dwDeviceList - 1));
							if(pDeviceListNew != NULL)
								g_pDeviceList = pDeviceListNew;
							else
							{
								#if	PRINT_DEBUG
									TRACE(L"WS-Discovery:  Failed to realloc g_pDeviceList!\n");
								#endif
								free(g_pDeviceList);
								g_pDeviceList = NULL;
							}
						}
						
						if(g_pDeviceList)
						{
							g_pDeviceList->Camera[g_pDeviceList->dwFound++] = DevCamera;
						}
					}
				//}
			}
		}
	}

	closesocket(so);
	
	#if	PRINT_DEBUG
		TRACE(L"WS-Discovery:  >>> %u\n", (unsigned int) g_pDeviceList->dwFound);
	#endif
	
	#if	PRINT_DEBUG
		for(dw = 0; dw < g_pDeviceList->dwFound; dw++)
		{
			memset(szTemp, 0, sizeof(szTemp));
			sprintf(szTemp, "\t[%2u]: %s:%u\tLocation = %s\tMac=%02x-%02x-%02x-%02x-%02x-%02x\n"
					, (unsigned int)dw, inet_ntoa(g_pDeviceList->Camera[dw].ip.in)
					, g_pDeviceList->Camera[dw].wPort
					, g_pDeviceList->Camera[dw].Xml
					, g_pDeviceList->Camera[dw].MAC[0], g_pDeviceList->Camera[dw].MAC[1], g_pDeviceList->Camera[dw].MAC[2]
					, g_pDeviceList->Camera[dw].MAC[3], g_pDeviceList->Camera[dw].MAC[4], g_pDeviceList->Camera[dw].MAC[5]);
			OutputDebugStringA(szTemp);
		}

	#endif
	
	TRACE(L"\n");
	
	return g_pDeviceList;
}

#if 1

// Digest = B64ENCODE( SHA1( B64DECODE( Nonce ) + Date + Password ) )

char			g_szUserName[64] = {0};
char			g_szPassword[64] = {0};
//char			g_szPassword[] = "123456";
char			g_szNonceBase64BinaryString[] = "emFjaGVyeXRlc3Q=";
char			g_szTimeString[] = "2010-09-16T07:50:45Z";
char			g_szDigest[128] = {0};

#define			SOAP_SMD_SHA1_SIZE			20

BOOL			g_fDigest = false;

#if 0
Nonce 		LKqI6G/AikKcQrN0zqZflg==
Date 		2010-09-16T07:50:45Z
Password	userpassword	
Digest		tuOSpG1F1IXsozq4HFNeeGeFLEI=
#endif

void GetDigest(char* Noncestr, char* ddatestr, char* Passwordstr) 
{ 
	//Digest = B64ENCODE( SHA1( B64DECODE( Nonce ) + Date + Password ) ) 
	
	////////////////////////////////////////////////////////////////////////// 
	//B64DECODE( Nonce ) 
	UCHAR decode[256]; 
	int len, i;
	
	//bc_base64_decode((UCHAR*)Noncestr, strlen(Noncestr), decode, 255, &len);
	len = strlen(Noncestr);
	memcpy(decode,Noncestr, len); 

	
	//B64DECODE( Nonce ) + Date + Password 
	UCHAR alladd[256]; 
	
	memcpy(alladd,decode, len); 
	memcpy(alladd + len, ddatestr, strlen(ddatestr));
	memcpy(alladd + len + strlen(ddatestr), Passwordstr, strlen(Passwordstr)); 
	int alllen = len+strlen(ddatestr)+strlen(Passwordstr);
	
	//SHA1( B64DECODE( Nonce ) + Date + Password ) 
	
	UCHAR shacode[256];

	//sha1(alladd,alllen,shacode, 500, &len);
	//unsigned char*	tempOut = new unsigned char[256];
	unsigned char*	tempOut = shacode;
	{
		sha1_ctx		m_sha1;
		CString			tempHash;
		int				j;
		
		sha1_begin(&m_sha1);
		j = alllen;
		sha1_hash(&alladd[0], j, &m_sha1);
		sha1_end(tempOut, &m_sha1);

		for(i = 0 ; i < SOAP_SMD_SHA1_SIZE ; i++)
		{
			char tmp[3];
			_itoa(tempOut[i], tmp, 16);
			if (strlen(tmp) == 1)
			{
				tmp[1] = tmp[0];
				tmp[0] = '0';
				tmp[2] = '\0';
			}
			tempHash += tmp;	
		}
	}

	//B64ENCODE bc_base64_encode(shacode, len,Digest,Digestbuflen, Digestlen);
	{
		char	szTemp[32] = {0};

		USES_CONVERSION;

		memcpy(szTemp,shacode, SOAP_SMD_SHA1_SIZE); 
		
		STRING		inCode;
		STRING_OUT	poutCode(inCode);

		Base64::Encode((unsigned char *)&szTemp[0], SOAP_SMD_SHA1_SIZE, poutCode);
		strcpy (g_szDigest, W2A(poutCode.c_str()));
	}
}


void WS_Digest(CString csUser, CString csPWD)
{
	USES_CONVERSION;
	char			szNonceString[128] = {0};
	sha1_ctx		m_sha1;
	int 			i;
	STRING			inCode;

	strcpy(g_szUserName, W2A(csUser));
	strcpy(g_szPassword, W2A(csPWD));

	
	inCode = A2W(g_szNonceBase64BinaryString);
	i = strlen((char *)g_szNonceBase64BinaryString);
	Base64::Decode(inCode, i, (BYTE_DATA_OUT)&szNonceString);

	GetDigest(szNonceString, g_szTimeString, g_szPassword);	
}

/*
void TESTBase64()
{
	USES_CONVERSION;
	char			szNonceString[128] = {0};
	//unsigned char	szPassWord[128] = "admin";
	//unsigned char	szPassWord[128] = "userpassword";
    unsigned char	obuf[20];
	sha1_ctx		m_sha1;
	unsigned char*	tempOut = new unsigned char[256];
	CString			tempHash;
	int 	i;
	
	//STRING		inCode1(L"YWJjZGVmZ2hpamtsbW5vcHFyc3R1cnd2YWZh");
	STRING		inCode1;
	//STRING		inCode;
	//STRING_OUT	poutCode(inCode);
	//poutCode = outCode;

	//i = strlen((char *)szPassWord);

	//Base64::Encode(&szPassWord[0], i, poutCode);

	inCode1 = A2W(g_szNonceBase64BinaryString);
	i = strlen((char *)g_szNonceBase64BinaryString);

	Base64::Decode(inCode1, i, (BYTE_DATA_OUT)&szNonceString);


	UCHAR Digest[500];
	int len;
	
	GetDigest(szNonceString, g_szTimeString, password, Digest, 500, &len);	
}
void TEST()
{
	unsigned char	szTemp[128] = {0};
	//unsigned char	szPassWord[128] = "admin";
	unsigned char	szPassWord[128] = "userpassword";
    unsigned char	obuf[20];
	sha1_ctx		m_sha1;
	unsigned char*	tempOut = new unsigned char[256];
	CString			tempHash;
	//CString		str(_T("Hello"));

	int 	i;

	//sha1(szTemp, (unsigned char)password, strlen(password));


	// Check what operation we're doing
	sha1_begin(&m_sha1);
	//sha1_hash(reinterpret_cast<unsigned char *>(str.GetBuffer(str.GetLength())), str.GetLength(), &m_sha1);
	i = strlen((char *)szPassWord);
	sha1_hash(&szPassWord[0], i, &m_sha1);
	sha1_end(tempOut, &m_sha1);

	for(int i = 0 ; i < SOAP_SMD_SHA1_SIZE ; i++)
	{
		char tmp[3];
		_itoa(tempOut[i], tmp, 16);
		if (strlen(tmp) == 1)
		{
			tmp[1] = tmp[0];
			tmp[0] = '0';
			tmp[2] = '\0';
		}
		tempHash += tmp;	
	}
	delete[] tempOut;
}
*/

#endif



BOOL Get_Device_Service(CString url, CString csUser, CString csPWD, char * szONVIF_URL)
{
	Curlplus	myCurl;
	CString		m_csCGIStatus;
	CString		m_csContent;
	BOOL		fGet = FALSE;

	//WS_Digest(csUser, csPWD);

	m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities></s:Body></s:Envelope>"));
	
	m_csCGIStatus = myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
	if(m_csCGIStatus)
	{
		LPSTR	pszMedia;
		char*	szMedia;
		char	szFind[128] = {0};

		szMedia = new char[m_csCGIStatus.GetLength() + 1];

		USES_CONVERSION;
		strcpy(szMedia, W2A(m_csCGIStatus));
		 
		pszMedia = strstr(szMedia, "<tt:Media><tt:XAddr>");
		if(pszMedia)
		{
			LPSTR	pszEnd;
			//<tt:XAddr>http://10.1.21.92/onvif/device_service</tt:XAddr>
			pszMedia += 20;				//<tt:Media><tt:XAddr>
			pszEnd = strstr(pszMedia, "</tt:XAddr>");
			if (pszEnd)
			{
				strncpy(szFind, pszMedia, pszEnd - pszMedia);
				szFind[pszEnd - pszMedia] = 0;
				strcpy(szONVIF_URL, szFind);
				OutputDebugStringA(szONVIF_URL);
				TRACE(L"\n");
				fGet = TRUE;
			}
		}
		delete [] szMedia;
	}

	return fGet;
}

BOOL Get_VideoProfileName(CString url, CString csUser, CString csPWD, char * szGetProfileName)
{
	Curlplus	myCurl;
	CString		m_csCGIStatus;
	CString		m_csContent;
	BOOL		fGet = FALSE;
	 
	USES_CONVERSION;
	//m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><soap:Body><trt:GetProfiles /></soap:Body></soap:Envelope>"));
	m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\r\n  <soap:Body>\r\n    <trt:GetProfiles />\r\n  </soap:Body></soap:Envelope>"));
	//m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\r\n <s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>admin</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">edyqSKTmyz6UYK+0Wy9UcBkJrFw=</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">9b4jl7CIYEW80bCjQR98xOgBAAAAAA==</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2014-06-27T05:33:49.684Z</Created></UsernameToken></Security></s:Header> <soap:Body>\r\n    <trt:GetProfiles />\r\n  </soap:Body></soap:Envelope>"));
	//m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\r\n <s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>%s</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created></UsernameToken></Security></s:Header> <soap:Body>\r\n    <trt:GetProfiles />\r\n  </soap:Body></soap:Envelope>")
					//, A2W(g_szUserName), A2W(g_szDigest), A2W(g_szNonceBase64BinaryString), A2W(g_szTimeString) );
																																																																				//<GetProfile></GetProfile>
	m_csCGIStatus = myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
	if(m_csCGIStatus)
	{
		LPSTR	pszMedia;
		char*	szMedia;
		//char	szFind[128] = {0};

		int 	iLens = m_csCGIStatus.GetLength() + 1;
		
		szMedia = new char[iLens];

		USES_CONVERSION;
		strcpy(szMedia, W2A(m_csCGIStatus));

		for(int i = 0; i < iLens; i++)
		{
			if(szMedia[i] == '"') 
				szMedia[i] = 0x20;
		}
		 
		pszMedia = strstr(szMedia, "<trt:Profiles ");
		if(pszMedia)
		{
			LPSTR	pszEnd;
			//<trt:Profiles fixed="true" token="protoken_ch01">
			//<trt:Profiles token="Profile1" fixed="false">
			pszMedia += 14;				//<tt:Media><tt:XAddr>
			pszEnd = strstr(pszMedia, "token= ");
			if(pszEnd)
			{
				LPSTR	pszEnd1;
				pszEnd += 7;

				pszEnd1 = strstr(pszEnd, " ");
				if(pszEnd1)
				{
					strncpy(szGetProfileName, pszEnd, pszEnd1 - pszEnd);
					//szGetProfileName[pszEnd1 - pszEnd] = 0;
					OutputDebugStringA(szGetProfileName);
					TRACE(L"\n");
					fGet = TRUE;
				}				
			}
		}
		delete [] szMedia;
	}
	
	if(!fGet)
	{
		//Try Digest
		WS_Digest(csUser, csPWD);
		m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\r\n <s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>%s</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created></UsernameToken></Security></s:Header> <soap:Body>\r\n    <trt:GetProfiles />\r\n  </soap:Body></soap:Envelope>")
						, A2W(g_szUserName), A2W(g_szDigest), A2W(g_szNonceBase64BinaryString), A2W(g_szTimeString) );
		
		m_csCGIStatus = myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
		if(m_csCGIStatus)
		{
			LPSTR	pszMedia;
			char*	szMedia;
			
			g_fDigest = TRUE;

			int 	iLens = m_csCGIStatus.GetLength() + 1;
			
			szMedia = new char[iLens];

			USES_CONVERSION;
			strcpy(szMedia, W2A(m_csCGIStatus));

			for(int i = 0; i < iLens; i++)
			{
				if(szMedia[i] == '"') 
					szMedia[i] = 0x20;
			}
			 
			pszMedia = strstr(szMedia, "<trt:Profiles ");
			if(pszMedia)
			{
				LPSTR	pszEnd;
				//<trt:Profiles fixed="true" token="protoken_ch01">
				//<trt:Profiles token="Profile1" fixed="false">
				pszMedia += 14;				//<tt:Media><tt:XAddr>
				pszEnd = strstr(pszMedia, "token= ");
				if(pszEnd)
				{
					LPSTR	pszEnd1;
					pszEnd += 7;

					pszEnd1 = strstr(pszEnd, " ");
					if(pszEnd1)
					{
						strncpy(szGetProfileName, pszEnd, pszEnd1 - pszEnd);
						//szGetProfileName[pszEnd1 - pszEnd] = 0;
						OutputDebugStringA(szGetProfileName);
						TRACE(L"\n");
						fGet = TRUE;
					}				
				}
			}
			delete [] szMedia;
		}		
	}

	return fGet;
}

BOOL Get_RTSP_URI(CString url, CString csUser, CString csPWD, CString *pcsURL)
{
	Curlplus	myCUrl;
	BOOL		fGetService, fGetRTSP_URI = FALSE, fGetVideoProfile;
	char		szONVIF_URL[128] = {0};
	char		szFind[128] = {0};
	char		szGetProfileName[64] = {0};
	CString		m_csCgiUrl;

	fGetService = Get_Device_Service(url, csUser, csPWD, &szONVIF_URL[0]);
	if(fGetService)
	{
		USES_CONVERSION;

		m_csCgiUrl = A2W(szONVIF_URL);
		fGetVideoProfile = Get_VideoProfileName(m_csCgiUrl, csUser, csPWD, &szGetProfileName[0]);
	}
	
	if(fGetVideoProfile)
	{
		//CString		m_csCgiUrl, m_csContent;
		CString		m_csContent;
		CString		m_csGetRTSP;
		
		USES_CONVERSION;
		//http://10.1.21.92/onvif/device_service
		//m_csCgiUrl = CString(szONVIF_URL);

		//<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>
		//m_csCgiUrl = A2W(szONVIF_URL);
		//m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"> <SOAP-ENV:Body><trt:GetStreamUri><trt:StreamSetup xsi:type=\"tt:StreamSetup\"><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport xsi:type=\"tt:Transport\"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>Profile1</trt:ProfileToken></trt:GetStreamUri></SOAP-ENV:Body></SOAP-ENV:Envelope>"));
		//m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"> <s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>admin</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">edyqSKTmyz6UYK+0Wy9UcBkJrFw=</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">9b4jl7CIYEW80bCjQR98xOgBAAAAAA==</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2014-06-27T05:33:49.684Z</Created></UsernameToken></Security></s:Header> <SOAP-ENV:Body><trt:GetStreamUri><trt:StreamSetup xsi:type=\"tt:StreamSetup\"><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport xsi:type=\"tt:Transport\"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>%s</trt:ProfileToken></trt:GetStreamUri></SOAP-ENV:Body></SOAP-ENV:Envelope>"), A2W(szGetProfileName));
		if(!g_fDigest)
			m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"> <SOAP-ENV:Body><trt:GetStreamUri><trt:StreamSetup xsi:type=\"tt:StreamSetup\"><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport xsi:type=\"tt:Transport\"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>%s</trt:ProfileToken></trt:GetStreamUri></SOAP-ENV:Body></SOAP-ENV:Envelope>"), A2W(szGetProfileName));
		else
			m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:tt=\"http://www.onvif.org/ver10/schema\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"> <s:Header><Security xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><UsernameToken><Username>%s</Username><Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password><Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce><Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created></UsernameToken></Security></s:Header> <SOAP-ENV:Body><trt:GetStreamUri><trt:StreamSetup xsi:type=\"tt:StreamSetup\"><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport xsi:type=\"tt:Transport\"><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>%s</trt:ProfileToken></trt:GetStreamUri></SOAP-ENV:Body></SOAP-ENV:Envelope>")
					, A2W(g_szUserName), A2W(g_szDigest), A2W(g_szNonceBase64BinaryString), A2W(g_szTimeString), A2W(szGetProfileName) );
		
		m_csGetRTSP = myCUrl.Post_Wait_Return(m_csCgiUrl, csUser, csPWD, m_csContent);
		if(m_csGetRTSP)
		{
			LPSTR		pszMedia;
			char*		szMedia;
			
			szMedia = new char[m_csGetRTSP.GetLength()+1];
			//USES_CONVERSION;
			strcpy(szMedia,  W2A (m_csGetRTSP));
			pszMedia = strstr(szMedia, "<trt:MediaUri><tt:Uri>");
			if(pszMedia)
			{
				LPSTR	pszEnd;
				//<trt:MediaUri><tt:Uri>rtsp://10.1.21.92/live.sdp</tt:Uri>
				pszMedia += 22;				//<trt:MediaUri><tt:Uri>
				pszEnd = strstr(pszMedia, "</tt:Uri>");
				if(pszEnd)
				{
					strncpy(szFind, pszMedia, pszEnd - pszMedia);
					szFind[pszEnd - pszMedia] = 0;
					fGetRTSP_URI = TRUE;
					*pcsURL = A2W(szFind);
				}
			}
			delete [] szMedia;
		}		
	}

	g_fDigest = FALSE;
	
	return fGetRTSP_URI;
}

BOOL Get_PTZ_Capability(CString url, CString csUser, CString csPWD, CString *pcsURL)
{
	Curlplus	myCurl;
	CString		m_csCGIStatus;
	CString		m_csContent;
	BOOL		fGet = FALSE;
	
	m_csContent.Format(_T("<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities></s:Body></s:Envelope>"));
	
	m_csCGIStatus = myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
	if(m_csCGIStatus)
	{
		LPSTR		pszPTZ_XML;
		char*		szPTZ_XML;
		char		szFind[128] = {0};

		szPTZ_XML = new char[m_csCGIStatus.GetLength()+1];

		USES_CONVERSION;
		strcpy(szPTZ_XML,  W2A (m_csCGIStatus));
		 
		pszPTZ_XML = strstr(szPTZ_XML, "<tt:PTZ><tt:XAddr>");
		if(pszPTZ_XML)
		{
			LPSTR	pszEnd;

			//<tt:XAddr>http://10.1.21.124/onvif/ptz_service</tt:XAddr>
			pszPTZ_XML += 18;				//<tt:PTZ><tt:XAddr>
			pszEnd = strstr(pszPTZ_XML, "</tt:XAddr>");
			if(pszEnd)
			{
				strncpy(szFind, pszPTZ_XML, pszEnd - pszPTZ_XML);
				szFind[pszEnd - pszPTZ_XML] = 0;
				*pcsURL = A2W(szFind);
				//OutputDebugStringA(szFind);
				//TRACE(L"\n");
				fGet = TRUE;
			}
		}
		delete [] szPTZ_XML;
	}

	return fGet;
}

const	char	szPTZ_STOP[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><tptz:ContinuousMove><tptz:ProfileToken>Profile1</tptz:ProfileToken><tptz:Velocity><tt:PanTilt x=\"0\" y=\"0\" /><tt:Zoom x=\"0\" /></tptz:Velocity></tptz:ContinuousMove></s:Body></s:Envelope>";
	
const	char	szPTZ_ContinuousMove_Start[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\"><s:Body><tptz:ContinuousMove><tptz:ProfileToken>Profile1</tptz:ProfileToken><tptz:Velocity><tt:PanTilt ";
const	char	szPTZ_ContinuousMove_End[] = "</tptz:Velocity></tptz:ContinuousMove></s:Body></s:Envelope>";

//const	char	szPTZ_X_R[] = "x=\"0.300000012\" ";
//const	char	szPTZ_X_L[] = "x=\"-0.300000012\" ";
//const	char	szPTZ_X_R[] = "x=\"0.219999999\" ";
//const	char	szPTZ_X_L[] = "x=\"-0.219999999\" ";
const	char	szPTZ_X_R[] = "x=\"0.100000001\" ";
const	char	szPTZ_X_L[] = "x=\"-0.100000001\" ";

//const	char	szPTZ_X_UL[] = "x=\"-0.219999999\" ";
/*
const	char	szPTZ_X_UL[] = "x=\"-0.219999999\" ";
const	char	szPTZ_Y_UP_L[] = "y=\"0.100000001\" />";

const	char	szPTZ_X_DR[] = "x=\"0.219999999\" ";
const	char	szPTZ_Y_DOWN_R[] = "y=\"-0.100000001\" />";
*/
const	char	szPTZ_X[] = "x=\"0\" ";
const	char	szPTZ_Y[] = "y=\"0\" />";
const	char	szPTZ_Z[] = "<tt:Zoom x=\"0\" />";


//const	char	szPTZ_Y_UP[] = "y=\"0.300000012\" />";
//const	char	szPTZ_Y_DOWN[] = "y=\"-0.300000012\" />";
const	char	szPTZ_Y_UP[] = "y=\"0.100000001\" />";
const	char	szPTZ_Y_DOWN[] = "y=\"-0.100000001\" />";

const	char	szPTZ_Z_IN[] = "<tt:Zoom x=\"0.300000012\" />";
const	char	szPTZ_Z_DE[] = "<tt:Zoom x=\"-0.300000012\" />";

char	g_szPTZ[1536];

void Set_PTZ_STOP(CString url, CString csUser, CString csPWD)
{
	Curlplus	myCurl;
	CString		m_csContent;
	
	USES_CONVERSION;
	m_csContent = A2W(szPTZ_STOP);
	myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
}

void Set_PTZ_SEND(CString url, CString csUser, CString csPWD)
{
	Curlplus	myCurl;
	CString		m_csContent;
	
	USES_CONVERSION;
	m_csContent = A2W(g_szPTZ);
	myCurl.Post_Wait_Return(url, csUser, csPWD, m_csContent);
}

void Set_PTZ(CString url, CString csUser, CString csPWD, PTZ_MOVE enumMove)
{
	Curlplus	myCurl;
	CString		m_csContent;
	
	switch(enumMove)
	{
		case MOVE_UP_LEFT:
			//sprintf(g_szPTZ, "%s%s%s%s%s"
				//, szPTZ_ContinuousMove_Start, szPTZ_X_UL, szPTZ_Y_UP_L, szPTZ_Z, szPTZ_ContinuousMove_End);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_UP, szPTZ_Z, szPTZ_ContinuousMove_End);
			Set_PTZ_SEND(url, csUser, csPWD);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_L, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			TRACE(L"MOVE_UP_LEFT\n");
			break;
			
		case MOVE_UP:
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_UP, szPTZ_Z, szPTZ_ContinuousMove_End);
			TRACE(L"MOVE_UP\n");
			break;
			
		case MOVE_UP_RIGHT:
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_UP, szPTZ_Z, szPTZ_ContinuousMove_End);
			Set_PTZ_SEND(url, csUser, csPWD);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_R, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			TRACE(L"MOVE_UP_RIGHT\n");
			break;
			
		case MOVE_LEFT:
			TRACE(L"MOVE_LEFT\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_L, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			break;
			
		case MOVE_HOME:
			TRACE(L"MOVE_HOME\n");
			break;
			
		case MOVE_RIGHT:
			TRACE(L"MOVE_RIGHT\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_R, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			break;
			
		case MOVE_DOWN_LEFT:
			TRACE(L"MOVE_DOWN_LEFT\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_DOWN, szPTZ_Z, szPTZ_ContinuousMove_End);
			Set_PTZ_SEND(url, csUser, csPWD);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_L, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			break;

		case MOVE_DOWN:
			TRACE(L"MOVE_DOWN\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_DOWN, szPTZ_Z, szPTZ_ContinuousMove_End);
			break;
			
		case MOVE_DOWN_RIGHT:
			TRACE(L"MOVE_DOWN_RIGHT\n");
			//sprintf(g_szPTZ, "%s%s%s%s%s"
				//, szPTZ_ContinuousMove_Start, szPTZ_X_DR, szPTZ_Y_DOWN_R, szPTZ_Z, szPTZ_ContinuousMove_End);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y_DOWN, szPTZ_Z, szPTZ_ContinuousMove_End);
			Set_PTZ_SEND(url, csUser, csPWD);
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X_R, szPTZ_Y, szPTZ_Z, szPTZ_ContinuousMove_End);
			break;
			
		case MOVE_ZOOM_INCREASE:
			TRACE(L"MOVE_ZOOM_INCREASE\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y, szPTZ_Z_IN, szPTZ_ContinuousMove_End);
			break;
			
		case MOVE_ZOOM_DECREASE:
			TRACE(L"MOVE_ZOOM_DECREASE\n");
			sprintf(g_szPTZ, "%s%s%s%s%s"
				, szPTZ_ContinuousMove_Start, szPTZ_X, szPTZ_Y, szPTZ_Z_DE, szPTZ_ContinuousMove_End);
			break;

		default:
			TRACE(L"Set_PTZ No this cmd\n");
			return;
	}
	
	Set_PTZ_SEND(url, csUser, csPWD);
	
	Set_PTZ_STOP(url, csUser, csPWD);
}
