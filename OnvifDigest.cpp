#include "stdafx.h"
#include "OnvifDigest.h"
#include "sha1.h"


const char *wsse_PasswordTextURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
const char *wsse_PasswordDigestURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest";
const char *wsse_Base64BinaryURI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";

COnvifDigest::COnvifDigest( const char * szUsername, const char * szPassword )
: m_strUsername(szUsername)
, m_strPassword(szPassword)
{

}

COnvifDigest::~COnvifDigest( void )
{

}

void COnvifDigest::Authentication( soap * pSoap, bool bAuth /*= true*/, const std::string strId /*= ""*/ )
{
	const char * szId = strId.empty() ? NULL : strId.c_str();
	if (bAuth)
	{
		soap_wsse_add_UsernameTokenDigest(pSoap, szId, m_strUsername.c_str(), m_strPassword.c_str());
		TokenTimestmap(pSoap);
	}
}

const char * COnvifDigest::GetUsername( void )
{
	return m_strUsername.c_str();
}

const char * COnvifDigest::GetPassword( void )
{
	return m_strPassword.c_str();
}

/* private */

void COnvifDigest::TokenTimestmap( soap *pSoap, time_t lifetime /*= TOKEN_TIMESTAMP*/ )
{
	soap_wsse_add_Timestamp(pSoap, "Time", lifetime);
}

void COnvifDigest::calc_nonce(struct soap *soap, char nonce[SOAP_WSSE_NONCELEN])
{
	int i;
	time_t r = time(NULL);
	memcpy(nonce, &r, 4);
	for (i = 4; i < SOAP_WSSE_NONCELEN; i += 4)
	{ 
		r = soap_random;
		memcpy(nonce + i, &r, 4);
	}
}

struct _wsse__Security* COnvifDigest::soap_wsse_add_Security(struct soap *soap)
{
	/* if we don't have a SOAP Header, create one */
	soap_header(soap);
	/* if we don't have a wsse:Security element in the SOAP Header, create one */
	if (!soap->header->wsse__Security)
	{ 
		soap->header->wsse__Security = (_wsse__Security*)soap_malloc(soap, sizeof(_wsse__Security));
		soap_default__wsse__Security(soap, soap->header->wsse__Security);
	}
	return soap->header->wsse__Security;
}

int COnvifDigest::soap_wsse_add_UsernameTokenText(struct soap *soap, const char *id, 
	const char *username, const char *password)
{ 
	_wsse__Security *security = soap_wsse_add_Security(soap);
	/* allocate a UsernameToken if we don't have one already */
	if (!security->UsernameToken)
		security->UsernameToken = (_wsse__UsernameToken*)soap_malloc(soap, sizeof(_wsse__UsernameToken));
	soap_default__wsse__UsernameToken(soap, security->UsernameToken);
	/* populate the UsernameToken */
	security->UsernameToken->wsu__Id = soap_strdup(soap, id);
	security->UsernameToken->Username = soap_strdup(soap, username);
	/* allocate and populate the Password */
	if (password)
	{ 
		security->UsernameToken->Password = (_wsse__Password*)soap_malloc(soap, sizeof(_wsse__Password));
		soap_default__wsse__Password(soap, security->UsernameToken->Password);
		security->UsernameToken->Password->Type = (char*)wsse_PasswordTextURI;
		security->UsernameToken->Password->__item = soap_strdup(soap, password);
	}
	return SOAP_OK;
}

int COnvifDigest::soap_wsse_add_UsernameTokenDigest(struct soap *soap, const char *id, 
	const char *username, const char *password)
{ 
	_wsse__Security *security = soap_wsse_add_Security(soap);
	time_t now = time(NULL);
	const char *created = soap_dateTime2s(soap, now);
	char HA[SOAP_SMD_SHA1_SIZE], HABase64[29];
	char nonce[SOAP_WSSE_NONCELEN], *nonceBase64;
	/* generate a nonce */
	calc_nonce(soap, nonce);
	nonceBase64 = soap_s2base64(soap, (unsigned char*)nonce, NULL, SOAP_WSSE_NONCELEN);
	/* The specs are not clear: compute digest over binary nonce or base64 nonce? */
	/* compute SHA1(created, nonce, password) */

/*	// boost?算?果不?，??是我的使用方法不?
	unsigned int Digest[5] = {0};
	boost::uuids::detail::sha1	sha;
	sha.process_bytes(nonce, strlen(nonce));
	sha.process_bytes(created, strlen(created));
	sha.process_bytes(password, strlen(password));
	sha.get_digest(Digest);

	for (int n=0,i=0; n<SOAP_SMD_SHA1_SIZE; )
	{
		HA[n++] = (Digest[i] >> 24) & 0xFF;
		HA[n++] = (Digest[i] >> 16) & 0xFF;
		HA[n++] = (Digest[i] >> 8) & 0xFF;
		HA[n++] = Digest[i] & 0xFF;
		i++;
	}*/
	calc_digest(soap, created, nonce, SOAP_WSSE_NONCELEN, password, HA);
//	calc_digest(soap, created, nonce, SOAP_WSSE_NONCELEN, password, HA);

	/*
	calc_digest(soap, created, nonceBase64, strlen(nonceBase64), password, HA);
	*/
	soap_s2base64(soap, (unsigned char*)HA, HABase64, SOAP_SMD_SHA1_SIZE);
	/* populate the UsernameToken with digest */
	soap_wsse_add_UsernameTokenText(soap, id, username, HABase64);
	/* populate the remainder of the password, nonce, and created */
	security->UsernameToken->Password->Type = (char*)wsse_PasswordDigestURI;
	security->UsernameToken->Nonce = nonceBase64;
	security->UsernameToken->wsu__Created = soap_strdup(soap, created);

	return SOAP_OK;
}

int COnvifDigest::soap_wsse_add_Timestamp( struct soap *soap, const char *id, time_t lifetime )
{
	_wsse__Security *security = soap_wsse_add_Security(soap);
	time_t now = time(NULL);
	char *created = soap_strdup(soap, soap_dateTime2s(soap, now));
	char *expired = lifetime ? soap_strdup(soap, soap_dateTime2s(soap, now + lifetime)) : NULL;
	/* allocate a Timestamp if we don't have one already */
	if (!security->wsu__Timestamp)
		security->wsu__Timestamp = (_wsu__Timestamp*)soap_malloc(soap, sizeof(_wsu__Timestamp));
	soap_default__wsu__Timestamp(soap, security->wsu__Timestamp);
	/* populate the wsu:Timestamp element */
	security->wsu__Timestamp->wsu__Id = soap_strdup(soap, id);
	security->wsu__Timestamp->Created = created;
	security->wsu__Timestamp->Expires = expired;
	return SOAP_OK;
}

void COnvifDigest::calc_digest( struct soap *soap, const char *created, 
	const char *nonce, int noncelen, const char *password, char hash[SOAP_SMD_SHA1_SIZE] )
{
	SHA1Context sha;
	SHA1Reset(&sha);
	SHA1Input(&sha, (unsigned char *)nonce, noncelen);
	SHA1Input(&sha, (unsigned char *)created, strlen(created));
	SHA1Input(&sha, (unsigned char *)password, strlen(password));
	if (!SHA1Result(&sha))
	{
		fprintf(stderr, "ERROR-- could not compute message digest\n");
	}
	else
	{
		int j = 0;
		for(int i = 0; i < 5 ; i++)
		{
			hash[j++] = sha.Message_Digest[i] >> 24;
			hash[j++] = sha.Message_Digest[i] >> 16;
			hash[j++] = sha.Message_Digest[i] >> 8;
			hash[j++] = sha.Message_Digest[i] >> 0;
		}
	}
}