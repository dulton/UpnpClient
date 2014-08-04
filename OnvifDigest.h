/** SHA1 digest size in octets */
#define SOAP_SMD_SHA1_SIZE	(20)

/** Size of the random nonce */
#define SOAP_WSSE_NONCELEN	(20)

#define TOKEN_TIMESTAMP 5

class COnvifDigest
{
public:
	COnvifDigest(const char * szUsername, const char * szPassword);
	~COnvifDigest(void);

	void Authentication(soap * pSoap, bool bAuth = true, const std::string strId = "");

	const char * GetUsername(void);

	const char * GetPassword(void);

private:
	void TokenTimestmap(soap * pSoap, time_t lifetime = TOKEN_TIMESTAMP);

	void calc_nonce(struct soap *soap, char nonce[SOAP_WSSE_NONCELEN]);
	struct _wsse__Security* soap_wsse_add_Security(struct soap *soap);
	int  soap_wsse_add_UsernameTokenText(struct soap *soap, const char *id, const char *username, const char *password);
	int  soap_wsse_add_UsernameTokenDigest(struct soap *soap, const char *id, const char *username, const char *password);
	int  soap_wsse_add_Timestamp(struct soap *soap, const char *id, time_t lifetime);
	void calc_digest(struct soap *soap, const char *created, 
		const char *nonce, int noncelen, const char *password, char hash[SOAP_SMD_SHA1_SIZE]);

private:
	std::string m_strUsername;
	std::string m_strPassword;
};