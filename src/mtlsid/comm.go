package mtlsid

//
// Type mapping definitions for ReST communiation
// We are going to create a big structure to aid automatic identification of types
//

type Simple_Response struct {
	Outcome string `json:"outcome"`
}

type Intent_Reference struct {
	Value   string `json:"value"`
	Outcome string `json:"outcome"`
}

type X509_Identity struct {
	Name        string `json:"name"`
	P12         string `json:"p12"`
	Password    string `json:"password"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private-key"`
	Outcome     string `json:"outcome"`
}

type signon_Result struct {
	Token   string `json:"token"`
	Outcome string `json:"outcome"`
}

type Auth_Response struct {
	Error  string        `json:"error"`
	Result signon_Result `json:"result"`
}

type Intent struct {
	Token  string `json:"token"`
	Intent string `json:"intent"`
	QR     string `json:"intent-qr"`
}

type Intent_Response struct {
	Error  string `json:"error"`
	Result Intent `json:"result"`
}

type X509_Identity_Response struct {
	Error  string        `json:"error"`
	Result X509_Identity `json:"result"`
}

type Autoprovisioning_Token_Response struct {
	Error  string        		  `json:"error"`
	Result Autoprovisioning_Token `json:"result"`
}

type Autoprovisioning_Token struct {
	Managed_Service  string     `json:"managed-cli.Service"`
	Token            string 	`json:"token"`
}

type IDP_Response struct {
	SimpleResponse  Simple_Response  `json:"Simple-Response"`
	IdentityProfile Identity_Profile `json:"Identity-Profile"`
	Http_code       int
}

type Identity_Profile struct {
	OrgID              string   `json:"organizational-reference"`
	LocalUserID        string   `json:"local-user-id"`
	ServiceRoles       []string `json:"service-roles"`
	TrustSponsors      []string `json:"trust-sponsors"`
	SitesFrequented    int      `json:"sites-frequented"`
	AverageIdentityAge int      `json:"average-identity-age"`
	MaxIdentityAge     int      `json:"max-identity-age"`
	TrustScore         int      `json:"trust-score"`
	LocalTrust         int      `json:"local-trust"`
	LocalIntrusions    int      `json:"local-intrusions"`
	Outcome            string   `json:"outcome"`
}
