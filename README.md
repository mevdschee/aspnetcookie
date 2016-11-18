# aspnetcookie

A Go package that can decode and validate an ASP.net FormsAuthentication encrypted and signed cookie.

## Limitations

Currently only the following (Web.config) configuration is tested:

```
<machineKey
    validationKey="2E502E08392C704E2234759EDA7A5940A8CE1C42C7964B8142778764CF0006C2"
    decryptionKey="5226859B3CB262982B574093B29DAD9083030C93604C820F009D5192BDEC31F2"
    validation="SHA1"
    decryption="AES"
    compatibilityMode="Framework20SP2"
/>
```

Only SHA1 based HMAC and AES encryption are currently supported.

## Usage

```
validationKey, _ := hex.DecodeString("2E502E08392C704E2234759EDA7A5940A8CE1C42C7964B8142778764CF0006C2")
decryptionKey, _ := hex.DecodeString("5226859B3CB262982B574093B29DAD9083030C93604C820F009D5192BDEC31F2")
codec := aspnetcookie.New("SHA1", validationKey, "AES", decryptionKey)
cookie, _ := codec.EncodeNew("maurits.vanderschee", 3600*24*365, true, "\"nothing\"", "/")
ticket, _ := codec.Decode(cookie)
```	

where ticket is:

```
// FormsAuthenticationTicket holds:
type FormsAuthenticationTicket struct {
	version           byte
	name              string
	issueDateUtc      int64
	expirationDateUtc int64
	isPersistent      bool
	userData          string
	cookiePath        string
}
```

## Links

see: https://referencesource.microsoft.com/#System.Web/Security/FormsAuthentication.cs
