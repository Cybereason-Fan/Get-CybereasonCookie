# [Get-CybereasonCookie 1.0.0](https://github.com/Cybereason-Fan/Get-CybereasonCookie)

### Authenticates to an on-premises Cybereason API and returns a cookie 🍪
> Requires an account on an on-premises Cybereason management console

![image](usage-Get-CybereasonSensors.png)

```
 
❗ You must load this script as a "dot sourced" script (see the screenshot above!)

```
. .\Get-CybereasonCookie.ps1
```
```
SYNTAX
    Get-CybereasonCookie [-server_fqdn] <String> [[-Credential] <PSCredential>] [[-otp] <String>] [-no_mfa]
    [-JustGiveMeTheCookie] [-NoFormatting] [-DebugMode] [<CommonParameters>]


DESCRIPTION
    Generate a session cookie (32 character string) which you can use for the next 8 hours for all subsequent calls to
    the Cybereason on-premises API
``` 

❓ Not sure what to do with your cookie? Use it with tools such as [Get-CybereasonSensors](https://github.com/Cybereason-Fan/Get-CybereasonSensors)

## 1.0.0

- Initial release

