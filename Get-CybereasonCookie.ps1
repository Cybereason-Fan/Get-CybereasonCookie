Function global:Get-CybereasonCookie {
<#
.SYNOPSIS
Authenticates to an on-premises Cybereason API and returns a cookie
.DESCRIPTION
Generate a session cookie (32 character string) which you can use for the next 8 hours for all subsequent calls to the Cybereason on-premises API
.PARAMETER server_fqdn
Required string - This is the fully qualified domain name of the Cybereason console. There is no error-checking on this. Make sure you have it correct.
.PARAMETER credential
Optional PSCredential that you can supply. This is useful for testing when you intend to run this function many times in a row and not want to type in your password over and over. When this parameter is not supplied, the user will be prompted with Get-Credential.
.PARAMETER otp
Optional string* with your MFA (aka TFA) one-time password. * when specified, this needs to be a 6-digit integer
.PARAMETER no_mfa
Optional switch that removes the requirement for the otp (MFA code)
.PARAMETER JustGiveMeTheCookie
Optional Switch that will cause the output to be *only* the 32 character string of the session cookie. This is intended for scripts and other automations which may use this function.
.PARAMETER NoFormatting
Optional Switch that removes the color formatting from the default output
.PARAMETER DebugMode
Optional Switch that will verbosely display the parameters that are sent to Invoke-WebRequest (good for troubleshooting)
.EXAMPLE
Get-CybereasonCookie -server_fqdn 'server.domain.com' -credential $credential -otp 123456
.LINK
https://github.com/Cybereason-Fan/Get-CybereasonCookie
#>
    Param(
        [Parameter(Mandatory = $true)]
        [string]$server_fqdn,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$otp,
        [Parameter(Mandatory = $false)]
        [switch]$no_mfa,
        [Parameter(Mandatory = $false)]
        [switch]$JustGiveMeTheCookie,
        [Parameter(Mandatory = $false)]
        [switch]$NoFormatting,
        [Parameter(Mandatory = $false)]
        [switch]$DebugMode
    )
    Function Invoke-CybereasonAPI {
        [OutputType([System.Net.Cookie])]
        Param(
            [Parameter(Mandatory = $true)]
            [hashtable]$parameters        
        )
        $ProgressPreference = 'SilentlyContinue'
        $Error.Clear()    
        Try {
            [Microsoft.PowerShell.Commands.WebResponseObject]$response = Invoke-WebRequest @parameters
        }
        Catch {
            [array]$error_clone = $Error.Clone()
            [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
            Write-Host "Error: Invoke-WebRequest failed due to [$error_message]"
            Exit
        }
        Remove-Variable -Force -Name parameters
        If ( $response.StatusCode -isnot [int]) {
            Write-Host "Error: Somehow there was no numerical response code"
            Exit
        }
        [int]$response_statuscode = $response.StatusCode
        If ( $response_statuscode -ne 200) {
            Write-Host "Error: Received a numerical status code [$response_statuscode] instead of 200 'OK'. Please look into this."
            Exit
        }
        If ( $null -ne $web_session.Cookies) {
            [System.Net.Cookie]$cookie = $web_session.Cookies.GetCookies($logon_url) | Select-Object -First 1
            [string]$session_id = $cookie.Value
            If ( $session_id -cnotmatch $regex_jsessionid ) {
                Write-Host "Error: Somehow the session id [$session_id] is not a valid session id string"
                Exit
            }
            Return $cookie
        }
    }
    If ( $null -eq $credential ) {    
        $Error.Clear()
        Try {
            [PSCredential]$credential = Get-Credential
        }
        Catch {
            [array]$error_clone = $Error.Clone()
            [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
            Write-Host "Error: Get-Credential failed due to [$error_message]"
            Exit
        }
    }
    Try {
        [int]$otp_length = $otp.Length    
        If (($otp_length -gt 0) -and ($no_mfa -eq $true)) {
            Write-Host "Error: You cannot specify a MFA code and also specify -no_mfa. Please choose one or the other"
            Exit
        }
        ElseIf (($otp_length) -and ($otp -notmatch '^[\d]{6}$')) {
            Write-Host "Error: The MFA code is expected to be 6 digits in length (only digits!)"
            Exit
        }
        ElseIf (($otp -match '^[\d]{6}$') -and ($no_mfa -ne $true)) {
            [boolean]$mfa = $true
        }
        ElseIf (($no_mfa -eq $true) -and ($otp_length -eq 0)) {
            [boolean]$mfa = $false
        }
        Else {
            Write-Host "You needed to specify either your OTP code with -otp or specify a non-MFA logon with -no_mfa. Please try again."
            Exit
        }
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Converting OTP error due to [$error_message]"
        Exit
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [string]$regex_jsessionid = '^[0-9A-F]{32}$'
    [string]$logon_url = "https://$server_fqdn/login.html"
    [string]$username = $credential.UserName
    [int]$username_length = $username.Length
    If ( $username_length -eq 0) {
        Write-Host "Error: How is the username empty?"
        Exit
    }
    $Error.Clear()
    Try {
        [string]$unencrypted_string = $credential.GetNetworkCredential().Password
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Failed to convert the entered password into a secure string due to [$error_message]"
        Exit
    }
    Remove-Variable -Force -Name credential
    [hashtable]$body = @{ 'username' = $username; 'password' = $unencrypted_string; }
    Remove-Variable -Force -Name unencrypted_string
    [hashtable]$parameters = @{}
    $parameters.Add('Uri', $logon_url)
    $parameters.Add('Method', 'POST')
    $parameters.Add('ContentType', 'application/x-www-form-urlencoded')
    $parameters.Add('Body', $body)
    $parameters.Add('SessionVariable', 'web_session')
    If ( $DebugMode -eq $true) {
        [hashtable]$parameters_clone = $parameters.Clone()
        $parameters_clone.body.password = '***REDCATED***'
    }
    For ($i = 0; $i -le 1; $i++) {    
        If ($i -eq 0) {
            [System.Net.Cookie]$cookie = Invoke-CybereasonAPI -parameters $parameters
        }
        ElseIf (($i -eq 1) -and ($mfa -eq $true)) {                
            Try {            
                [Microsoft.PowerShell.Commands.WebRequestSession]$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
                $session.Cookies.Add($cookie)
            }
            Catch {
                [array]$error_clone = $Error.Clone()
                [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
                Write-Host "Error: Failed to create a new web request session and add a cookie to it due to [$error_message]"
                Exit
            }
            $parameters.Remove('SessionVariable')
            $parameters.Add('WebSession', $session)
            $parameters.Remove('Body')
            $body.Remove('username')
            $body.Remove('password')
            $body.Add('submit', 'Login')
            $body.Add('totpCode', $otp)
            Remove-Variable -Force -Name otp
            $parameters.Add('Body', $body)
            Remove-Variable -Force -Name body
            $parameters.Remove( 'Uri')
            $parameters.Add('Uri', ($logon_url -replace 'login.html'))        
            Invoke-CybereasonAPI -parameters $parameters
        }
        ElseIf (($i -eq 1) -and ($mfa -ne $true)) {
        
        }
        Else {
            Write-Host "Error: Somehow the authentication loop broke"
            Exit
        }
    }
    [string]$session_id = $cookie.Value
    [datetime]$session_expires = $cookie.Expires
    [string]$session_expires_display = Get-Date -Date $session_expires -Format 'yyyy-MM-dd HH:mm:ss'
    [datetime]$session_timestamp = $cookie.Timestamp
    [string]$session_timestamp_display = Get-Date -Date $session_timestamp -Format 'yyyy-MM-dd HH:mm:ss'
    If ( $JustGiveMeTheCookie -eq $true) {
        Return $session_id
    }
    ElseIf ( $NoFormatting -eq $true) {
        Write-Host ""
        Write-Host "Cybereason cookie generated for $username at $session_timestamp_display"
        Write-Host "Session ID $session_id expiration at $session_expires_display"
        Write-Host ""
    }
    Else {
        Write-Host ""
        Write-Host "Cybereason cookie generated for " -NoNewline
        Write-Host $username -NoNewline -ForegroundColor Yellow
        Write-Host " at " -NoNewline
        Write-Host $session_timestamp_display -ForegroundColor Magenta
        Write-Host "Session ID " -NoNewLine
        Write-Host $session_id -NoNewline -ForegroundColor Red
        Write-Host " expiration at " -NoNewline
        Write-Host $session_expires_display -ForegroundColor Magenta
        Write-Host ""
    }
}