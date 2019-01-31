
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$TenableUser = ""
$TenablePass = ""
$CLIENT_ID = ""
$CLIENT_SECRET = ""
$global:DomoBaseUrl = "https://api.domo.com"
$global:DomoDatasetId = ""
$global:TenableURL = "https://insertURLhere/rest"

function DomoToken {
    [cmdletbinding()]
    Param([Parameter()]$CLIENT_ID,$CLIENT_SECRET)
    $DomoTokenUrl = "oauth/token?grant_type=client_credentials&scope=data"
                                    
    $CLIENT_SECRET = $CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $CLIENT_ID,$CLIENT_SECRET
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $CLIENT_ID,$CLIENT_SECRET))) 
                                    
    $headers = @{"Authorization" = "Basic $base64AuthInfo"}
                        
    $Response = Invoke-RestMethod -Method Get -Uri "$($global:DomoBaseUrl)/$($DomoTokenUrl)" -Headers $headers -Credential $credential -ContentType "application/json"
                            
    $access_token = "bearer $($Response.access_token)"
    return $access_token
}
            
function DomoData {
    [cmdletbinding()]
    Param([Parameter()]$access_token)
    
    $DomoHeaders = @{'Content-Type'= 'text/csv'; 'Accept'= 'text/csv'; 'Authorization'= $access_token}
    $DomoData = "v1/datasets/$($global:DomoDatasetId)/data?includeHeader=true"
    $Data = Invoke-RestMethod -Method Get -Uri "$($global:DomoBaseUrl)/$($DomoData)" -Headers $DomoHeaders

    return $Data
}
function TenableToken {
    [cmdletbinding()]
    Param([Parameter()]$TenableUser,$TenablePass)
    $headers = @{'Content-Type'= 'application/json'}
    $creds = (ConvertTo-Json -Compress @{username=$TenableUser; password=$TenablePass})
    $ret = Invoke-WebRequest -Method Post -Uri "$($global:TenableURL)/token" -Headers $headers -Body $creds -UseBasicParsing -SessionVariable sv
    $token = (ConvertFrom-json $ret.Content).response.token
    Return $token, $sv
}
function SendToTenable {
    [cmdletbinding()]
    Param([Parameter()][string]$tenable_token, $IPAddressList, $sv)
    $Body = (ConvertTo-Json -Compress @{"definedIPs"="$($IPAddressList)"})
    $ret = Invoke-WebRequest -Method Patch -Uri "$($global:TenableURL)/asset/53" -Headers @{"X-SecurityCenter"=$($tenable_token); "Content-Type"="application/json"} -Body $Body -UseBasicParsing -WebSession $sv
    Return $ret
}

$access_token = DomoToken $CLIENT_ID $CLIENT_SECRET
$Data = DomoData $access_token
$Keys = ConvertFrom-Csv $Data | Where-Object "Risk Rating" -Like "*High*" | Select-Object -ExpandProperty "IP Address"
[string]$IPAddressList = $Keys -join ","
$tenable_token, $sv = TenableToken $TenableUser $TenablePass
$Send = SendToTenable $tenable_token $IPAddressList $sv

#Destroy the Security Center token
$ret = Invoke-WebRequest -URI "$($global:TenableURL)/token" -method Delete -UseBasicParsing -Headers @{"X-SecurityCenter"="$tenable_token"} -Websession $sv
