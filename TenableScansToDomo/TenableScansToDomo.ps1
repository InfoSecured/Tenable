
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

$CLIENT_ID = ""
$CLIENT_SECRET = ""
$datasetId = ""
$TENABLE_USER = ""
$TENABLE_PASS = ""
$TENABLE_URL = ""

#----------------------------------
# Login To Tenable
#----------------------------------
#Ignore self signed certificates
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
# Build credentials object
$LoginData = (ConvertTo-Json -compress @{username=$TENABLE_USER; password=$TENABLE_PASS})
#----------------------------------
# Get Token
#----------------------------------
# Login to Tenable
                        
try{
    $ret = Invoke-WebRequest -URI "$($TENABLE_URL)/token" -Method POST  -Body $LoginData -UseBasicParsing -SessionVariable sv -ErrorAction Stop

}
catch [System.Net.WebException] {
    $failMessage = ($_.Exception.Message).ToString().Trim();
    Write-Output $failMessage;
    If ($failMessage.Contains('404')) { 
        Write-Output "Host not found. Exiting." 
        write-host $error[0]
        throw $LASTEXITCODE
    }
    ElseIf ($failMessage.Contains('403')) { 
        Write-Output "Invalid Login Credentials. Exiting." 
        write-host $error[0]
        throw $LASTEXITCODE
    }
    Exit
}
# Extract the token
$loginToken = (ConvertFrom-json $ret.Content).response.token

#----------------------------------
# Get Data from Tenable
#----------------------------------
$csv_upload = ''
try {
    $ret = Invoke-WebRequest -URI "$($TENABLE_URL)/scanResult?&filter=running&fields=id,name,status,startTime,totalIPs,completedIPs" -Method Get -Headers @{"X-SecurityCenter"=$($loginToken); "Content-Type"="application/json"} -Websession $sv -ErrorAction Stop | ConvertFrom-Json | SELECT -expand response | SELECT -expand manageable 
    $array = @($ret)
                                        
    foreach($scan in $array)
    {
        $id = $scan.id
        $name = $scan.name
        $status = $scan.status
        $startTime = $scan.startTime
        $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
        $startTime = $origin.AddSeconds($startTime).ToLocalTime()
        $totalIPs = $scan.totalIPs
        $completedIPs = $scan.completedIPs
        $percentage = [math]::Round(($completedIPs/$totalIPs)*100,2)
        foreach($i in $id)
            {
                $ret = Invoke-WebRequest -URI "$($TENABLE_URL)/scanResult/$($id)" -Method Get -Headers @{"X-SecurityCenter"=$($loginToken); "Content-Type"="application/json"} -Websession $sv -ErrorAction Stop | ConvertFrom-Json | SELECT -expand response | SELECT -expand progress
                $array2 = @($ret)

                $scanningIPs = $ret.scanningIPs
                $scanningIPs = $scanningIPs.Replace('-',' - ')
                $csv_upload += "`"{0}`",`"{1}`",`"{2}`",`"{3}`",`"{4}`",`"{5}`"`n" -f $id,$name,$status,$startTime,$scanningIPs,$percentage
            }
    }
}
catch [System.Net.WebException] {
    $failMessage = ($_.Exception.Message).ToString().Trim();
    Write-Output $failMessage;
    If ($failMessage.Contains('404')) { 
        Write-Output "Host not found. Exiting." 
        write-host $error[0]
        throw $LASTEXITCODE
    }
    ElseIf ($failMessage.Contains('403')) { 
        Write-Output "An error occurred. Exiting." 
        write-host $error[0]
        throw $LASTEXITCODE
    }
    Exit
}

#Destroy the token
Invoke-WebRequest -URI "$($TENABLE_URL)/token" -method Delete -UseBasicParsing -Headers @{"X-SecurityCenter"="$loginToken"} -Websession $sv
Write-Host $csv_upload


#----------------------------------
# Get Token From Domo
#----------------------------------
$Url = "https://api.domo.com/oauth/token?grant_type=client_credentials&scope=data"
                        
$CLIENT_SECRET = $CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential -ArgumentList $CLIENT_ID,$CLIENT_SECRET
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $CLIENT_ID,$CLIENT_SECRET))) 
                        
$headers = @{"Authorization" = "Basic $base64AuthInfo"}
function SendToDomo {
    [cmdletbinding()]
    Param([Parameter()] $datasetId)
                
    $Response = Invoke-RestMethod -Method Get -Uri $Url -Headers $headers -Credential $credential -ContentType "application/json"
    $access_token = "bearer $($Response.access_token)"
                            
    #----------------------------------
    # Write Data to Domo
    #----------------------------------

    $Url = "https://api.domo.com/v1/datasets/$datasetId/data"
    $domoheaders = @{'Content-Type'= 'text/csv'; 'Accept'= 'text/csv'; 'Authorization'= $access_token}
    $WriteData = Invoke-RestMethod -Method Put -Uri $Url -Headers $domoheaders -Body $csv_upload

    Write-Host $WriteData
}
SendToDomo $datasetId
                 
Write-Host $access_token
Write-Host $WriteData
			