
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

$tenableUser = "" # In this case should be API credentials.
$tenablePass = "" # In this case should be API credentials.
$global:client_id = "" # Needs to be obtained from Salesforce Connected App. .
$global:client_secret = "" # Needs to be obtained from Salesforce Connected App. 
$global:security_token = "" # Needs to be obtained from Salesforce User Profile. Can be reset by user if unknown.
$global:username = "" # Same credentials as Federation.
$global:password = "" # Same credentials as Federation.
[int]$queryId = "" # Tenable Query ID.
$additional = "" # Location of file with additional data for the description field.
$tenable_url = ""
$global:SFTokenURL = ""
$global:SFProdURL = ""

$additional = Get-Content -Raw $additional | ConvertFrom-StringData

# Obtains a Token from Salesforce
function SalesforceToken {
    [cmdletbinding()]

    $browser = New-Object System.Net.WebClient
    $browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials

    $postParams = @{
        grant_type = "password"
        client_id=$global:client_id;
        client_secret=$global:client_secret;
        username=$global:username;
        password="$($global:password)$($global:security_token)";
    }

    $preAuth = Invoke-RestMethod -Uri $global:SFTokenURL -Method POST -Body $postParams
    $authValue = "Bearer $($preAuth.access_token)"
    
    Return $authValue
}

# Creates an IT Case in Salesforce
function CreateCase {
    [cmdletbinding()]
    Param([Parameter()]$subject,$description)

    $authValue = SalesforceToken
    $SFHeaders = @{"Authorization" = $authValue; "Accept" = "application/json"; "Content-Type" = "application/json"}

    $payload = (ConvertTo-Json -Compress @{ #Change these fields as necessary for the Salesforce Case Object
        "Type"="IT Cases";
        "Origin"= "IT Technician";
        "Case_Category__c"= "Security";
        "Case_Subcategory__c"= "Vulnerability Management";
        "Queue_Assignment__c"= "Information Assurance";
        "Status"= "unassigned";
        "Subject"= "$($subject)";
        "Priority"= "High";
        "Description"= "$($description)"
    })

    Invoke-WebRequest -Uri $global:SFProdURL -Method POST -Headers $SFHeaders -Body $payload
}

# Obtains a Token for Tenable
function TenableToken {
    [cmdletbinding()]
    Param([Parameter()]$tenableUser,$tenablePass)

    $headers = @{'Content-Type'= 'application/json'}
    $creds = (ConvertTo-Json -Compress @{username=$tenableUser; password=$tenablePass})
    $ret = Invoke-WebRequest -Method Post -Uri "$($tenable_url)/token" -Headers $headers -Body $creds -UseBasicParsing -SessionVariable sv
    $token = (ConvertFrom-json $ret.Content).response.token

    Return $token, $sv
}

# Obtains vulnerability data from Tenable
function GetFindings {
    [cmdletbinding()]
    Param([Parameter()][string]$tenable_token, $queryId, $IPAddressList, $sv)

    $payload = (ConvertTo-Json -Compress @{
        "type" = "vuln";
        "query" = @{
            "id"=$queryId
        };
        "sourceType"= "cumulative";
        "startOffset" = 0;
        "endOffset" = 1000;
        "columns" = @(
            @{"name"="pluginID"}
            @{"name"="pluginName"}
            @{"name"="severity"}
            @{"name"="ip"}
            @{"name"="dnsName"}
            @{"name"="netbiosName"}
            @{"name"="pluginText"}
            @{"name"="firstSeen"}
            @{"name"="lastSeen"}
            @{"name"="synopsis"}
        )
    })

    $ret = Invoke-WebRequest -Method Post -Uri "$($tenable_url)/analysis/download" -Headers @{"X-SecurityCenter"=$($tenable_token); "Content-Type"="application/json"} -Body $payload -UseBasicParsing -WebSession $sv

    Return $ret
}

# Turns vulnerability data into human readable
# information for upload to Salesforce via API
function ShapeData {
    [cmdletbinding()]
    Param([Parameter()]$Data, $additional)

    $converted = ConvertFrom-Csv $Data.Content | Select-Object 'Plugin','Plugin Name','Severity','IP Address','DNS Name','NetBIOS Name','Plugin Text','First Discovered','Last Observed','Synopsis'

    # Fill in the DNS Name with either the NetBIOS Name or IP Address if it does not exist and change case to uppercase.
    for($index = 0; $index -lt $converted.count; $index++) {
        foreach($item in $converted[$index]) {
            if(! $item.'DNS Name') {$item.'DNS Name' = $item.'NetBIOS Name'}
            if(! $item.'DNS Name') {$item.'DNS Name' = $item.'IP Address'}
            $item.'DNS Name' = $item.'DNS Name' -replace [RegEx]::Escape("\\..*\\.com"),""
            $item.'DNS Name' = $item.'DNS Name' -replace "UNKNOWN\\\\",""
            $item.'DNS Name' = $item.'DNS Name' -replace [RegEx]::Escape(".*\\\\"),""
            $item.'DNS Name' = $item.'DNS Name'.ToUpper()
        }
    }

    # Group vulnerabilities by Plugin ID
    $grouped = $converted | Select-Object * | Group-Object Plugin
    
    if ($grouped -ne $null) {
        for ($i = 0; $i -le $grouped.Length-1; $i++) {

            $targets = $grouped[$i].Group | Select-Object -ExpandProperty 'DNS Name' | Out-String
            $targets = $targets.Replace(" ","`n") 
            $synopsis = $grouped[$i].Group | Select-Object -Unique -ExpandProperty Synopsis
            $plugin = $grouped[$i].Group | Select-Object -Unique -ExpandProperty Plugin
            $pluginName = $grouped[$i].Group | Select-Object -Unique -ExpandProperty 'Plugin Name'

            $subject = "Tenable (1-High): {0}" -f $pluginName

            # Looks for the Plugin ID in the $additional hashtable and if it exists, adds more details to the description.
            if($plugin -in $additional.keys){
                $description = "The system(s) below contain the following vulnerability: `n`n{0}`n`n{3}`n`n{1}`n`nReference: Plugin {2}" -f $synopsis,$targets,$plugin,$additional.item($plugin)
            }
            else{
                $description = "The system(s) below contain the following vulnerability: `n`n{0}`n`n{1}`n`nReference: Plugin {2}" -f $synopsis,$targets,$plugin
            }
            
            CreateCase $subject $description
        }
    }
    else {
        Write-Output "No Data Retrieved"
        Exit 0
    }
}

$tenable_token, $sv = TenableToken $tenableUser $tenablePass
$Data = GetFindings $tenable_token $queryId $IPAddressList $sv
$Payload = ShapeData $Data $additional

#Destroy the Tenable token
Invoke-WebRequest -URI "$($tenable_url)/token" -method Delete -UseBasicParsing -Headers @{"X-SecurityCenter"="$tenable_token"} -Websession $sv
