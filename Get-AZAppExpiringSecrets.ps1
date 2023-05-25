
# @amoranio

<#

######## If you wish to run this with input ##########

param(
    [Parameter(Mandatory=$true)]
    [string]$tenantId,
    [Parameter(Mandatory=$true)]
    [string]$SPClientId,
    [Parameter(Mandatory=$true)]
    [string]$SPClientSecret,
    [Parameter(Mandatory=$true)]
    [string]$groupid
)

#>


##########################


###### Functions #########

function Get-AccessToken {
    param (
        [string]$tenantId,
        [string]$SPClientId,
        [string]$SPClientSecret
    )

    $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $SPClientId
        client_secret = $SPClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
    return $response.access_token
}


function Get-ServicePrincipalsFromGroup($accessToken, $groupId) {
    $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/members/microsoft.graph.servicePrincipal"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    return $response.value
}


function Get-ApplicationFromServicePrincipal($accessToken, $servicePrincipalId) {
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$servicePrincipalId/appId"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    return $response.value
}


function Get-ApplicationSecrets($accessToken, $appId) {
    $uri = "https://graph.microsoft.com/v1.0/applications/$appId/passwordCredentials"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers
    return $response.value
}

function Get-ApplicationObjectId($accessToken, $clientId) {
    $uri = "https://graph.microsoft.com/v1.0/applications?" + '$filter'+ "=appId eq '$($clientId)'"
    $headers = @{
        "Authorization" = "Bearer $accessToken"
    }

    $response = Invoke-RestMethod -Uri $uri -Headers $headers

    return $response.value.id
}


function Get-ServicePrincipalSecretExpiry($secret, $expiryThreshold) {
    $expiryDate = Get-Date $secret.endDateTime
    $currentDate = Get-Date
    $expiryInMonths = (($expiryDate - $currentDate).Days) / 30

    return $expiryInMonths -le $expiryThreshold
}


function Get-ExpiringServicePrincipalSecrets($accessToken, $expiryThreshold = 3, $groupid) {
    $expiringSecrets = @()

    $servicePrincipals = Get-ServicePrincipalsFromGroup -accessToken $accessToken -groupId $groupid

    foreach ($servicePrincipal in $servicePrincipals) {
        Write-Host "[*] Checking ServicePrincipal: $($servicePrincipal.id)"
        ############

        $appclientID = Get-ApplicationFromServicePrincipal -accessToken $accessToken -servicePrincipalId $servicePrincipal.id

        ## need to get the objectID rather than the appID
        $applicationID = Get-ApplicationObjectId -accessToken $accessToken -clientId $appclientID
        Write-Host "[*] Releated AppID: $($applicationID)"

        ##############
        $secrets = Get-ApplicationSecrets -accessToken $accessToken -appId $applicationID

        #################

        foreach ($secret in $secrets) {
            if (Get-ServicePrincipalSecretExpiry -secret $secret -expiryThreshold $expiryThreshold) {
                $expiringSecret = @{
                    "ServicePrincipalName" = $servicePrincipal.displayName
                    "SecretId" = $secret.keyId
                    "SecretDescription" = $secret.hint
                    "ExpiryDate" = $secret.endDateTime
                }

                $expiringSecrets += $expiringSecret
            }
        }
    }

    return $expiringSecrets
}



###### Execution Steps #########

$tenantId = ""
$SPClientId = ""
$SPClientSecret = ""
$groupid = ""


<#

#### Automation Account - Local Variables #######

If you are using an automation account, you can use this if you are storing the passwords. Remember to mask our

$tenantId = Get-AutomationVariable -Name "XYZ"
$SPClientId = Get-AutomationVariable -Name "XYZ"
$SPClientSecret = Get-AutomationVariable -Name "XYZ"
$groupid = Get-AutomationVariable -Name "XYZ"

#>


$logo = '

    ad8888888888ba
    dP`         `"8b,
    8  ,aaa,       "Y888a     ,aaaa,     ,aaa,  ,aa,
    8  8` `8           "88baadP""""YbaaadP"""YbdP""Yb
    8  8   8              """        """      ""    8b
    8  8, ,8         ,aaaaaaaaaaaaaaaaaaaaaaaaddddd88P
    8  `"""`       ,d8""
    Yb,         ,ad8"    @amoranio - Monitor Service Principal Secrets
    "Y8888888888P"


 '

 Write-Output $logo

Write-Output "[*] Getting AccessToken..." 
$accessToken = Get-AccessToken -tenantId $tenantId -SPClientId $SPClientId -SPClientSecret $SPClientSecret

$expiringSecrets = Get-ExpiringServicePrincipalSecrets -accessToken $accessToken -groupid $groupid

# Output the expiring secrets
Write-Output ""

if ($expiringSecrets){

    Write-Output "[!] Secrets Found To Be Expiring"
    $expiringSecrets | Format-Table

} else {

    Write-Output "[/] No Secrets Expring Within The Next 3 Months"
}

Write-Output ""

#### End
