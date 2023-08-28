function Get-GoogleAuthTokens {
    $scopes = "https://www.googleapis.com/auth/photoslibrary.readonly"
    
    Start-Process "https://accounts.google.com/o/oauth2/v2/auth?client_id=$clientId&scope=$([string]::Join("%20", $scopes))&access_type=offline&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob"
    $code = Read-Host "Enter code here"
    $response = Invoke-WebRequest $authRequestUri -ContentType application/x-www-form-urlencoded -Method POST -Body "client_id=$clientId&client_secret=$clientSecret&redirect_uri=urn:ietf:wg:oauth:2.0:oob&code=$code&grant_type=authorization_code"
    $accessToken = ($response.Content | ConvertFrom-Json).access_token 
    $refreshToken = ($response.Content | ConvertFrom-Json).refresh_token
    Set-Content $rootFolder"\refreshToken.txt" $refreshToken
    Set-Content $rootFolder"\accessToken.txt" $accessToken
}

function Reset-GoogleAccessToken {
    $refreshTokenParams = @{
        client_id=$clientId;
        client_secret=$clientSecret;
        refresh_token=(Get-Content "$rootFolder\refreshToken.txt");
        grant_type="refresh_token"; # Fixed value
      }
      
      $tokens = Invoke-RestMethod -Uri $authRequestUri -Method POST -Body $refreshTokenParams

      Set-Content "$rootFolder\accessToken.txt" $tokens.access_token
}

function Get-AllItemsObject {
    $photosUri = "/mediaItems"
    $PhotosRequestUri = "$APIUri$PhotosUri"
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    $body = @{
        "pageSize" = "100"
    }
    $answer = Invoke-RestMethod -Headers $headers -Uri $PhotosRequestUri -Body $body -Method GET -ContentType 'application/json'

    $itemsList = @()
    foreach ($item in $answer.mediaItems) {
        $itemsList += $item
    }
    
    while ($answer.nextPageToken) {
        Reset-GoogleAccessToken
        $body = @{
            "pageSize" = "100"
            "pageToken" = $answer.nextPageToken
        }
        $answer = Invoke-RestMethod -Headers $headers -Uri $PhotosRequestUri -Body $body -Method GET -ContentType 'application/json'
        $itemsList += $answer.mediaItems
    }
    $itemsList
}

$rootFolder = $PSScriptRoot
$clientId = "4732530628-c4nhevedm7hg5vk8lad3js6vbvip0m1a.apps.googleusercontent.com"
$clientSecret = "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"
$authRequestUri = "https://www.googleapis.com/oauth2/v4/token"

$accessToken= Get-Content $rootFolder"\accessToken.txt"
$APIUri = "https://photoslibrary.googleapis.com/v1"

Get-GoogleAuthTokens

Write-Host "Gathering files list and information from Google Photos..."
$allItems = Get-AllItemsObject

$destinationFolderRoot = "H:\Photos-Video\From Google\"
$date = Get-Date -Format dd-MM-yyyy
$destinationFolder = "$destinationFolderRoot"+"Backup-of-$date"

if (!(Test-Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder
}

Write-Host "Backing up to H drive..."
if ($PSVersionTable.PSVersion -like "7.*") {

    $StartTime = $(get-date)

    $allItems | ForEach-Object -Parallel {
        $ProgressPreference = "SilentlyContinue"
        $destinationFolderRoot = "H:\Photos-Video\From Google\"
        $date = Get-Date -Format dd-MM-yyyy
        $destinationFolder = "$destinationFolderRoot"+"Backup-of-$date"
        $outFile = "$destinationFolder"+"\"+$_.filename
        if ($_.mimeType -like "image*") {
            $uri = $_.baseUrl+"=d"
        }
        elseif ($_.mimeType -like "video*") {
            $uri = $_.baseUrl+"=dv"
        }
        Invoke-WebRequest -Uri $uri -OutFile $outFile
    }
    $(get-date)-$StartTime
}

elseif ($PSVersionTable.PSVersion -like "5.*") {
    $StartTime = $(get-date)

    Write-Host "This script is a lot faster with Powershell 7. Consider using that instead."
    foreach ($item in $allItems) {
        $ProgressPreference = "SilentlyContinue"
        $outFile = "$destinationFolder"+"\"+$item.filename
        if ($item.mimeType -like "image*") {
            $uri = $item.baseUrl+"=d"
        }
        elseif ($item.mimeType -like "video*") {
            $uri = $item.baseUrl+"=dv"
        }
        Invoke-WebRequest -Uri $uri -OutFile $outFile
    }
    $ProgressPreference = "Continue"

    $(get-date)-$StartTime
}

Get-ChildItem -Path $rootFolder | Where-Object -Property Name -like "*.txt" | Remove-Item

#### Delete all from Google. Must be done manually, as of 08-28-2023, there is no way to use Google's APIs to delete items from Photos.

### Later: Find way to preserve metadata