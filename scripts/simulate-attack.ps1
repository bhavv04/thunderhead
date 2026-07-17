# ─── Thunderhead attack simulator (fast) ──────────────────────────────────────
param(
  [string]$ProxyUrl = "http://localhost:8080"
)

Write-Host ""
Write-Host "  thunderhead attack simulator" -ForegroundColor Red
Write-Host "  target: $ProxyUrl" -ForegroundColor DarkGray
Write-Host ""

$attackers = @(
  @{
    IP    = "203.0.113.42"
    UA    = "python-requests/2.28.0"
    Label = "Python scraper - high rate + robots violation"
    Paths = @("/admin", "/robots.txt", "/api/users", "/api/orders",
              "/api/admin/users", "/api/keys", "/api/tokens", "/api/secrets")
    Count = 50
  },
  @{
    IP    = "198.51.100.7"
    UA    = "scrapy/2.7.0"
    Label = "Scrapy - sequential crawl"
    Paths = @("/about", "/blog", "/careers", "/contact", "/docs",
              "/faq", "/home", "/legal", "/pricing", "/team")
    Count = 45
  },
  @{
    IP    = "45.33.32.156"
    UA    = ""
    Label = "Headless - no headers at all"
    Paths = @("/", "/api/users", "/api/data", "/export", "/dump")
    Count = 50
  },
  @{
    IP    = "185.220.101.5"
    UA    = "curl/7.68.0"
    Label = "curl - robots + high rate"
    Paths = @("/admin", "/wp-admin", "/.env", "/config", "/backup",
              "/admin/users", "/admin/config", "/admin/logs")
    Count = 50
  }
)

foreach ($attacker in $attackers) {
  Write-Host "  attacking as $($attacker.IP)" -ForegroundColor Red
  Write-Host "  $($attacker.Label)" -ForegroundColor DarkGray

  $jobs = @()
  for ($i = 0; $i -lt $attacker.Count; $i++) {
    $path    = $attacker.Paths[$i % $attacker.Paths.Count]
    $ip      = $attacker.IP
    $ua      = $attacker.UA
    $url     = "$ProxyUrl$path"

    $jobs += Start-Job -ScriptBlock {
      param($url, $ip, $ua)
      try {
        $headers = @{ "X-Forwarded-For" = $ip }
        if ($ua -ne "") { $headers["User-Agent"] = $ua }
        Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
      } catch {}
    } -ArgumentList $url, $ip, $ua
  }

  # wait for all jobs to finish
  $jobs | Wait-Job | Out-Null
  $jobs | Remove-Job

  Write-Host "  done - $($attacker.Count) requests sent" -ForegroundColor DarkGray
  Write-Host ""
}

Write-Host "  done. check your dashboard at http://localhost:3000" -ForegroundColor White
Write-Host ""