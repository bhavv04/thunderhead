# ─── Thunderhead attack simulator ─────────────────────────────────────────────
# Simulates aggressive bot traffic designed to trigger tarpit and block.
# Usage: .\scripts\simulate-attack.ps1

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
    Label = "Python scraper -high rate + robots violation"
    Paths = @("/admin", "/robots.txt", "/api/users", "/api/orders", "/api/products",
              "/api/admin/users", "/api/keys", "/api/tokens", "/api/passwords", "/api/secrets")
    Count = 40
  },
  @{
    IP    = "198.51.100.7"
    UA    = "scrapy/2.7.0"
    Label = "Scrapy -sequential crawl + no headers"
    Paths = @("/about", "/blog", "/careers", "/contact", "/docs",
              "/faq", "/home", "/legal", "/pricing", "/team")
    Count = 35
  },
  @{
    IP    = "45.33.32.156"
    UA    = ""
    Label = "Headless client -no UA, no Accept, no Accept-Language"
    Paths = @("/", "/api/users", "/api/data", "/export", "/dump")
    Count = 38
  },
  @{
    IP    = "185.220.101.5"
    UA    = "curl/7.68.0"
    Label = "curl -robots + high rate"
    Paths = @("/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup")
    Count = 42
  }
)

foreach ($attacker in $attackers) {
  Write-Host "  attacking as $($attacker.IP)" -ForegroundColor Red
  Write-Host "  $($attacker.Label)" -ForegroundColor DarkGray

  for ($i = 0; $i -lt $attacker.Count; $i++) {
    $path = $attacker.Paths[$i % $attacker.Paths.Count]
    try {
      $headers = @{ "X-Forwarded-For" = $attacker.IP }
      if ($attacker.UA -ne "") {
        $headers["User-Agent"] = $attacker.UA
      }
      Invoke-WebRequest `
        -Uri "$ProxyUrl$path" `
        -Headers $headers `
        -UseBasicParsing `
        -TimeoutSec 15 `
        -ErrorAction SilentlyContinue | Out-Null
    } catch {
      # tarpitted requests will timeout -that's expected
    }
  }

  Write-Host "  done -$($attacker.Count) requests sent" -ForegroundColor DarkGray
  Write-Host ""
}

Write-Host "  check your dashboard at http://localhost:3000" -ForegroundColor White
Write-Host "  you should see tarpit and block actions on the clients page" -ForegroundColor DarkGray
Write-Host ""