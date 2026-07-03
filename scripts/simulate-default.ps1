# ─── Thunderhead traffic simulator ────────────────────────────────────────────
# Usage: .\scripts\simulate.ps1
# Simulates realistic mixed traffic through the proxy to populate the dashboard.

param(
  [string]$ProxyUrl = "http://localhost:8080",
  [int]$Rounds = 3
)

$clients = @(
  @{
    IP = "203.0.113.42"
    UA = "python-requests/2.28.0"
    Paths = @("/api/users", "/api/orders", "/api/products", "/api/admin/users", "/admin", "/robots.txt")
    Delay = 50
    Label = "Python scraper (high risk)"
  },
  @{
    IP = "198.51.100.7"
    UA = "scrapy/2.7.0"
    Paths = @("/about", "/blog", "/contact", "/docs", "/faq", "/pricing", "/team", "/careers")
    Delay = 80
    Label = "Scrapy bot (sequential crawl)"
  },
  @{
    IP = "192.168.1.101"
    UA = "curl/7.68.0"
    Paths = @("/api/search", "/api/login", "/api/checkout")
    Delay = 200
    Label = "curl client (suspicious)"
  },
  @{
    IP = "10.0.0.55"
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
    Paths = @("/", "/about", "/pricing")
    Delay = 500
    Label = "Legit browser (low risk)"
  },
  @{
    IP = "172.16.0.12"
    UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    Paths = @("/", "/blog", "/contact")
    Delay = 600
    Label = "Legit browser (low risk)"
  },
  @{
    IP = "203.0.113.99"
    UA = "Googlebot/2.1 (+http://www.google.com/bot.html)"
    Paths = @("/", "/sitemap.xml", "/robots.txt")
    Delay = 300
    Label = "Googlebot (allowlisted)"
  }
)

Write-Host ""
Write-Host "  thunderhead traffic simulator" -ForegroundColor White
Write-Host "  target: $ProxyUrl" -ForegroundColor DarkGray
Write-Host "  rounds: $Rounds" -ForegroundColor DarkGray
Write-Host ""

for ($round = 1; $round -le $Rounds; $round++) {
  Write-Host "  round $round / $Rounds" -ForegroundColor DarkGray

  foreach ($client in $clients) {
    Write-Host "    $($client.Label) [$($client.IP)]" -ForegroundColor DarkGray

    $count = Get-Random -Minimum 3 -Maximum 15
    for ($i = 0; $i -lt $count; $i++) {
      $path = $client.Paths | Get-Random
      try {
        $headers = @{
          "User-Agent"       = $client.UA
          "X-Forwarded-For"  = $client.IP
        }

        # add browser headers for legit clients
        if ($client.UA -like "*Mozilla*") {
          $headers["Accept"]          = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
          $headers["Accept-Language"] = "en-US,en;q=0.9"
        }

        Invoke-WebRequest `
          -Uri "$ProxyUrl$path" `
          -Headers $headers `
          -UseBasicParsing `
          -TimeoutSec 10 `
          -ErrorAction SilentlyContinue | Out-Null

      } catch {
        # upstream might be down, that's fine
      }
      Start-Sleep -Milliseconds $client.Delay
    }
  }

  if ($round -lt $Rounds) {
    Write-Host "  sleeping 2s before next round..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
  }
}

Write-Host ""
Write-Host "  done. check your dashboard at http://localhost:3000" -ForegroundColor White
Write-Host ""