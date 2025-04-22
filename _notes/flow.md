# starting tips
## [xss]
- basic payload: ` <u>test123</u> ` 
- urlencoded:    ` %3Cu%3E%3Ch3%3Etest123%3C%2Fh3%3E%3C%2Fu%3E `
## [postman/newman]
- change header value: `newman run wolt_all_deduped.json -r cli,html --reporter-html-export report.html --env-var "authorization=abc123xyz"`
- generate report additionally: `-r cli,html`

# starting point
## `credentials`
- base: alejandro501@proton.me / my normal password
