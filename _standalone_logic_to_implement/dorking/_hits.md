## [help]
0. `command for opening everything in a file at once`
      # for one file
   1. xargs -d '\n' -a wolt_github_dork_links.txt -I {} xdg-open "{}"
      # for the first `n` files in folder -- `head -n 10` means 10 files for example
   2. ls | head -n 10 | xargs -I {} sh -c 'cat "{}" | xargs -I % xdg-open "%"' 
      

## [shodan]

## [github]

## [wayback]

## [google]
