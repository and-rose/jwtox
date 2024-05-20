complete -c jwtox -s k -l key -d 'The key to use for signature verification' -r
complete -c jwtox -s c -l no-calc -d 'Do not calculate the dates for iat, exp, and nbf'
complete -c jwtox -s n -l no-color -d 'No color output'
complete -c jwtox -s H -l header-only -d 'Only print the header as JSON'
complete -c jwtox -s p -l payload-only -d 'Only print the payload as JSON'
complete -c jwtox -s u -l utc -d 'Print dates in UTC instead of local time'
complete -c jwtox -s h -l help -d 'Print help'
complete -c jwtox -s V -l version -d 'Print version'
