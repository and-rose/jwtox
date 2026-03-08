complete -c jwtox -s f -l field -d 'Extract a single, top-level claim from the payload' -r
complete -c jwtox -s k -l key-file -d 'The key to use for signature verification' -r
complete -c jwtox -s c -l no-calc -d 'Do not calculate the dates for iat, exp, and nbf'
complete -c jwtox -s n -l no-color -d 'No color output'
complete -c jwtox -s H -l header-only -d 'Only print the header as JSON'
complete -c jwtox -s P -l payload-only -d 'Only print the payload as JSON'
complete -c jwtox -s p -l pretty -d 'pretty print the output instead of compact JSON (only applies when printing header and/or payload)'
complete -c jwtox -s S -l signature-only -d 'Only print the signature as a base64 string'
complete -c jwtox -s u -l utc -d 'Print dates in UTC instead of local time'
complete -c jwtox -s v -l verify-jwks -d 'Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint'
complete -c jwtox -s C -l no-cache
complete -c jwtox -s X -l clear-cache
complete -c jwtox -s h -l help -d 'Print help'
complete -c jwtox -s V -l version -d 'Print version'
