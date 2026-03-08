
use builtin;
use str;

set edit:completion:arg-completer[jwtox] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'jwtox'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'jwtox'= {
            cand -f 'Extract a single, top-level claim from the payload'
            cand --field 'Extract a single, top-level claim from the payload'
            cand -k 'The key to use for signature verification'
            cand --key-file 'The key to use for signature verification'
            cand -c 'Do not calculate the dates for iat, exp, and nbf'
            cand --no-calc 'Do not calculate the dates for iat, exp, and nbf'
            cand -n 'No color output'
            cand --no-color 'No color output'
            cand -H 'Only print the header as JSON'
            cand --header-only 'Only print the header as JSON'
            cand -P 'Only print the payload as JSON'
            cand --payload-only 'Only print the payload as JSON'
            cand -p 'pretty print the output instead of compact JSON (only applies when printing header and/or payload)'
            cand --pretty 'pretty print the output instead of compact JSON (only applies when printing header and/or payload)'
            cand -S 'Only print the signature as a base64 string'
            cand --signature-only 'Only print the signature as a base64 string'
            cand -u 'Print dates in UTC instead of local time'
            cand --utc 'Print dates in UTC instead of local time'
            cand -v 'Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint'
            cand --verify-jwks 'Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint'
            cand -C 'C'
            cand --no-cache 'no-cache'
            cand -X 'X'
            cand --clear-cache 'clear-cache'
            cand -h 'Print help'
            cand --help 'Print help'
            cand -V 'Print version'
            cand --version 'Print version'
        }
    ]
    $completions[$command]
}
