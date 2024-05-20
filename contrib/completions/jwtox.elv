
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
            cand -k 'The key to use for signature verification'
            cand --key 'The key to use for signature verification'
            cand -c 'Do not calculate the dates for iat, exp, and nbf'
            cand --no-calc 'Do not calculate the dates for iat, exp, and nbf'
            cand -n 'No color output'
            cand --no-color 'No color output'
            cand -H 'Only print the header as JSON'
            cand --header-only 'Only print the header as JSON'
            cand -p 'Only print the payload as JSON'
            cand --payload-only 'Only print the payload as JSON'
            cand -u 'Print dates in UTC instead of local time'
            cand --utc 'Print dates in UTC instead of local time'
            cand -h 'Print help'
            cand --help 'Print help'
            cand -V 'Print version'
            cand --version 'Print version'
        }
    ]
    $completions[$command]
}
