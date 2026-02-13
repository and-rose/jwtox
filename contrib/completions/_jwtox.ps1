
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'jwtox' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'jwtox'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'jwtox' {
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'The key to use for signature verification')
            [CompletionResult]::new('--key-file', '--key-file', [CompletionResultType]::ParameterName, 'The key to use for signature verification')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Do not calculate the dates for iat, exp, and nbf')
            [CompletionResult]::new('--no-calc', '--no-calc', [CompletionResultType]::ParameterName, 'Do not calculate the dates for iat, exp, and nbf')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'No color output')
            [CompletionResult]::new('--no-color', '--no-color', [CompletionResultType]::ParameterName, 'No color output')
            [CompletionResult]::new('-H', '-H ', [CompletionResultType]::ParameterName, 'Only print the header as JSON')
            [CompletionResult]::new('--header-only', '--header-only', [CompletionResultType]::ParameterName, 'Only print the header as JSON')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Only print the payload as JSON')
            [CompletionResult]::new('--payload-only', '--payload-only', [CompletionResultType]::ParameterName, 'Only print the payload as JSON')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print dates in UTC instead of local time')
            [CompletionResult]::new('--utc', '--utc', [CompletionResultType]::ParameterName, 'Print dates in UTC instead of local time')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint')
            [CompletionResult]::new('--verify-jwks', '--verify-jwks', [CompletionResultType]::ParameterName, 'Verify the signature by reaching out to the authority specified in the "iss" claim using the JWKs endpoint')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
