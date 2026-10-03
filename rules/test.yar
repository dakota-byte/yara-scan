rule HelloWorld
{
    meta:
        description = "Matches the string 'hello' (case-insensitive)"
        author = "triage-scanner test"
    strings:
        $a = "hello" nocase
    condition:
        $a
}
