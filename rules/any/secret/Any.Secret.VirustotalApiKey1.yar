// betterleaks v1.10.0's virustotal-api-key.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_VirustotalApiKey1
{
    meta:
        description     = "VirusTotal API key, which may expose private submissions, intelligence, or account API access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "VirustotalApiKey1"
        severity        = "high"
        score           = 80
        id              = "virustotal-api-key.1"
        confidence      = "high"
        keyword         = "virustotal"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:[vV][iI][rR][uU][sS][tT][oO][tT][aA][lL])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
