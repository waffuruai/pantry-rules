// betterleaks v1.10.0's notion-api-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_NotionApiToken
{
    meta:
        description     = "Notion API token"
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "NotionApiToken"
        severity        = "high"
        score           = 80
        id              = "notion-api-token"
        confidence      = "high"
        keyword         = "ntn_"
        skip_entropy_le = "4.0"

    strings:
        $secret = /\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
