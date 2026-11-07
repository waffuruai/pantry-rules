// betterleaks v1.10.0's cursor-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CursorApiKey
{
    meta:
        description     = "Detected a Cursor Integrations API Key, which may expose AI-assisted development services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CursorApiKey"
        severity        = "medium"
        score           = 50
        id              = "cursor-api-key"
        confidence      = "medium"
        keyword         = "cursor"
        skip_entropy_le = "3.5"

    strings:
        $secret = /(?:[cC][uU][rR][sS][oO][rR])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([kK][eE][yY]_[A-F0-9a-f]{64})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
