// betterleaks v1.10.0's minimax-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_MinimaxApiKey
{
    meta:
        description     = "Detected a MiniMax API key, which may expose AI model, speech, image, video, or file services to unauthorized access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "MinimaxApiKey"
        severity        = "high"
        score           = 80
        id              = "minimax-api-key"
        confidence      = "high"
        keyword         = "sk-api-"
        keyword         = "minimax"
        skip_entropy_le = "3.5"

    strings:
        $secret = /\b([sS][kK]-[aA][pP][iI]-[a-zA-ZA-Za-z0-9_-]{119})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
