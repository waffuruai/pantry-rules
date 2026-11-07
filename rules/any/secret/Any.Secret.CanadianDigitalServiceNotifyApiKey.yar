// betterleaks v1.10.0's canadian-digital-service-notify-api-key rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_CanadianDigitalServiceNotifyApiKey
{
    meta:
        description     = "Detected a GC Notify API key, which may allow unauthorized notification access."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "CanadianDigitalServiceNotifyApiKey"
        severity        = "high"
        score           = 80
        id              = "canadian-digital-service-notify-api-key"
        confidence      = "high"
        keyword         = "gcntfy-"
        skip_entropy_lt = "3.5"

    strings:
        $secret = /(?:\b([Aa][pP][iI][Kk][eE][yY]-[vV]1\s+[gG][cC][nN][tT][fF][yY]-[A-Za-z0-9_]+-[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12}-[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12})\b)/  // gitleaks:allow

    condition:
        $secret
}
