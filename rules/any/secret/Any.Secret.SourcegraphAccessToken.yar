// betterleaks v1.10.0's sourcegraph-access-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_SourcegraphAccessToken
{
    meta:
        description     = "Sourcegraph is a code search and navigation engine."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "SourcegraphAccessToken"
        severity        = "high"
        score           = 80
        id              = "sourcegraph-access-token"
        confidence      = "high"
        keyword         = "sgp_"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b([sS][gG][pP]_(?:[A-Fa-fa-fA-F0-9]{16}|[lL][oO][cC][aA][lL])_[A-Fa-fa-fA-F0-9]{40}|[sS][gG][pP]_[A-Fa-fa-fA-F0-9]{40})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
