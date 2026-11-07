// betterleaks v1.10.0's upstash-redis-rest-token.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_UpstashRedisRestToken1
{
    meta:
        description       = "Upstash Redis REST token, which may grant read-only or full access to an Upstash database."
        author            = "betterleaks"
        reference         = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license           = "MIT"
        os                = "any"
        category          = "secret"
        family            = "UpstashRedisRestToken1"
        severity          = "high"
        score             = 80
        id                = "upstash-redis-rest-token.1"
        confidence        = "high"
        keyword           = "upstash"
        component1        = "upstash-redis-rest-url.1"
        component1_within = "5L"
        skip_entropy_lt   = "3.5"

    strings:
        $secret = /(?:(?:[uU][pP][sS][tT][aA][sS][hH])(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:[A-Za-z0-9]{32,48}|AYNgAS[A-Za-z0-9+\/_-]{26,90}={0,2}))(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
