// betterleaks v1.10.0's upstash-redis-rest-url.1 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

private rule Any_Secret_UpstashRedisRestUrl1
{
    meta:
        description = "Upstash Redis REST URL, used as a component of the Upstash REST-token composite rule."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "UpstashRedisRestUrl1"
        severity    = "high"
        score       = 80
        id          = "upstash-redis-rest-url.1"
        confidence  = "high"
        keyword     = "upstash.io"

    strings:
        $secret = /\b([hH][tT][tT][pP][sS]:\/\/[A-Za-z0-9][A-Za-z0-9-]{2,63}\.[uU][pP][sS][tT][aA][sS][hH]\.[iI][oO])(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
