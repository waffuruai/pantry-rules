// betterleaks v1.10.0's sidekiq-sensitive-url rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SidekiqSensitiveUrl
{
    meta:
        description = "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SidekiqSensitiveUrl"
        severity    = "high"
        score       = 80
        id          = "sidekiq-sensitive-url"
        confidence  = "high"
        keyword     = "gems.contribsys.com"
        keyword     = "enterprise.contribsys.com"

    strings:
        $secret = /\b[hH][tT][tT][pP][sS]?:\/\/([A-Fa-f0-9]{8}:[A-Fa-f0-9]{8})@(?:[gG][eE][mM][sS].[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS].[cC][oO][mM]|[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE].[cC][oO][nN][tT][rR][iI][bB][sS][yY][sS].[cC][oO][mM])(?:[\/|\#|\?|:]|$)/  // gitleaks:allow

    condition:
        $secret
}
