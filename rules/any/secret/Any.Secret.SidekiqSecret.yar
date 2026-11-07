// betterleaks v1.10.0's sidekiq-secret rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_SidekiqSecret
{
    meta:
        description = "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "SidekiqSecret"
        severity    = "high"
        score       = 80
        id          = "sidekiq-secret"
        confidence  = "high"
        keyword     = "bundle_enterprise__contribsys__com"
        keyword     = "bundle_gems__contribsys__com"

    strings:
        $secret = /(?:[Bb][Uu][Nn][Dd][Ll][Ee]_[Ee][Nn][Tt][Ee][Rr][Pp][Rr][Ii][Ss][Ee]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm]|[Bb][Uu][Nn][Dd][Ll][Ee]_[Gg][Ee][Mm][Ss]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([A-Fa-f0-9]{8}:[A-Fa-f0-9]{8})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
