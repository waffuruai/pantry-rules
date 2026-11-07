// betterleaks v1.10.0's jwt rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_Jwt
{
    meta:
        description     = "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "Jwt"
        severity        = "high"
        score           = 80
        id              = "jwt"
        confidence      = "high"
        keyword         = "eyj"
        skip_entropy_le = "3.0"

    strings:
        $secret = /\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:\\?['"\x60]|[\s;]|\\[nr]|$)/  // gitleaks:allow

    condition:
        $secret
}
