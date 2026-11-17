// betterleaks v1.10.0's jwt-base64 rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.

rule Any_Secret_JwtBase64
{
    meta:
        description     = "Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information."
        author          = "betterleaks"
        reference       = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license         = "MIT"
        os              = "any"
        category        = "secret"
        family          = "JwtBase64"
        severity        = "high"
        score           = 80
        id              = "jwt-base64"
        confidence      = "high"
        keyword         = "zxlk"
        skip_entropy_le = "2.0"

    strings:
        $secret = /\bZXlK(?:(aGJHY2lPaU)|(aGNIVWlPaU)|(aGNIWWlPaU)|(aGRXUWlPaU)|(aU5qUWlP)|(amNtbDBJanBi)|(amRIa2lPaU)|(bGNHc2lPbn)|(bGJtTWlPaU)|(cWEzVWlPaU)|(cWQyc2lPb)|(cGMzTWlPaU)|(cGRpSTZJ)|(cmFXUWlP)|(clpYbGZiM0J6SWpwY)|(cmRIa2lPaUp)|(dWIyNWpaU0k2)|(d01tTWlP)|(d01uTWlPaU)|(d2NIUWlPaU)|(emRXSWlPaU)|(emRuUWlP)|(MFlXY2lPaU)|(MGVYQWlPaUp)|(MWNtd2l)|(MWMyVWlPaUp)|(MlpYSWlPaU)|(MlpYSnphVzl1SWpv)|(NElqb2)|(NE5XTWlP)|(NE5YUWlPaU)|(NE5YUWpVekkxTmlJNkl)|(NE5YVWlPaU)|(NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}/  // gitleaks:allow

    condition:
        $secret
}
