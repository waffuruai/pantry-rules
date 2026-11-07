// betterleaks v1.10.0's figma-personal-access-header-token rule (MIT: see NOTICE), translated by tools/betterleaks.py.
// Don't edit it: change the translator and run `mise run gen`, or write a rule of our own.
// betterleaks can check this secret with its provider; Pantry doesn't (https://github.com/waffuruai/pantry/issues/190).

rule Any_Secret_FigmaPersonalAccessHeaderToken
{
    meta:
        description = "Uncovered a Figma Personal Access Token in a header, which may compromise design assets and team collaboration."
        author      = "betterleaks"
        reference   = "https://github.com/betterleaks/betterleaks/blob/v1.10.0/config/betterleaks.toml"
        license     = "MIT"
        os          = "any"
        category    = "secret"
        family      = "FigmaPersonalAccessHeaderToken"
        severity    = "high"
        score       = 80
        id          = "figma-personal-access-header-token"
        confidence  = "high"
        keyword     = "x-figma-token"
        keyword     = "xfigmatoken"
        keyword     = "x_figma_token"

    strings:
        $secret = /(?:[xX]-[fF][iI][gG][mM][aA]-[tT][oO][kK][eE][nN]|[xX][fF][iI][gG][mM][aA][tT][oO][kK][eE][nN]|[xX]_[fF][iI][gG][mM][aA]_[tT][oO][kK][eE][nN])(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9A-F]{4}-[a-f0-9A-F]{8}(?:-[a-f0-9A-F]{4}){3}-[a-f0-9A-F]{12})(?:\\?['"\x60]|[\s;]|\\[NRnr]|$)/  // gitleaks:allow

    condition:
        $secret
}
