namespace SecurityCodeScan.Analyzers.Taint
{
    public enum Tag
    {
        // HttpCookie
        HttpCookieSecure,
        HttpCookieHttpOnly,

        // PasswordValidator
        RequiredLengthIsSet,
        RequireDigitIsSet,
        RequireLowercaseIsSet,
        RequireNonLetterOrDigitIsSet,
        RequireUppercaseIsSet,
        RequiredLenghtIsTooShort
    }
}
