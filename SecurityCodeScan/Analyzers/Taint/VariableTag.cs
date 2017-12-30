using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityCodeScan.Analyzers.Taint
{
    public enum VariableTag
    {
		// HttpCookie
        HttpCookie,
        HttpCookieSecure,
        HttpCookieHttpOnly,

		// PasswordValidator
		PasswordValidator,
		RequiredLengthIsSet,
		RequireDigitIsSet,
		RequireLowercaseIsSet,
		RequireNonLetterOrDigitIsSet,
		RequireUppercaseIsSet,

	}
}
