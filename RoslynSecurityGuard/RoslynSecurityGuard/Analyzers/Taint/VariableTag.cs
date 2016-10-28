using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public enum VariableTag
    {
        HttpCookie,
        HttpCookieSecure,
        HttpCookieHttpOnly,

    }
}
