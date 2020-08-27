using System.Text;
using System.Text.RegularExpressions;

namespace SecurityCodeScan.Test.Helpers
{
    internal static class CsToVbConverter
    {
        public static string CSharpReplaceToVBasic(this string cs)
        {
            var vbString = cs;
            vbString = Regex.Replace(vbString, @"default\(([^\)]*)\)",                  "DirectCast(Nothing, $1)");
            vbString = Regex.Replace(vbString, @"\(([^\s\)""]+)\)(?!\.)([^,;\n\s\)]+)", "DirectCast($2, $1)");
            vbString = Regex.Replace(vbString, @"\bnew\s*\[\s*\]\s*({.*?})",            "$1");
            vbString = Regex.Replace(vbString, @"({(\s*[^\s]*))\s*=",                   "With {.$2 =");
            vbString = Regex.Replace(vbString, @"(<(\s*[^>]*\s*)>)",                    "(Of $2)");

            var vb = new StringBuilder(vbString);
            vb.Replace("null", "Nothing");
            vb.Replace(";", "\r\n");
            vb.Replace("new ", "New ");
            vb.Replace("var ", "Dim ");
            vb.Replace("typeof", "GetType");
            vb.Replace("'", "\"");
            vb.Replace("this.", "Me.");
            vb.Replace("static ", "Shared ");
            vb.Replace("using ", "Imports ");
            vb.Replace("out ", "");
            vb.Replace("ref ", "");
            vb.Replace("[", "(");
            vb.Replace("]", ")");
            vb.Replace("&&", "AndAlso");
            vb.Replace("!=", "IsNot");

            vb.Replace("public ",   "Public ");
            vb.Replace("internal ", "Friend ");

            vbString = vb.ToString();
            return vbString;
        }
    }
}
