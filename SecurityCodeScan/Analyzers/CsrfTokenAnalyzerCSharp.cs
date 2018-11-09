using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class MvcCsrfTokenAnalyzerCSharp : MvcCsrfTokenAnalyzer
    {
    }

    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CoreCsrfTokenAnalyzerCSharp : CoreCsrfTokenAnalyzer
    {
    }
}
