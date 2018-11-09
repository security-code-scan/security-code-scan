using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class MvcCsrfTokenAnalyzerVBasic : MvcCsrfTokenAnalyzer
    {
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class CoreCsrfTokenAnalyzerVBasic : CoreCsrfTokenAnalyzer
    {
    }
}
