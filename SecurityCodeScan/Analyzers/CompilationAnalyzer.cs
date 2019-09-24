using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Analyzers
{
    internal class CompilationAnalyzer
    {
        public const string DiagnosticId = "SCS0000";

        public static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public void OnCompilationAction(CompilationAnalysisContext ctx)
        {
            ctx.ReportDiagnostic(Diagnostic.Create(Rule, Location.None));
        }
    }
}
