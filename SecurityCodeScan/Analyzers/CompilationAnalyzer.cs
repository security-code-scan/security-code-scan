using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class CompilationAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "SCS0000";

        public static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor(DiagnosticId);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationAction(OnCompilationAction);
        }

        private void OnCompilationAction(CompilationAnalysisContext ctx)
        {
            ctx.ReportDiagnostic(Diagnostic.Create(Rule, Location.None));
        }
    }
}
