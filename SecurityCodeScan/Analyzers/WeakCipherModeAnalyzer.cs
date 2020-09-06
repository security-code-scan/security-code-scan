using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherModeAnalyzerCSharp : WeakCipherModeAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.IdentifierName);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakCipherModeAnalyzerVisualBasic : WeakCipherModeAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            if (!Debugger.IsAttached) // prefer single thread for debugging in development
                context.EnableConcurrentExecution();

            if (context.IsAuditMode())
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
            else
                context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);

            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.IdentifierName);
        }
    }

    public abstract class WeakCipherModeAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleGeneric = LocaleUtil.GetDescriptor("SCS0013");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleGeneric);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            var type = symbol.GetTypeName();
            switch (type)
            {
                case "System.Security.Cryptography.CipherMode.ECB":
                case "System.Security.Cryptography.CipherMode.CBC":
                case "System.Security.Cryptography.CipherMode.OFB":
                case "System.Security.Cryptography.CipherMode.CFB":
                case "System.Security.Cryptography.CipherMode.CTS":
                {
                    var diagnostic = Diagnostic.Create(RuleGeneric, ctx.Node.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
            }
        }
    }
}
