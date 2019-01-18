using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Config;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using VB = Microsoft.CodeAnalysis.VisualBasic;

namespace SecurityCodeScan.Analyzers
{
    [SecurityAnalyzer(LanguageNames.CSharp)]
    internal class WeakCipherModeAnalyzerCSharp : WeakCipherModeAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.IdentifierName);
        }
    }

    [SecurityAnalyzer(LanguageNames.VisualBasic)]
    internal class WeakCipherModeAnalyzerVisualBasic : WeakCipherModeAnalyzer
    {
        public override void Initialize(ISecurityAnalysisContext context)
        {
            context.RegisterCompilationStartAction(OnCompilationStartAction);
        }

        private void OnCompilationStartAction(CompilationStartAnalysisContext context, Configuration config)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.IdentifierName);
        }
    }

    internal abstract class WeakCipherModeAnalyzer : SecurityAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleCBC     = LocaleUtil.GetDescriptor("SCS0011");
        private static readonly DiagnosticDescriptor RuleECB     = LocaleUtil.GetDescriptor("SCS0012");
        private static readonly DiagnosticDescriptor RuleGeneric = LocaleUtil.GetDescriptor("SCS0013");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(RuleECB,
                                                                                                           RuleCBC,
                                                                                                           RuleGeneric);

        protected static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            var type = symbol.GetTypeName();
            switch (type)
            {
                case "System.Security.Cryptography.CipherMode.ECB":
                {
                    var diagnostic = Diagnostic.Create(RuleECB, ctx.Node.GetLocation(), "ECB");
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
                case "System.Security.Cryptography.CipherMode.CBC":
                {
                    var diagnostic = Diagnostic.Create(RuleCBC, ctx.Node.GetLocation(), "CBC");
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
                case "System.Security.Cryptography.CipherMode.OFB":
                case "System.Security.Cryptography.CipherMode.CFB":
                case "System.Security.Cryptography.CipherMode.CTS":
                {
                    var diagnostic = Diagnostic.Create(RuleGeneric, ctx.Node.GetLocation(), "OFB");
                    ctx.ReportDiagnostic(diagnostic);
                    break;
                }
            }
        }
    }
}
