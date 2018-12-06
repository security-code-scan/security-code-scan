using System.Collections.Immutable;
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
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.IdentifierName);
        }
    }

    [DiagnosticAnalyzer(LanguageNames.VisualBasic)]
    public class WeakCipherModeAnalyzerVisualBasic : WeakCipherModeAnalyzer
    {
        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.IdentifierName);
        }
    }

    public abstract class WeakCipherModeAnalyzer : DiagnosticAnalyzer
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
