using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakCipherModeAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleCBC     = LocaleUtil.GetDescriptor("SCS0011");
        private static readonly DiagnosticDescriptor RuleECB     = LocaleUtil.GetDescriptor("SCS0012");
        private static readonly DiagnosticDescriptor RuleGeneric = LocaleUtil.GetDescriptor("SCS0013");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleECB,
                                                                                                           RuleCBC,
                                                                                                           RuleGeneric);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.SimpleMemberAccessExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node, expression;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node       = ctx.Node as CSharpSyntax.MemberAccessExpressionSyntax;
                expression = ((CSharpSyntax.MemberAccessExpressionSyntax)node)?.Expression;
            }
            else
            {
                node       = ctx.Node as VBSyntax.MemberAccessExpressionSyntax;
                expression = ((VBSyntax.MemberAccessExpressionSyntax)node)?.Expression;
            }

            if (node == null)
                return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            //DES.Create()
            if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "ECB"))
            {
                var diagnostic = Diagnostic.Create(RuleECB, expression.GetLocation(), "ECB");
                ctx.ReportDiagnostic(diagnostic);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CBC"))
            {
                var diagnostic = Diagnostic.Create(RuleCBC, expression.GetLocation(), "CBC");
                ctx.ReportDiagnostic(diagnostic);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "OFB") ||
                     AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CFB") ||
                     AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CTS"))
            {
                var diagnostic = Diagnostic.Create(RuleGeneric, expression.GetLocation(), "OFB");
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
