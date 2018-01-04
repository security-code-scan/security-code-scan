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
    public class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0010");

        private static readonly ImmutableArray<string> BadCiphers = ImmutableArray.Create("DES", "RC2");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode,
                                             CSharp.SyntaxKind.InvocationExpression,
                                             CSharp.SyntaxKind.ObjectCreationExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode,
                                             VB.SyntaxKind.InvocationExpression,
                                             VB.SyntaxKind.ObjectCreationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node, node2, expression;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node       = ctx.Node as CSharpSyntax.InvocationExpressionSyntax;
                expression = ((CSharpSyntax.InvocationExpressionSyntax)node)?.Expression;
                node2      = ctx.Node as CSharpSyntax.ObjectCreationExpressionSyntax;
            }
            else
            {
                node       = ctx.Node as VBSyntax.InvocationExpressionSyntax;
                expression = ((VBSyntax.InvocationExpressionSyntax)node)?.Expression;
                node2      = ctx.Node as VBSyntax.ObjectCreationExpressionSyntax;
            }

            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (!AnalyzerUtil.SymbolMatch(symbol, type: cipher, name: "Create"))
                        continue;

                    var diagnostic = Diagnostic.Create(Rule, expression.GetLocation(), cipher);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }

            if (node2 != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node2).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (!AnalyzerUtil.SymbolMatch(symbol, type: cipher + "CryptoServiceProvider"))
                        continue;

                    var diagnostic = Diagnostic.Create(Rule, node2.GetLocation(), cipher);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
