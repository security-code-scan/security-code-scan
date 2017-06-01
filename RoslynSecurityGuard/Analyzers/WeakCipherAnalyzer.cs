using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System.Collections.Immutable;

using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0010");
        
        private static ImmutableArray<string> BadCiphers = ImmutableArray.Create("DES", "RC2");
        
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.InvocationExpression, CSharp.SyntaxKind.ObjectCreationExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.InvocationExpression, VB.SyntaxKind.ObjectCreationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode node, node2, expression;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                node = ctx.Node as CSharpSyntax.InvocationExpressionSyntax;
                expression = ((CSharpSyntax.InvocationExpressionSyntax)node)?.Expression;
                node2 = ctx.Node as CSharpSyntax.ObjectCreationExpressionSyntax;
            }
            else
            {
                node = ctx.Node as VBSyntax.InvocationExpressionSyntax;
                expression = ((VBSyntax.InvocationExpressionSyntax)node)?.Expression;
                node2 = ctx.Node as VBSyntax.ObjectCreationExpressionSyntax;
            }

            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (AnalyzerUtil.SymbolMatch(symbol, type: cipher, name: "Create"))
                    {
                        var diagnostic = Diagnostic.Create(Rule, expression.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
            if (node2 != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node2).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (AnalyzerUtil.SymbolMatch(symbol, type: cipher + "CryptoServiceProvider"))
                    {
                        var diagnostic = Diagnostic.Create(Rule, node2.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
        }
    }
}
