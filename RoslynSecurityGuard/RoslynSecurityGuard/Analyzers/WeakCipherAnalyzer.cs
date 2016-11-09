using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;
using RoslynSecurityGuard.Analyzers.Utils;
using RoslynSecurityGuard.Analyzers.Locale;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SG0010");
        
        private static ImmutableArray<string> BadCiphers = ImmutableArray.Create("DES", "RC2");
        
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression, SyntaxKind.ObjectCreationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {

            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            ObjectCreationExpressionSyntax node2 = ctx.Node as ObjectCreationExpressionSyntax;
            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                foreach (string cipher in BadCiphers)
                {
                    if (AnalyzerUtil.SymbolMatch(symbol, type: cipher, name: "Create"))
                    {
                        var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), cipher);
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
