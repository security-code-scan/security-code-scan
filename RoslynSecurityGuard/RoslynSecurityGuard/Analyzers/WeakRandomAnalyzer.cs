using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakRandomAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0005", typeof(WeakRandomAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }


        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                //System.Random.Next()
                if (AnalyzerUtil.InvokeMatch(symbol, className: "Random", method: "Next") ||
                    AnalyzerUtil.InvokeMatch(symbol, className: "Random", method: "NextBytes") ||
                    AnalyzerUtil.InvokeMatch(symbol, className: "Random", method: "NextDouble"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[0]);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
