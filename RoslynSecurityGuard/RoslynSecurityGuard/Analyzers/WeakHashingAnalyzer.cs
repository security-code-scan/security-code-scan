using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0006", typeof(WeakHashingAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {

            var node = ctx.Node as InvocationExpressionSyntax;
            if (node == null) return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;
            //MD5.Create()
            if (AnalyzerUtil.SymbolMatch(symbol, type: "MD5", name: "Create"))
            {
                var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), "MD5");
                ctx.ReportDiagnostic(diagnostic);
            }
            //SHA1.Create()
            else if (AnalyzerUtil.SymbolMatch(symbol, type: "SHA1", name: "Create"))
            {
                var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), "SHA1");
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}