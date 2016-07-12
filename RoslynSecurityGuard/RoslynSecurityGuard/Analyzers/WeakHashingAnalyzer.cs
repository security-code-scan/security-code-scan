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

        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource(typeof(WeakHashingAnalyzer), DiagnosticSeverity.Warning);

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
                //MD5.Create()
                if (AnalyzerUtil.InvokeMatch(symbol, className: "MD5", method: "Create"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[] { "MD5" });
                    ctx.ReportDiagnostic(diagnostic);
                }
                //SHA1.Create()
                else if (AnalyzerUtil.InvokeMatch(symbol, className: "SHA1", method: "Create"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[] { "SHA1" });
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}