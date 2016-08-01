using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XPathInjectionAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0003", typeof(XPathInjectionAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

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

                //Both SelectNodes and SelectSingleNode have the same method signatures
                //XmlNode will also match XmlDocument (implementation of XmlNode)
                if (AnalyzerUtil.SymbolMatch(symbol, type: "XmlNode", name: "SelectNodes") ||
                    AnalyzerUtil.SymbolMatch(symbol, type: "XmlNode", name: "SelectSingleNode"))
                {
                    var args = node.ArgumentList.Arguments;
                    if (!AnalyzerUtil.IsStaticString(args[0].Expression))
                    {
                        var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation());
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
        }
    }
}