using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class CommandInjectionAnalyzer : DiagnosticAnalyzer
    {

        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0001",typeof(CommandInjectionAnalyzer).Name, DiagnosticSeverity.Warning);

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

            //Process.Start()
            //https://msdn.microsoft.com/en-us/library/system.diagnostics.process.start(v=vs.110).aspx
            //FIXME: Cover all the signatures
            if (AnalyzerUtil.SymbolMatch(symbol, type: "Process", name: "Start") && node.ArgumentList.Arguments.Count > 0) {
                //DataFlowAnalysis flow = ctx.SemanticModel.AnalyzeDataFlow(AnalyzerUtil.GetMethodFromNode(node));
                 
                if (!(AnalyzerUtil.IsStaticString(node.ArgumentList.Arguments[0].Expression))) 
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
