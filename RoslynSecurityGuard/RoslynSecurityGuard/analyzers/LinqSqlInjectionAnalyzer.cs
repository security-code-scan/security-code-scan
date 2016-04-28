using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class LinqSqlInjectionAnalyzer : DiagnosticAnalyzer
    {

        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource(typeof(LinqSqlInjectionAnalyzer), DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            
            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            if (node != null) {

                //DataContext.ExecuteQuery()
                var invokedSymbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                if (AnalyzerUtil.InvokeMatch(invokedSymbol, className : "DataContext", method: "ExecuteQuery")) {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[0]);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }

        }
        
    }
}
