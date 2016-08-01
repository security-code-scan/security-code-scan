using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
                private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0010", typeof(WeakCipherAnalyzer).Name, DiagnosticSeverity.Warning);

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
                //DES.Create()
                if (AnalyzerUtil.InvokeMatch(symbol, className: "DES", method: "Create"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), "DES");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
            if (node2 != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node2).Symbol;
                //DES.Create()
                if (AnalyzerUtil.InvokeMatch(symbol, className: "DESCryptoServiceProvider"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node2.GetLocation(), "DES");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
