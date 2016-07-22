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
  public class WeakCipherModeAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0012", typeof(WeakCipherModeAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            MemberAccessExpressionSyntax node = ctx.Node as MemberAccessExpressionSyntax;
            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;
                //DES.Create()
                if (AnalyzerUtil.InvokeMatch(symbol, className: "CipherMode", method: "ECB"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[] { "ECB" });
                    ctx.ReportDiagnostic(diagnostic);
                }
                if (AnalyzerUtil.InvokeMatch(symbol, className: "CipherMode", method: "OFB"))
                {
                    var diagnostic = Diagnostic.Create(Rule, node.Expression.GetLocation(), new string[] { "OFB" });
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
