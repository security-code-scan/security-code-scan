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
    public class WeakCipherModeAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleECB = AnalyzerUtil.GetDescriptorFromResource("SG0012", typeof(WeakCipherModeAnalyzer).Name + "Ecb", DiagnosticSeverity.Warning);
        private static readonly DiagnosticDescriptor RuleOFB = AnalyzerUtil.GetDescriptorFromResource("SG0013", typeof(WeakCipherModeAnalyzer).Name + "Ofb", DiagnosticSeverity.Warning);
        private static readonly DiagnosticDescriptor RuleCBC = AnalyzerUtil.GetDescriptorFromResource("SG0014", typeof(WeakCipherModeAnalyzer).Name + "Cbc", DiagnosticSeverity.Warning);


        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleECB,RuleOFB,RuleCBC);

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
                    var diagnostic = Diagnostic.Create(RuleECB, node.Expression.GetLocation(), "ECB");
                    ctx.ReportDiagnostic(diagnostic);
                }
                if (AnalyzerUtil.InvokeMatch(symbol, className: "CipherMode", method: "OFB"))
                {
                    var diagnostic = Diagnostic.Create(RuleOFB, node.Expression.GetLocation(), "OFB");
                    ctx.ReportDiagnostic(diagnostic);
                }
                if (AnalyzerUtil.InvokeMatch(symbol, className: "CipherMode", method: "CBC"))
                {
                    var diagnostic = Diagnostic.Create(RuleCBC, node.Expression.GetLocation(), "CBC");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
