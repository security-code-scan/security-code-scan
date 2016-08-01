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
        private static readonly DiagnosticDescriptor RuleGeneric = AnalyzerUtil.GetDescriptorFromResource("SG0013", typeof(WeakCipherModeAnalyzer).Name + "Generic", DiagnosticSeverity.Warning);
        private static readonly DiagnosticDescriptor RuleCBC = AnalyzerUtil.GetDescriptorFromResource("SG0014", typeof(WeakCipherModeAnalyzer).Name + "Cbc", DiagnosticSeverity.Warning);


        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RuleECB,RuleCBC,RuleGeneric);

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
                if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "ECB"))
                {
                    var diagnostic = Diagnostic.Create(RuleECB, node.Expression.GetLocation(), "ECB");
                    ctx.ReportDiagnostic(diagnostic);
                }
                else if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CBC"))
                {
                    var diagnostic = Diagnostic.Create(RuleCBC, node.Expression.GetLocation(), "CBC");
                    ctx.ReportDiagnostic(diagnostic);
                }
                else if (AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "OFB") || AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CFB") || AnalyzerUtil.SymbolMatch(symbol, "CipherMode", "CTS"))
                {
                    var diagnostic = Diagnostic.Create(RuleGeneric, node.Expression.GetLocation(), "OFB");
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
