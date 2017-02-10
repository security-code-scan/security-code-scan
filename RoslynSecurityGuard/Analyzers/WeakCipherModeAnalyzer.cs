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
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherModeAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor RuleCBC = LocaleUtil.GetDescriptor("SG0011");
        private static readonly DiagnosticDescriptor RuleECB = LocaleUtil.GetDescriptor("SG0012");
        private static readonly DiagnosticDescriptor RuleGeneric = LocaleUtil.GetDescriptor("SG0013");


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
