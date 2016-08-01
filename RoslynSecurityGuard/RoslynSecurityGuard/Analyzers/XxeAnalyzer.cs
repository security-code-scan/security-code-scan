using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class XxeAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource("SG0007",
            typeof(XxeAnalyzer).Name, DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.SimpleAssignmentExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var assignment = ctx.Node as AssignmentExpressionSyntax;
            var memberAccess = assignment?.Left as MemberAccessExpressionSyntax;
            if (memberAccess == null) return;

            var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
            if (AnalyzerUtil.InvokeMatch(symbolMemberAccess, className: "XmlReaderSettings", method: "ProhibitDtd"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "False")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
            else if (AnalyzerUtil.InvokeMatch(symbolMemberAccess, className: "XmlReaderSettings", method: "DtdProcessing"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(assignment.Right);
                if (constant.HasValue && constant.Value.ToString() == "2")
                {
                    var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}
