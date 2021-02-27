#nullable disable
using System;
using Microsoft.CodeAnalysis.VisualBasic;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    internal class XxeAnalyzerVBasic : XxeAnalyzer
    {
        public XxeAnalyzerVBasic(XxeSecurityTypes xmlTypes, bool areDefaultsSecure) :
            base(xmlTypes, VBSyntaxNodeHelper.Default, areDefaultsSecure) { }

        public void RegisterSyntaxNodeAction(CodeBlockStartAnalysisContext<SyntaxKind> c)
        {
            c.RegisterSyntaxNodeAction(
                VisitSyntaxNode,
                SyntaxKind.InvocationExpression,
                SyntaxKind.ObjectCreationExpression,
                SyntaxKind.SimpleAssignmentStatement,
                SyntaxKind.VariableDeclarator);
        }

        private void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            switch (ctx.Node.Kind())
            {
                case SyntaxKind.ObjectCreationExpression:
                    AnalyzeObjectCreation(null, ctx.Node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.SimpleAssignmentStatement:
                    AnalyzeAssignment(ctx.Node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.VariableDeclarator:
                    AnalyzeVariableDeclaration(ctx.Node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.InvocationExpression:
                    AnalyzeInvocation(ctx.Node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
            }
        }
    }
}
