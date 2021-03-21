#nullable disable
using System;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    internal class XxeAnalyzerCSharp : XxeAnalyzer
    {
        public XxeAnalyzerCSharp(XxeSecurityTypes xmlTypes, bool areDefaultsSecure) : base(
            xmlTypes, CSharpSyntaxNodeHelper.Default, areDefaultsSecure) { }

        public void RegisterSyntaxNodeAction(CodeBlockStartAnalysisContext<SyntaxKind> c)
        {
            c.RegisterSyntaxNodeAction(
                VisitSyntaxNode,
                SyntaxKind.InvocationExpression,
                SyntaxKind.ObjectCreationExpression,
                SyntaxKind.SimpleAssignmentExpression,
                SyntaxKind.VariableDeclarator);
        }

        private void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var node = /*CSharpSyntaxNodeHelper.Default.GetVariableDeclaratorOfAFieldDeclarationNode(ctx.Node) ??*/ ctx.Node;

            switch (node.Kind())
            {
                case SyntaxKind.ObjectCreationExpression:
                    AnalyzeObjectCreation(null, node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.SimpleAssignmentExpression:
                    AnalyzeAssignment(node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.VariableDeclarator:
                    AnalyzeVariableDeclaration(node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
                case SyntaxKind.InvocationExpression:
                    AnalyzeInvocation(node, ctx.SemanticModel, ctx.ReportDiagnostic);
                    break;
            }
        }
    }
}
