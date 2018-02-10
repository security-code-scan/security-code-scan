using System;
using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class XxeAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0007");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.SimpleAssignmentExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.SimpleAssignmentStatement);
            context.RegisterSyntaxNodeAction(VisitObjectCreationSyntaxNode,
                                         CSharp.SyntaxKind.ObjectCreationExpression);

            context.RegisterSyntaxNodeAction(VisitObjectCreationSyntaxNode,
                                         VB.SyntaxKind.ObjectCreationExpression);
        }

        private static readonly Version SafeDotNetVersion = new Version(4, 5, 2);

        public void VisitObjectCreationSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var symbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (symbol == null)
                return;

            if (!symbol.ContainingType.IsType("System.Xml.XmlReaderSettings") ||
                ctx.SemanticModel.Compilation.GetDotNetFrameworkVersion() >= SafeDotNetVersion)
            {
                return;
            }

            var diagnostic = Diagnostic.Create(Rule, ctx.Node.GetLocation());
            ctx.ReportDiagnostic(diagnostic);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode assignment;
            SyntaxNode memberAccess;
            SyntaxNode memberSet;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                assignment   = ctx.Node as CSharpSyntax.AssignmentExpressionSyntax;
                memberAccess = ((CSharpSyntax.AssignmentExpressionSyntax)assignment)?.Left as CSharpSyntax.MemberAccessExpressionSyntax;
                memberSet    = ((CSharpSyntax.AssignmentExpressionSyntax)assignment)?.Right;
            }
            else
            {
                assignment   = ctx.Node as VBSyntax.AssignmentStatementSyntax;
                memberAccess = ((VBSyntax.AssignmentStatementSyntax)assignment)?.Left as VBSyntax.MemberAccessExpressionSyntax;
                memberSet    = ((VBSyntax.AssignmentStatementSyntax)assignment)?.Right;
            }

            if (memberAccess == null || memberSet == null)
                return;

            var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
            if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "ProhibitDtd"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(memberSet);
                if (!constant.HasValue || constant.Value.ToString() != "False")
                    return;

                var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
            else if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "XmlReaderSettings", name: "DtdProcessing"))
            {
                var constant = ctx.SemanticModel.GetConstantValue(memberSet);
                if (!constant.HasValue || constant.Value.ToString() != "2")
                    return;

                var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
