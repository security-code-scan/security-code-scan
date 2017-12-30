using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using System;
using System.Collections.Immutable;
using System.Linq;

using SecurityCodeScan.Analyzers.Utils;
using SecurityCodeScan.Analyzers.Locale;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakCertificateValidationAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = LocaleUtil.GetDescriptor("SCS0004");

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, CSharp.SyntaxKind.AddAssignmentExpression, CSharp.SyntaxKind.SimpleAssignmentExpression);
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, VB.SyntaxKind.AddAssignmentStatement, VB.SyntaxKind.SimpleAssignmentStatement);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode assignment;
            SyntaxNode memberAccess;

            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                assignment = ctx.Node as CSharpSyntax.AssignmentExpressionSyntax;
                memberAccess = ((CSharpSyntax.AssignmentExpressionSyntax)assignment)?.Left as CSharpSyntax.MemberAccessExpressionSyntax;            }
            else
            {
                assignment = ctx.Node as VBSyntax.AssignmentStatementSyntax;
                memberAccess = ((VBSyntax.AssignmentStatementSyntax)assignment)?.Left as VBSyntax.MemberAccessExpressionSyntax;
            }       

            if (memberAccess == null) return;

            var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
            if (AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "ServicePointManager", name: "ServerCertificateValidationCallback") ||
                AnalyzerUtil.SymbolMatch(symbolMemberAccess, type: "ServicePointManager", name: "CertificatePolicy"))
            {
                var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation());
                ctx.ReportDiagnostic(diagnostic);
            }
        }
    }
}
