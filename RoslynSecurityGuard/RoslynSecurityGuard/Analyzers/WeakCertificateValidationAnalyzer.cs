using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Immutable;
using System.Linq;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCertificateValidationAnalyzer : DiagnosticAnalyzer
    {
        private static DiagnosticDescriptor Rule = AnalyzerUtil.GetDescriptorFromResource(typeof(WeakCertificateValidationAnalyzer), DiagnosticSeverity.Warning);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule); } }

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.AddAssignmentExpression, SyntaxKind.SimpleAssignmentExpression);
        }

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var assignment = ctx.Node as AssignmentExpressionSyntax;
            if(assignment != null)
            {

                var memberAccess = assignment.Left as MemberAccessExpressionSyntax;
                if (memberAccess != null)
                {

                    var symbolMemberAccess = ctx.SemanticModel.GetSymbolInfo(memberAccess).Symbol;
                    if (AnalyzerUtil.InvokeMatch(symbolMemberAccess, className: "ServicePointManager", method: "ServerCertificateValidationCallback") ||
                        AnalyzerUtil.InvokeMatch(symbolMemberAccess, className: "ServicePointManager", method: "CertificatePolicy"))
                    {
                        var diagnostic = Diagnostic.Create(Rule, assignment.GetLocation(), new string[0]);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
                //}
            }
        }
    }
}
