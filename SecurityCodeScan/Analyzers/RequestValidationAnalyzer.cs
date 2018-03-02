using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

using SecurityCodeScan.Analyzers.Utils;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class RequestValidationAnalyzer : DiagnosticAnalyzer
    {
        private static readonly DiagnosticDescriptor                 Rule = LocaleUtil.GetDescriptor("SCS0017");
        public override         ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            // Separated the parsers on this one as they use too many language dependent syntax types. 
            // TODO: Review to see if this can be simplified.\
            context.RegisterSyntaxNodeAction(VisitPropertiesCSharp,         CSharp.SyntaxKind.PropertyDeclaration);
            context.RegisterSyntaxNodeAction(VisitPropertiesVisualBasic,    VB.SyntaxKind.PropertyStatement);
            context.RegisterSyntaxNodeAction(VisitMemberAccessCSharp,       CSharp.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(VisitMemberAccessVisualBasic,  VB.SyntaxKind.SimpleMemberAccessExpression);
            context.RegisterSyntaxNodeAction(VisitMethodsCSharp,            CSharp.SyntaxKind.MethodDeclaration);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic,       VB.SyntaxKind.FunctionBlock);
            context.RegisterSyntaxNodeAction(VisitMethodsVisualBasic,       VB.SyntaxKind.SubBlock);
        }

        private void VisitPropertiesCSharp(SyntaxNodeAnalysisContext ctx)
        {
            VisitProperties(ctx, CSharpSyntaxNodeHelper.Default);
        }

        private void VisitPropertiesVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            VisitProperties(ctx, VBSyntaxNodeHelper.Default);
        }

        private void VisitProperties(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var attributes = nodeHelper.GetPropertyAttributeNodes(ctx.Node);

            SyntaxNode allowHtmlAttribute = null;
            foreach (var attribute in attributes)
            {
                if (nodeHelper.GetAttributeNameNode(attribute).ToString().Contains("AllowHtml"))
                {
                    allowHtmlAttribute = attribute;
                    break;
                }
            }

            if (allowHtmlAttribute == null)
                return;

            var attributeSymbols = ctx.SemanticModel.GetSymbolInfo(allowHtmlAttribute).Symbol;
            if (attributeSymbols == null)
                return;

            var containingSymbol = attributeSymbols.ContainingSymbol.ToString();
            if (containingSymbol != "System.Web.Mvc.AllowHtmlAttribute")
                return;

            ctx.ReportDiagnostic(Diagnostic.Create(Rule, nodeHelper.GetPropertyIdentifierNode(ctx.Node).GetLocation()));
        }

        private void VisitMemberAccessVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            VisitMemberAccess(ctx, VBSyntaxNodeHelper.Default);
        }

        private void VisitMemberAccessCSharp(SyntaxNodeAnalysisContext ctx)
        {
            VisitMemberAccess(ctx, CSharpSyntaxNodeHelper.Default);
        }

        private void VisitMemberAccess(SyntaxNodeAnalysisContext ctx, SyntaxNodeHelper nodeHelper)
        {
            var name = nodeHelper.GetMemberAccessNameNode(ctx.Node);
            if (name.ToString() != "Unvalidated")
                return;

            var memberAccessSymbol = ctx.SemanticModel.GetSymbolInfo(ctx.Node).Symbol;
            if (memberAccessSymbol == null)
                return;

            var containingSymbol = memberAccessSymbol.ContainingSymbol.ToString();
            if (containingSymbol == "System.Web.Helpers.Validation" || containingSymbol == "System.Web.HttpRequestBase")
                ctx.ReportDiagnostic(Diagnostic.Create(Rule, name.GetLocation()));
        }

        private void VisitMethodsCSharp(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is CSharpSyntax.MethodDeclarationSyntax node))
                return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.AttributeLists)
            {
                if (attribute.Attributes.Count == 0)
                    continue; //Bound check .. Unlikely to happen

                var att = attribute.Attributes[0];

                //Extract the annotation identifier
                if (!(att.Name is CSharpSyntax.IdentifierNameSyntax identifier))
                    continue;

                if (identifier.Identifier.Text != "ValidateInput")
                    continue;

                var                           hasArgumentFalse = false;
                CSharpSyntax.ExpressionSyntax expression       = null;
                foreach (var arg in att.ArgumentList.Arguments)
                {
                    var literal = (CSharpSyntax.LiteralExpressionSyntax)arg.Expression;
                    if (literal.Token.ValueText != "false")
                        continue;

                    hasArgumentFalse = true;
                    expression       = arg.Expression;
                }

                if (hasArgumentFalse && expression != null)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                }
            }
        }

        private void VisitMethodsVisualBasic(SyntaxNodeAnalysisContext ctx)
        {
            if (!(ctx.Node is VBSyntax.MethodBlockSyntax node))
                return;

            //Iterating over the list of annotation for a given method
            foreach (var attribute in node.BlockStatement.AttributeLists)
            {
                if (attribute.Attributes.Count == 0)
                    continue; //Bound check .. Unlikely to happen

                var att = attribute.Attributes[0];

                //Extract the annotation identifier
                if (!(att.Name is VBSyntax.IdentifierNameSyntax identifier))
                    continue;

                if (identifier.Identifier.Text != "ValidateInput")
                    continue;

                var                       hasArgumentFalse = false;
                VBSyntax.ExpressionSyntax expression       = null;
                foreach (var arg in att.ArgumentList.Arguments)
                {
                    var literal = (VBSyntax.LiteralExpressionSyntax)arg.GetExpression();
                    if (literal.Token.ValueText != "False")
                        continue;

                    hasArgumentFalse = true;
                    expression       = arg.GetExpression();
                }

                if (hasArgumentFalse && expression != null)
                {
                    ctx.ReportDiagnostic(Diagnostic.Create(Rule, expression.GetLocation()));
                }
            }
        }
    }
}
