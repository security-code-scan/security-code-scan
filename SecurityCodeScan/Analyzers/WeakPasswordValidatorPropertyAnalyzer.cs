using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.VisualBasic;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Taint;
using SecurityCodeScan.Analyzers.Utils;
using CSharp = Microsoft.CodeAnalysis.CSharp;
using CSharpSyntax = Microsoft.CodeAnalysis.CSharp.Syntax;
using VB = Microsoft.CodeAnalysis.VisualBasic;
using VBSyntax = Microsoft.CodeAnalysis.VisualBasic.Syntax;

namespace SecurityCodeScan.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp, LanguageNames.VisualBasic)]
    public class WeakPasswordValidatorPropertyAnalyzer : TaintAnalyzerExtension
    {
        private static readonly DiagnosticDescriptor RulePasswordLength                  = LocaleUtil.GetDescriptor("SCS0032"); // RequiredLength's value is too small
        public const            string               RulePasswordDiagnosticId            = "SCS0033";
        private static readonly DiagnosticDescriptor RulePasswordValidators              = LocaleUtil.GetDescriptor(RulePasswordDiagnosticId); // Not enough properties set
        private static readonly DiagnosticDescriptor RulePasswordValidatorRequiredLength = LocaleUtil.GetDescriptor("SCS0034");                // RequiredLength must be set

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RulePasswordLength,
                                                                                                           RulePasswordValidators,
                                                                                                           RulePasswordValidatorRequiredLength);

        public override void Initialize(AnalysisContext context)
        {
            context.RegisterSyntaxNodeAction(VisitAssignmentExpression, CSharp.SyntaxKind.SimpleAssignmentExpression);
            context.RegisterSyntaxNodeAction(VisitAssignmentExpression,
                                             VB.SyntaxKind.SimpleAssignmentStatement,
                                             VB.SyntaxKind.NamedFieldInitializer);
        }

        private static void VisitAssignmentExpression(SyntaxNodeAnalysisContext ctx)
        {
            SyntaxNode n, right, left;
            if (ctx.Node.Language == LanguageNames.CSharp)
            {
                var node = (CSharpSyntax.AssignmentExpressionSyntax)ctx.Node;
                n        = node;
                right    = node.Right;
                left     = node.Left;
            }
            else
            {
                var vbNode = ctx.Node as VBSyntax.AssignmentStatementSyntax;
                if (vbNode != null)
                {
                    n        = vbNode;
                    right    = vbNode.Right;
                    left     = vbNode.Left;
                }
                else
                {
                    var node = (VBSyntax.NamedFieldInitializerSyntax)ctx.Node;
                    n        = node;
                    right    = node.Expression;
                    left     = node.Name;
                }
            }

            var symbol = ctx.SemanticModel.GetSymbolInfo(left).Symbol;

            var content = right.GetText().ToString();

            // Only if it is the RequiredLength property of a PasswordValidator
            if (!AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequiredLength") ||
                content == string.Empty)
            {
                return;
            }

            int numericValue;

            // Validates that the value is an int and that it is over the minimum value required
            if (!int.TryParse(right.GetText().ToString(), out numericValue) ||
                numericValue >= Constants.PasswordValidatorRequiredLength)
            {
                return;
            }

            var diagnostic = Diagnostic.Create(RulePasswordLength, n.GetLocation());
            ctx.ReportDiagnostic(diagnostic);
        }

        public WeakPasswordValidatorPropertyAnalyzer()
        {
            TaintAnalyzer.RegisterExtension(this);
        }

        public override void VisitAssignment(CSharpSyntax.AssignmentExpressionSyntax node,
                                             ExecutionState                          state,
                                             MethodBehavior                          behavior,
                                             ISymbol                                 symbol,
                                             VariableState                           variableRightState)
        {
            if (node != null)
                TagVariables(symbol, variableRightState);
        }

        public override void VisitEndMethodDeclaration(CSharpSyntax.MethodDeclarationSyntax node, ExecutionState state)
        {
            CheckState(state);
        }

        public override void VisitAssignment(VisualBasicSyntaxNode node,
                                             ExecutionState        state,
                                             MethodBehavior        behavior,
                                             ISymbol               symbol,
                                             VariableState         variableRightState)
        {
            if (node is VBSyntax.AssignmentStatementSyntax || node is VBSyntax.NamedFieldInitializerSyntax)
                TagVariables(symbol, variableRightState);
        }

        public override void VisitEndMethodDeclaration(VBSyntax.MethodBlockSyntax node, ExecutionState state)
        {
            CheckState(state);
        }

        private void CheckState(ExecutionState state)
        {
            // For every variables registered in state
            foreach (var variableState in state.Variables)
            {
                var st = variableState.Value;

                // Only if it is the constructor of the PasswordValidator instance
                if (!AnalyzerUtil.SymbolMatch(state.GetSymbol(st.Node), "PasswordValidator", ".ctor"))
                    continue;

                // If the PasswordValidator instance doesn't have the RequiredLength property
                if (!st.Tags.Contains(VariableTag.RequiredLengthIsSet))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidatorRequiredLength,
                                                                             variableState.Value.Node.GetLocation()));
                }

                // If the PasswordValidator instance doesn't have enough properties set
                if (!(st.Tags.Count >= Constants.MinimumPasswordValidatorProperties))
                {
                    state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidators,
                                                                             variableState.Value.Node.GetLocation()));
                }
            }
        }

        private void TagVariables(ISymbol symbol, VariableState variableRightState)
        {
            // Only PasswordValidator properties will cause a new tag to be added
            if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequiredLength"))
            {
                variableRightState.AddTag(VariableTag.RequiredLengthIsSet);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequireDigit"))
            {
                variableRightState.AddTag(VariableTag.RequireDigitIsSet);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequireLowercase"))
            {
                variableRightState.AddTag(VariableTag.RequireLowercaseIsSet);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequireNonLetterOrDigit"))
            {
                variableRightState.AddTag(VariableTag.RequireNonLetterOrDigitIsSet);
            }
            else if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequireUppercase"))
            {
                variableRightState.AddTag(VariableTag.RequireUppercaseIsSet);
            }
        }
    }
}
