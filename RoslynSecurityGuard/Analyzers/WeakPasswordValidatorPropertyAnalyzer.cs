using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Immutable;
using RoslynSecurityGuard.Analyzers.Taint;
using Microsoft.CodeAnalysis.CSharp;
using RoslynSecurityGuard.Analyzers.Locale;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;

namespace RoslynSecurityGuard.Analyzers
{
	[DiagnosticAnalyzer(LanguageNames.CSharp)]
	public class WeakPasswordValidatorPropertyAnalyzer : DiagnosticAnalyzer, CSharpTaintAnalyzerExtension
	{
		private static DiagnosticDescriptor RulePasswordLength = LocaleUtil.GetDescriptor("SG0032");					// RequiredLength's value is too small
		private static DiagnosticDescriptor RulePasswordValidators = LocaleUtil.GetDescriptor("SG0033");				// Not enough properties set
		private static DiagnosticDescriptor RulePasswordValidatorRequiredLength = LocaleUtil.GetDescriptor("SG0034");	// RequiredLength must be set

		public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RulePasswordLength, RulePasswordValidators, RulePasswordValidatorRequiredLength);

		public override void Initialize(AnalysisContext context)
		{
			context.RegisterSyntaxNodeAction(VisitAssignmentExpression, SyntaxKind.SimpleAssignmentExpression);
		}

		private static void VisitAssignmentExpression(SyntaxNodeAnalysisContext ctx)
		{
			AssignmentExpressionSyntax node = ctx.Node as AssignmentExpressionSyntax;

			var symbol = ctx.SemanticModel.GetSymbolInfo(node.Left).Symbol;

			var content = node.Right.GetText().ToString();

			// Only if it is the RequiredLength property of a PasswordValidator
			if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequiredLength") && content != String.Empty)
			{
				int numericValue;
				// Validates that the value is an int and that it is over the minimum value required
				if (int.TryParse(node.Right.GetText().ToString(), out numericValue) && numericValue < Constants.PasswordValidatorRequiredLength)
				{
					var diagnostic = Diagnostic.Create(RulePasswordLength, node.GetLocation());
					ctx.ReportDiagnostic(diagnostic);
				}
			}
		}

		public WeakPasswordValidatorPropertyAnalyzer()
		{
			TaintAnalyzer.RegisterExtension(this);
		}

		private static void VisitDeclaration(SyntaxNodeAnalysisContext ctx)
		{

		}

		public void VisitStatement(StatementSyntax node, ExecutionState state)
		{

		}

		public void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
		{

		}

		public void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
		{
			var assignment = node;

			if (assignment is AssignmentExpressionSyntax)
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

		public void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
		{

		}

		public void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
		{
			// For every variables registered in state
			foreach (var variableState in state.Variables)
			{
				var st = variableState.Value;

				// Only if it is the constructor of the PasswordValidator instance
				if (AnalyzerUtil.SymbolMatch(state.GetSymbol(st.node), "PasswordValidator", ".ctor"))
				{
					// If the PasswordValidator instance doesn't have the RequiredLength property
					if (!st.tags.Contains(VariableTag.RequiredLengthIsSet))
					{
						state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidatorRequiredLength, variableState.Value.node.GetLocation()));
					}
					// If the PasswordValidator instance doesn't have enough properties set
					if (!(st.tags.Count() >= Constants.MinimumPasswordValidatorProperties))
					{
						state.AnalysisContext.ReportDiagnostic(Diagnostic.Create(RulePasswordValidators, variableState.Value.node.GetLocation()));
					}
				}
			}
		}

	}
}
