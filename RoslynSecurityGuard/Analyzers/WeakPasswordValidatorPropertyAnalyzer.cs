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
		private static DiagnosticDescriptor RulePasswordValidators = LocaleUtil.GetDescriptor("SG0033");

		public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RulePasswordValidators);

		public override void Initialize(AnalysisContext context)
		{
			context.RegisterSyntaxNodeAction(VisitDeclaration, SyntaxKind.VariableDeclaration);
		}

		public WeakPasswordValidatorPropertyAnalyzer()
		{
			TaintAnalyzer.RegisterExtension(this);
		}

		private static void VisitDeclaration(SyntaxNodeAnalysisContext ctx)
		{
			VariableDeclarationSyntax node = ctx.Node as VariableDeclarationSyntax;

			var variableDeclaration = node.Type.GetText().ToString().Trim();
			var simpleAssigments = node.DescendantNodes().OfType<AssignmentExpressionSyntax>();

			//foreach (AssignmentExpressionSyntax sa in simpleAssigments)
			//{
			//	sa.Left.GetText();
			//}

			if (variableDeclaration == "PasswordValidator" && simpleAssigments.Count() < Constants.MinimumPasswordValidatorProperties)
			{
				var diagnostic = Diagnostic.Create(RulePasswordValidators, node.GetLocation());
				ctx.ReportDiagnostic(diagnostic);
			}
		}

		public void VisitStatement(StatementSyntax node, ExecutionState state)
		{

		}

		public void VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
		{

		}

		public void VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state, MethodBehavior behavior, ISymbol symbol, VariableState variableRightState)
		{
			var assigment = node;

			if (assigment.Left is MemberAccessExpressionSyntax)
			{
				var memberAccess = (MemberAccessExpressionSyntax)assigment.Left;

				if (memberAccess.Expression is IdentifierNameSyntax)
				{
					var identifier = (IdentifierNameSyntax)memberAccess.Expression;
					string variableAccess = identifier.Identifier.ValueText;

					if (AnalyzerUtil.SymbolMatch(symbol, type: "PasswordValidator", name: "RequireDigit"))
					{
						state.AddTag(variableAccess, VariableTag.RequireDigitIsSet);
					}
				}
				
			}
		}

		public void VisitBeginMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
		{
			
		}

		public void VisitEndMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
		{
			
		}
	}
}
