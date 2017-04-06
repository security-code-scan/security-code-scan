using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using RoslynSecurityGuard.Analyzers.Locale;
using RoslynSecurityGuard.Analyzers.Taint;
using RoslynSecurityGuard.Analyzers.Utils;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RoslynSecurityGuard.Analyzers
{
	[DiagnosticAnalyzer(LanguageNames.CSharp)]
	public class WeakPasswordValidatorAnalyzer : DiagnosticAnalyzer
	{
		private static DiagnosticDescriptor RulePasswordLength = LocaleUtil.GetDescriptor("SG0032");
		private static DiagnosticDescriptor RulePasswordValidators = LocaleUtil.GetDescriptor("SG0033");

		public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(RulePasswordLength, RulePasswordValidators);

		public override void Initialize(AnalysisContext context)
		{
			context.RegisterSyntaxNodeAction(VisitAssignment, SyntaxKind.SimpleAssignmentExpression, SyntaxKind.VariableDeclaration);
		}
		
		private static void VisitAssignment(SyntaxNodeAnalysisContext ctx)
		{
			AssignmentExpressionSyntax node = ctx.Node as AssignmentExpressionSyntax;

			var symbol = ctx.SemanticModel.GetSymbolInfo(node.Left).Symbol;

			var content = node.Right.GetText().ToString();

			if (AnalyzerUtil.SymbolMatch(symbol, name: "RequiredLength") && content != String.Empty && Convert.ToInt32(content) < 8)
			{
				int numericValue;
				if (!(int.TryParse(node.Right.GetText().ToString(), out numericValue) && numericValue > 8))
				{
					var diagnostic = Diagnostic.Create(RulePasswordLength, node.GetLocation());
					ctx.ReportDiagnostic(diagnostic);
				}
			}
		}
	// //
	}
}