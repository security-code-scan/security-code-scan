using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using SecurityCodeScan.Analyzers.Locale;
using SecurityCodeScan.Analyzers.Utils;
using System;
using System.Collections.Generic;

namespace SecurityCodeScan.Analyzers.Taint
{
    /// <summary>
    /// Symbolic execution of C# code
    /// </summary>
    public class CSharpCodeEvaluation : BaseCodeEvaluation
    {
        public static List<TaintAnalyzerExtension> extensions { get; set; } = new List<TaintAnalyzerExtension>();
        

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodDeclarationSyntax;
            try
            {
                if (node != null)
                {
                    var state = new ExecutionState(ctx);

                    foreach (var ext in extensions)
                    {
                        ext.VisitBeginMethodDeclaration(node, state);
                    }

                    VisitMethodDeclaration(node, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitEndMethodDeclaration(node, state);
                    }
                }
            }
            catch (Exception e)
            {
                //Intercept the exception for logging. Otherwise, the analyzer will failed silently.
                string methodName = node.Identifier.Text;
                string errorMsg = string.Format("Unhandle exception while visiting method {0} : {1}", methodName, e.Message);
                SGLogging.Log(errorMsg);
                SGLogging.Log(e.StackTrace, false);
                throw new Exception(errorMsg, e);
            }
        }

        /// <summary>
        /// Entry point that visit the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodDeclarationSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier), new VariableState(parameter, VariableTaint.TAINTED));
            }

            if (node.Body != null)
            {
                foreach (StatementSyntax statement in node.Body.Statements)
                {
                    VisitNode(statement, state);

                    foreach (var ext in extensions)
                    {
                        ext.VisitStatement(statement, state);
                    }
                }
            }

            //The state return is irrelevant because it is not use.
            return new VariableState(node, VariableTaint.UNKNOWN);
        }

        /// <summary>
        /// Statement are all segment separate by semi-colon.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        private VariableState VisitNode(SyntaxNode node, ExecutionState state)
        {
            //SGLogging.Log(node.GetType().ToString());

            //Variable allocation
            if (node is LocalDeclarationStatementSyntax)
            {
                var declaration = (LocalDeclarationStatementSyntax)node;
                return VisitLocalDeclaration(declaration, state);
            }
            else if (node is VariableDeclarationSyntax)
            {
                var declaration = (VariableDeclarationSyntax)node;
                return VisitVariableDeclaration(declaration, state);
            }

            //Expression
            else if (node is ExpressionStatementSyntax)
            {
                var expression = (ExpressionStatementSyntax)node;
                return VisitExpressionStatement(expression, state);
            }
            else if (node is ExpressionSyntax)
            {
                var expression = (ExpressionSyntax)node;
                return VisitExpression(expression, state);
            }
            else if (node is MethodDeclarationSyntax)
            {
                var methodDeclaration = (MethodDeclarationSyntax)node;
                return VisitMethodDeclaration(methodDeclaration, state);
            }
            else
            {
                foreach (var n in node.ChildNodes())
                {
                    VisitNode(n, state);
                }

				var isBlockStatement = node is BlockSyntax || node is IfStatementSyntax || node is ForEachStatementSyntax || node is ForStatementSyntax;

				if (!isBlockStatement)
				{
					SGLogging.Log("Unsupported statement " + node.GetType() + " (" + node.ToString() + ")");
				}

				return new VariableState(node, VariableTaint.UNKNOWN);
			}            
        }

        /// <summary>
        /// Unwrap
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitLocalDeclaration(LocalDeclarationStatementSyntax declaration, ExecutionState state)
        {
            return VisitVariableDeclaration(declaration.Declaration, state);
        }

        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclarationSyntax declaration, ExecutionState state)
        {
            VariableState lastState = new VariableState(declaration, VariableTaint.UNKNOWN);

            foreach (var variable in declaration.Variables)
            {
                var identifier = variable.Identifier;
                var initializer = variable.Initializer;
                if (initializer is EqualsValueClauseSyntax)
                {
                    EqualsValueClauseSyntax equalsClause = initializer;

                    VariableState varState = VisitExpression(equalsClause.Value, state);
					//varState.SetType(lastState.type);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }
            }

            //
            return lastState;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="syntaxToken"></param>
        /// <returns></returns>
        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }


        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            //Invocation
            if (expression is InvocationExpressionSyntax)
            {
                var invocation = (InvocationExpressionSyntax)expression;
                return VisitMethodInvocation(invocation, state);
            }
            else if (expression is ObjectCreationExpressionSyntax)
            {
                var objCreation = (ObjectCreationExpressionSyntax)expression;
                return VisitObjectCreation(objCreation, state);
            }

            else if (expression is LiteralExpressionSyntax)
            {
                return new VariableState(expression, VariableTaint.CONSTANT);
            }
            else if (expression is IdentifierNameSyntax)
            {
                var identifierName = (IdentifierNameSyntax)expression;
                return VisitIdentifierName(identifierName, state);
            }

            //Arithmetic : Addition
            else if (expression is BinaryExpressionSyntax)
            {
                var binaryExpression = (BinaryExpressionSyntax)expression;
                return VisitBinaryExpression(binaryExpression, state);
            }

            else if (expression is AssignmentExpressionSyntax)
            {
                var assignment = (AssignmentExpressionSyntax)expression;
                return VisitAssignment(assignment, state);
            }
            else if (expression is MemberAccessExpressionSyntax)
            {
                var memberAccess = (MemberAccessExpressionSyntax)expression;
                var leftExpression = memberAccess.Expression;
                return VisitExpression(leftExpression, state);
            }
            else if (expression is ElementAccessExpressionSyntax)
            {
                var elementAccess = (ElementAccessExpressionSyntax)expression;
                return VisitElementAccess(elementAccess, elementAccess.ArgumentList, state);
            }
            else if (expression is ArrayCreationExpressionSyntax)
            {
                var arrayCreation = (ArrayCreationExpressionSyntax)expression;
                return VisitArrayCreation(arrayCreation, state);
            }
            else if (expression is TypeOfExpressionSyntax)
            {
                var typeofEx = (TypeOfExpressionSyntax)expression;
                return new VariableState(expression, VariableTaint.SAFE);
            }
            else if (expression is ConditionalExpressionSyntax)
            {
                var conditional = (ConditionalExpressionSyntax)expression;
                VisitExpression(conditional.Condition, state);
                var finalState = new VariableState(expression, VariableTaint.SAFE);

                var whenTrueState = VisitExpression(conditional.WhenTrue, state);
                finalState = finalState.merge(whenTrueState);
                var whenFalseState = VisitExpression(conditional.WhenFalse, state);
                finalState = finalState.merge(whenFalseState);

                return finalState;
            }
            else if (expression is CheckedExpressionSyntax)
            {
                var checkedEx = (CheckedExpressionSyntax)expression;
                return VisitExpression(checkedEx.Expression, state);
            }
            else if (expression is QueryExpressionSyntax)
            {
                var query = (QueryExpressionSyntax)expression;
                var body = query.Body;
                return new VariableState(expression, VariableTaint.UNKNOWN);
            }
            else if (expression is InterpolatedStringExpressionSyntax)
            {
                var interpolatedString = (InterpolatedStringExpressionSyntax)expression;

                return VisitInterpolatedString(interpolatedString, state);
            }

            SGLogging.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(expression, VariableTaint.UNKNOWN);
        }

        private VariableState VisitInterpolatedString(InterpolatedStringExpressionSyntax interpolatedString, ExecutionState state)
        {

            var varState = new VariableState(interpolatedString, VariableTaint.CONSTANT);

            foreach (var content in interpolatedString.Contents)
            {
                var textString = content as InterpolatedStringTextSyntax;
                if (textString != null)
                {
                    varState = varState.merge(new VariableState(textString, VariableTaint.CONSTANT));
                }
                var interpolation = content as InterpolationSyntax;
                if (interpolation != null)
                {
                    var expressionState = VisitExpression(interpolation.Expression, state);
                    varState = varState.merge(expressionState);
                }
            }
            return varState;
        }

        private VariableState VisitElementAccess(ElementAccessExpressionSyntax elementAccess, BracketedArgumentListSyntax argumentList, ExecutionState state)
        {
            foreach (var argument in argumentList.Arguments)
            {
                VisitExpression(argument.Expression, state);
            }
            return new VariableState(elementAccess, VariableTaint.UNKNOWN);
        }

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
        }

        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
			VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

			foreach (SyntaxNode child in node.DescendantNodes())
			{
				if (child is AssignmentExpressionSyntax)
				{
					finalState = finalState.merge(VisitAssignment((AssignmentExpressionSyntax)child, state));
				}
				else
				{
					SGLogging.Log(child.GetText().ToString().Trim() + " -> " + finalState);
				}
			}
			
            return finalState;
        }

        private VariableState VisitArrayCreation(ArrayCreationExpressionSyntax node, ExecutionState state)
        {
            var arrayInit = node.Initializer;

            var finalState = new VariableState(node, VariableTaint.SAFE);
            if (arrayInit != null)
            {
                foreach (var ex in arrayInit.Expressions)
                {
                    var exprState = VisitExpression(ex, state);
                    finalState = finalState.merge(exprState);
                }
            }
            return finalState;
        }

        /// <summary>
        /// Logic for each method invocation (including constructor)
        /// The argument list is required because <code>InvocationExpressionSyntax</code> and 
        /// <code>ObjectCreationExpressionSyntax</code> do not share a common interface.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="argList"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitInvocationAndCreation(ExpressionSyntax node, ArgumentListSyntax argList, ExecutionState state)
        {

            var symbol = state.GetSymbol(node);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            int i = 0;
            if (argList == null)
            {
                return new VariableState(node, VariableTaint.UNKNOWN);
            }

            var returnState = new VariableState(node, VariableTaint.SAFE);

            foreach (var argument in argList.Arguments)
            {

                var argumentState = VisitExpression(argument.Expression, state);

                if (symbol != null)
                {
                    SGLogging.Log(symbol.ContainingType + "." + symbol.Name + " -> " + argumentState);
                }

                if (behavior != null)
                { //If the API is at risk
                    if ((argumentState.taint == VariableTaint.TAINTED || //Tainted values
                        argumentState.taint == VariableTaint.UNKNOWN) &&
                        Array.Exists(behavior.injectablesArguments, element => element == i) //If the current parameter can be injected.
                        )
                    {
                        var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }
                    else if (argumentState.taint == VariableTaint.CONSTANT && //Hard coded value
                        Array.Exists(behavior.passwordArguments, element => element == i) //If the current parameter is a password
                        )
                    {

                        var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                        var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                        state.AnalysisContext.ReportDiagnostic(diagnostic);
                    }

                    else if ( //
                        Array.Exists(behavior.taintFromArguments, element => element == i))
                    {
                        returnState = returnState.merge(argumentState);
                    }
                }

                //TODO: tainted all object passed in argument

                i++;
            }

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitInvocationAndCreation(node, argList, state);
            }

            var hasTaintFromArguments = behavior?.taintFromArguments?.Length > 0;
            if (hasTaintFromArguments)
            {
                return returnState;
            }
            else
            {
                return new VariableState(node, VariableTaint.UNKNOWN);
            }

        }

        private VariableState VisitAssignment(AssignmentExpressionSyntax node, ExecutionState state)
        {

            var symbol = state.GetSymbol(node.Left);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(node.Right, state);

			//Additionnal analysis by extension
			foreach (var ext in extensions)
			{
				ext.VisitAssignment(node, state, behavior, symbol, variableState);
			}

			IdentifierNameSyntax parentIdentifierSyntax = GetParentIdentifier(node.Left);
			if (parentIdentifierSyntax != null)
			{
				state.MergeValue(ResolveIdentifier(parentIdentifierSyntax.Identifier), variableState);
			}

			if (behavior != null && //Injection
                    behavior.isInjectableField &&
                    variableState.taint != VariableTaint.CONSTANT && //Skip safe values
                    variableState.taint != VariableTaint.SAFE)
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localeInjection);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }
            if (behavior != null && //Known Password API
                    behavior.isPasswordField &&
                    variableState.taint == VariableTaint.CONSTANT //Only constant
                    )
            {
                var newRule = LocaleUtil.GetDescriptor(behavior.localePassword);
                var diagnostic = Diagnostic.Create(newRule, node.GetLocation());
                state.AnalysisContext.ReportDiagnostic(diagnostic);
            }


            //TODO: tainted the variable being assign.


            return variableState;
        }

		/// <summary>
		/// Return the top member from an assignment.
		/// <code>
		/// a.b.c = 1234; //Will return a
		/// d.e = 1234 //Will return d
		/// </code>
		/// </summary>
		/// <param name="expression"></param>
		/// <returns></returns>
		private IdentifierNameSyntax GetParentIdentifier(ExpressionSyntax expression)
		{
			//if (!(expression is IdentifierNameSyntax))
			//{
			//	return GetParentIdentifier((ExpressionSyntax)expression.Parent);
			//}

			if (expression is MemberAccessExpressionSyntax)
			{
				return GetParentIdentifier(((MemberAccessExpressionSyntax)expression).Expression);
			}

			if (expression is IdentifierNameSyntax)
			{
				return (IdentifierNameSyntax)expression;
			}

			return null;

		}


		/// <summary>
		/// Identifier name include variable name.
		/// </summary>
		/// <param name="expression"></param>
		/// <param name="state"></param>
		/// <returns></returns>
		private VariableState VisitIdentifierName(IdentifierNameSyntax expression, ExecutionState state)
        {
            var value = ResolveIdentifier(expression.Identifier);
            return state.GetValueByIdentifier(value);
        }

        /// <summary>
        /// Combine the state of the two operands. Binary expression include concatenation.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitBinaryExpression(BinaryExpressionSyntax expression, ExecutionState state)
        {
            VariableState left = VisitExpression(expression.Left, state);
            VariableState right = VisitExpression(expression.Right, state);
            return left.merge(right);
        }

    }
}
