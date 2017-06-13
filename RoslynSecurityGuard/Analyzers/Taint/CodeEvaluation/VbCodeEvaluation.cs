using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using RoslynSecurityGuard.Analyzers.Utils;
using Microsoft.CodeAnalysis;
using RoslynSecurityGuard.Analyzers.Locale;
using Microsoft.CodeAnalysis.VisualBasic;

namespace RoslynSecurityGuard.Analyzers.Taint
{
    public class VbCodeEvaluation : BaseCodeEvaluation
    {
        public static List<TaintAnalyzerExtension> extensions { get; set; } = new List<TaintAnalyzerExtension>();

        public void VisitMethods(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as MethodBlockSyntax;
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
                string methodName = node.BlockStatement.ToString();
                string errorMsg = string.Format("Unhandle exception while visiting method: {0}", e.Message);
                SGLogging.Log(errorMsg);
                throw new Exception(errorMsg, e);
            }
        }


        /// <summary>
        /// Entry point that visit the method statements.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        private VariableState VisitMethodDeclaration(MethodBlockSyntax node, ExecutionState state)
        {
            foreach (ParameterSyntax parameter in node.SubOrFunctionStatement.ParameterList.Parameters)
            {
                state.AddNewValue(ResolveIdentifier(parameter.Identifier.Identifier), new VariableState(parameter, VariableTaint.TAINTED));
            }

            if (node.Statements != null)
            {
                foreach (StatementSyntax statement in node.Statements)
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
            else if (node is VariableDeclaratorSyntax)
            {
                var declaration = (VariableDeclaratorSyntax)node;
                return VisitVariableDeclaration(declaration, state);
            }
            else if (node is AssignmentStatementSyntax)
            {
                var assignment = (AssignmentStatementSyntax)node;
                return VisitAssignmentStatement(assignment, state);
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
            else if (node is MethodBlockSyntax)
            {
                var methodDeclaration = (MethodBlockSyntax)node;
                return VisitMethodDeclaration(methodDeclaration, state);
            }
            else
            {
                foreach (var n in node.ChildNodes())
                {
                    VisitNode(n, state);
                }

                // var isBlockStatement = node is BlockSyntax || node is IfStatementSyntax || node is ForEachStatementSyntax || node is ForStatementSyntax;
                var isBlockStatement = node is IfStatementSyntax || node is ForEachStatementSyntax || node is ForStatementSyntax;


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
            foreach (var i in declaration.Declarators)
            {
                return VisitVariableDeclaration(i, state);
            }
            return new VariableState(declaration, VariableTaint.UNKNOWN);
        }


        /// <summary>
        /// Evaluate expression that contains a list of assignment.
        /// </summary>
        /// <param name="declaration"></param>
        /// <param name="state"></param>
        private VariableState VisitVariableDeclaration(VariableDeclaratorSyntax declaration, ExecutionState state)
        {
            VariableState lastState = new VariableState(declaration, VariableTaint.UNKNOWN);

            foreach (var variable in declaration.Names)
            {
                var identifier = variable.Identifier;
                var initializer = declaration.Initializer;
                if (initializer is EqualsValueSyntax)
                {
                    EqualsValueSyntax equalsClause = initializer;

                    VariableState varState = VisitExpression(equalsClause.Value, state);
                    //varState.SetType(lastState.type);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }
                if (declaration.AsClause is AsNewClauseSyntax)
                {
                    var newClause = (AsNewClauseSyntax)declaration.AsClause;
                    VariableState varState = VisitExpression(newClause.NewExpression, state);
                    state.AddNewValue(ResolveIdentifier(identifier), varState);
                    lastState = varState;
                }
            }

            return lastState;
        }


        private VariableState VisitExpression(ExpressionSyntax expression, ExecutionState state)
        {
            // TODO: Review other expresion types that are unique to VB. 
            // TODO: Write tests to cover all these. 

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

            else if (expression is MemberAccessExpressionSyntax)
            {
                var memberAccess = (MemberAccessExpressionSyntax)expression;
                var leftExpression = memberAccess.Expression;
                return VisitExpression(leftExpression, state);
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
            else if (expression is TernaryConditionalExpressionSyntax)
            {
                var conditional = (TernaryConditionalExpressionSyntax)expression;
                VisitExpression(conditional.Condition, state);
                var finalState = new VariableState(expression, VariableTaint.SAFE);

                var whenTrueState = VisitExpression(conditional.WhenTrue, state);
                finalState = finalState.merge(whenTrueState);
                var whenFalseState = VisitExpression(conditional.WhenFalse, state);
                finalState = finalState.merge(whenFalseState);

                return finalState;
            }
            else if (expression is QueryExpressionSyntax)
            {
                var query = (QueryExpressionSyntax)expression;
                var body = query.Clauses;
                return new VariableState(expression, VariableTaint.UNKNOWN);
            }


            SGLogging.Log("Unsupported expression " + expression.GetType() + " (" + expression.ToString() + ")");

            //Unsupported expression
            return new VariableState(expression, VariableTaint.UNKNOWN);
        }

        private VariableState VisitMethodInvocation(InvocationExpressionSyntax node, ExecutionState state)
        {
            return VisitInvocationAndCreation(node, node.ArgumentList, state);
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

                var argumentState = VisitExpression(argument.GetExpression(), state);

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

        private VariableState VisitAssignmentStatement(AssignmentStatementSyntax node, ExecutionState state)
        {
            return VisitAssignment(node, node.Left, node.Right, state);
        }
        
        private VariableState VisitNamedFieldInitializer(NamedFieldInitializerSyntax node, ExecutionState state)
        {
            return VisitAssignment(node, node.Name, node.Expression, state);
        }

        private VariableState VisitAssignment(VisualBasicSyntaxNode node, ExpressionSyntax leftExpression, 
            ExpressionSyntax rightExpression, ExecutionState state)
        {

                var symbol = state.GetSymbol(leftExpression);
            MethodBehavior behavior = behaviorRepo.GetMethodBehavior(symbol);

            var variableState = VisitExpression(rightExpression, state);

            //Additionnal analysis by extension
            foreach (var ext in extensions)
            {
                ext.VisitAssignment(node, state, behavior, symbol, variableState);
            }
            
            IdentifierNameSyntax parentIdentifierSyntax = GetParentIdentifier(leftExpression);
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



        private VariableState VisitObjectCreation(ObjectCreationExpressionSyntax node, ExecutionState state)
        {
            VariableState finalState = VisitInvocationAndCreation(node, node.ArgumentList, state);

            foreach (SyntaxNode child in node.DescendantNodes())
            {
                if (child is NamedFieldInitializerSyntax)
                {
                    finalState = finalState.merge(VisitNamedFieldInitializer((NamedFieldInitializerSyntax)child, state));
                }
                else
                {
                    SGLogging.Log(child.GetText().ToString().Trim() + " -> " + finalState);
                }
            }

            return finalState;
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

        private VariableState VisitExpressionStatement(ExpressionStatementSyntax node, ExecutionState state)
        {
            return VisitExpression(node.Expression, state); //Simply unwrap the expression
        }

        private VariableState VisitArrayCreation(ArrayCreationExpressionSyntax node, ExecutionState state)
        {
            var arrayInit = node.Initializer;

            var finalState = new VariableState(node, VariableTaint.SAFE);
            if (arrayInit != null)
            {
                foreach (var ex in arrayInit.Initializers)
                {
                    var exprState = VisitExpression(ex, state);
                    finalState = finalState.merge(exprState);
                }
            }
            return finalState;
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
        /// 
        /// </summary>
        /// <param name="syntaxToken"></param>
        /// <returns></returns>
        private string ResolveIdentifier(SyntaxToken syntaxToken)
        {
            return syntaxToken.Text;
        }
    }
}
